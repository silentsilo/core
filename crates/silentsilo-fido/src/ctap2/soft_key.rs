//! A software authenticator on the other end of each link. Its side of the
//! protocol is written out here rather than borrowed from the client, so a
//! mistake in one is not simply mirrored by the other.

use std::collections::VecDeque;

use super::hid::{Hid, REPORT_LEN, Reports};
use super::nfc::{Apdu, Nfc};
use super::*;

const VAULT: &str = "0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e";

struct SoftKey {
    protocols: Vec<i64>,
    pin: Option<String>,
    max_list: usize,
    /// Id and `CredRandomWithoutUV`.
    credentials: Vec<(Vec<u8>, [u8; 32])>,
    agreement: Option<SecretKey>,
    token: [u8; 32],
}

impl SoftKey {
    fn new(protocols: &[i64]) -> Self {
        Self {
            protocols: protocols.to_vec(),
            pin: None,
            max_list: 8,
            credentials: Vec::new(),
            agreement: None,
            token: random_bytes(),
        }
    }

    /// The key's keys for protocol `p`, from the platform's COSE key.
    fn keys(&self, p: i64, platform: &Value) -> ([u8; 32], [u8; 32]) {
        let theirs = public_from_cose(platform).unwrap();
        let ours = self.agreement.as_ref().expect("key agreement asked first");
        let shared = diffie_hellman(ours.to_nonzero_scalar(), theirs.as_affine());
        let z = shared.raw_secret_bytes();
        if p == 1 {
            let k = sha256(z);
            return (k, k);
        }
        let hkdf = |info: &[u8]| {
            let mut out = [0u8; 32];
            Hkdf::<Sha256>::new(None, z).expand(info, &mut out).unwrap();
            out
        };
        (hkdf(b"CTAP2 HMAC key"), hkdf(b"CTAP2 AES key"))
    }

    fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    fn cbc(p: i64, key: &[u8; 32], data: &[u8], encrypt: bool) -> Vec<u8> {
        let (iv, body) = if p == 1 {
            ([0u8; 16], data.to_vec())
        } else if encrypt {
            (random_bytes(), data.to_vec())
        } else {
            (data[..16].try_into().unwrap(), data[16..].to_vec())
        };
        let mut buf = body.clone();
        let len = buf.len();
        if encrypt {
            cbc::Encryptor::<Aes256>::new(key.into(), &iv.into())
                .encrypt_padded_mut::<NoPadding>(&mut buf, len)
                .unwrap();
            if p == 1 {
                buf
            } else {
                [iv.as_slice(), &buf].concat()
            }
        } else {
            cbc::Decryptor::<Aes256>::new(key.into(), &iv.into())
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .unwrap();
            buf
        }
    }

    fn verify(p: i64, key: &[u8], message: &[u8], auth: &[u8]) -> bool {
        let full = Self::hmac(key, message);
        auth == if p == 1 { &full[..16] } else { &full[..] }
    }

    /// Status byte and body, as a key frames them.
    fn handle(&mut self, command: u8, cbor: &[u8]) -> Vec<u8> {
        match self.answer(command, cbor) {
            Ok(body) => [vec![0], encode(&body)].concat(),
            Err(status) => vec![status],
        }
    }

    fn answer(&mut self, command: u8, cbor: &[u8]) -> Result<Value, u8> {
        let request = if cbor.is_empty() {
            Value::Null
        } else {
            decode(cbor).unwrap()
        };
        let get = |k: i64| int_entry(&request, k);
        match command {
            CMD_GET_INFO => Ok(map(vec![
                (int(1), Value::Array(vec![text("FIDO_2_0")])),
                (int(2), Value::Array(vec![text("hmac-secret")])),
                (
                    int(4),
                    map(vec![(text("clientPin"), Value::Bool(self.pin.is_some()))]),
                ),
                (
                    int(6),
                    Value::Array(self.protocols.iter().map(|p| int(*p)).collect()),
                ),
                (int(7), int(self.max_list as i64)),
            ])),
            CMD_CLIENT_PIN => {
                let p = get(1)
                    .and_then(Value::as_integer)
                    .map(i64::try_from)
                    .unwrap()
                    .unwrap();
                assert!(self.protocols.contains(&p));
                match get(2)
                    .and_then(Value::as_integer)
                    .map(i64::try_from)
                    .unwrap()
                    .unwrap()
                {
                    PIN_GET_KEY_AGREEMENT => {
                        let secret = random_secret();
                        let public = secret.public_key();
                        self.agreement = Some(secret);
                        Ok(map(vec![(int(1), cose_public(&public))]))
                    }
                    PIN_GET_PIN_TOKEN => {
                        let (_, aes) = self.keys(p, get(3).unwrap());
                        let hash =
                            Self::cbc(p, &aes, get(6).and_then(Value::as_bytes).unwrap(), false);
                        let pin = self.pin.as_ref().ok_or(0x35u8)?;
                        if hash[..] != sha256(pin.as_bytes())[..16] {
                            return Err(0x31);
                        }
                        Ok(map(vec![(
                            int(2),
                            bytes(&Self::cbc(p, &aes, &self.token, true)),
                        )]))
                    }
                    PIN_GET_RETRIES => Ok(map(vec![(int(3), int(7))])),
                    other => panic!("clientPin {other}"),
                }
            }
            CMD_MAKE_CREDENTIAL => {
                let cdh = get(1).and_then(Value::as_bytes).unwrap();
                let rp = entry(get(2).unwrap(), &text("id"))
                    .and_then(Value::as_text)
                    .unwrap();
                assert_eq!(rp, RP_ID);
                if self.pin.is_some() {
                    let auth = get(8).and_then(Value::as_bytes).ok_or(0x36u8)?;
                    let p = get(9)
                        .and_then(Value::as_integer)
                        .map(i64::try_from)
                        .unwrap()
                        .unwrap();
                    if !Self::verify(p, &self.token, cdh, auth) {
                        return Err(0x33);
                    }
                }
                let wants = entry(get(6).unwrap(), &text("hmac-secret")).and_then(Value::as_bool);
                assert_eq!(wants, Some(true));
                let id = random_bytes::<48>().to_vec();
                self.credentials.push((id.clone(), random_bytes()));
                let mut data = sha256(rp.as_bytes()).to_vec();
                data.push(0x01 | 0x40 | 0x80);
                data.extend_from_slice(&[0, 0, 0, 0]);
                data.extend_from_slice(&[0u8; 16]);
                data.extend_from_slice(&(id.len() as u16).to_be_bytes());
                data.extend_from_slice(&id);
                data.extend_from_slice(&encode(&cose_public(&random_secret().public_key())));
                data.extend_from_slice(&encode(&map(vec![(
                    text("hmac-secret"),
                    Value::Bool(true),
                )])));
                Ok(map(vec![
                    (int(1), text("none")),
                    (int(2), bytes(&data)),
                    (int(3), map(vec![])),
                ]))
            }
            CMD_GET_ASSERTION => {
                assert_eq!(get(1).and_then(Value::as_text), Some(RP_ID));
                let allow = get(3).and_then(Value::as_array).unwrap();
                assert!(
                    allow.len() <= self.max_list,
                    "allow-list over the key's limit"
                );
                assert!(
                    int_entry(&request, 5)
                        .and_then(|o| entry(o, &text("uv")))
                        .is_none(),
                    "verification goes by PIN token"
                );
                let verified = match get(6).and_then(Value::as_bytes) {
                    Some(auth) => {
                        let p = get(7)
                            .and_then(Value::as_integer)
                            .map(i64::try_from)
                            .unwrap()
                            .unwrap();
                        let cdh = get(2).and_then(Value::as_bytes).unwrap();
                        if !Self::verify(p, &self.token, cdh, auth) {
                            return Err(0x33);
                        }
                        true
                    }
                    None => false,
                };
                let found = allow.iter().find_map(|c| {
                    let id = entry(c, &text("id")).and_then(Value::as_bytes)?;
                    self.credentials
                        .iter()
                        .find(|(known, _)| known == id)
                        .cloned()
                });
                let (id, cred_random) = found.ok_or(0x2Eu8)?;
                let cred_random = Self::secret(&cred_random, verified);
                let ext = entry(get(4).unwrap(), &text("hmac-secret")).unwrap();
                let p = int_entry(ext, 4)
                    .and_then(Value::as_integer)
                    .map(|i| i64::try_from(i).unwrap())
                    .unwrap_or(1);
                let (hmac_key, aes) = self.keys(p, int_entry(ext, 1).unwrap());
                let salt_enc = int_entry(ext, 2).and_then(Value::as_bytes).unwrap();
                let salt_auth = int_entry(ext, 3).and_then(Value::as_bytes).unwrap();
                assert!(Self::verify(p, &hmac_key, salt_enc, salt_auth), "saltAuth");
                let salts = Self::cbc(p, &aes, salt_enc, false);
                let output: Vec<u8> = salts
                    .chunks(32)
                    .flat_map(|salt| Self::hmac(&cred_random, salt))
                    .collect();
                let mut data = sha256(RP_ID.as_bytes()).to_vec();
                data.push(0x01 | 0x80);
                data.extend_from_slice(&[0, 0, 0, 1]);
                data.extend_from_slice(&encode(&map(vec![(
                    text("hmac-secret"),
                    bytes(&Self::cbc(p, &aes, &output, true)),
                )])));
                Ok(map(vec![
                    (
                        int(1),
                        map(vec![
                            (text("id"), bytes(&id)),
                            (text("type"), text("public-key")),
                        ]),
                    ),
                    (int(2), bytes(&data)),
                    (int(3), bytes(&[0u8; 70])),
                ]))
            }
            other => panic!("command {other}"),
        }
    }

    /// `CredRandomWithUV` stands apart from the unverified one.
    fn secret(cred_random: &[u8; 32], verified: bool) -> [u8; 32] {
        if verified {
            Self::hmac(cred_random, b"uv")
        } else {
            *cred_random
        }
    }

    /// What the silo's wrap key must be for this credential, by definition.
    fn expected_wrap_key(&self, id: &[u8]) -> [u8; 32] {
        self.expected(id, false, false)
    }

    fn expected(&self, id: &[u8], verified: bool, prf: bool) -> [u8; 32] {
        let (_, cred_random) = self.credentials.iter().find(|(k, _)| k == id).unwrap();
        let mut salt = sha256(format!("silentsilo-dek-v1:{VAULT}").as_bytes());
        if prf {
            salt = sha256(&[b"WebAuthn PRF\x00".as_slice(), &salt].concat());
        }
        *blake3::hash(&Self::hmac(&Self::secret(cred_random, verified), &salt)).as_bytes()
    }
}

impl Ctap for SoftKey {
    fn command(&mut self, command: u8, cbor: &[u8]) -> Result<Vec<u8>, CtapError> {
        split_status(self.handle(command, cbor))
    }
}

#[test]
fn a_credential_made_here_unlocks_to_the_wrap_key_every_platform_derives() {
    for protocols in [vec![1], vec![2], vec![2, 1]] {
        let mut key = SoftKey::new(&protocols);
        let made = make_credential(&mut key, VAULT, None).unwrap();
        assert_eq!(made.public_key.len(), 91);
        assert_eq!(&made.public_key[..2], &[0x30, 0x59]);

        let unlocked =
            derive_unlock_material(&mut key, std::slice::from_ref(&made.credential_id), VAULT)
                .unwrap();
        assert_eq!(unlocked.credential_id, made.credential_id);
        assert_eq!(
            unlocked.wrap_key,
            key.expected_wrap_key(&made.credential_id),
            "{protocols:?}"
        );
    }
}

#[test]
fn the_allow_list_is_split_to_the_keys_limit_and_a_stranger_is_named() {
    let mut key = SoftKey::new(&[1]);
    key.max_list = 1;
    let made = make_credential(&mut key, VAULT, None).unwrap();
    let others: Vec<Vec<u8>> = (0..3).map(|_| random_bytes::<48>().to_vec()).collect();
    let mut ids = others.clone();
    ids.push(made.credential_id.clone());

    let unlocked = derive_unlock_material(&mut key, &ids, VAULT).unwrap();
    assert_eq!(unlocked.credential_id, made.credential_id);
    assert!(matches!(
        derive_unlock_material(&mut key, &others, VAULT),
        Err(CtapError::NoCredentials)
    ));
}

#[test]
fn a_key_with_a_pin_asks_for_it_at_enrolment_only() {
    let mut key = SoftKey::new(&[2, 1]);
    key.pin = Some("4821".into());
    assert!(matches!(
        make_credential(&mut key, VAULT, None),
        Err(CtapError::PinRequired)
    ));
    assert!(matches!(
        make_credential(&mut key, VAULT, Some("0000")),
        Err(CtapError::PinInvalid { .. })
    ));
    let made = make_credential(&mut key, VAULT, Some("4821")).unwrap();
    let unlocked =
        derive_unlock_material(&mut key, std::slice::from_ref(&made.credential_id), VAULT).unwrap();
    assert_eq!(
        unlocked.wrap_key,
        key.expected_wrap_key(&made.credential_id)
    );
}

/// The applet behind APDUs: chaining in, `61xx` out, a keep-alive first.
struct SoftNfc {
    key: SoftKey,
    chained: Vec<u8>,
    pending: VecDeque<u8>,
    keepalive_once: bool,
    selected: bool,
}

impl SoftNfc {
    fn respond(&mut self, mut data: Vec<u8>, sw: u16) -> Vec<u8> {
        if data.len() > 255 {
            self.pending = data.split_off(255).into();
            let left = self.pending.len().min(255) as u8;
            data.extend_from_slice(&[0x61, left]);
            return data;
        }
        data.extend_from_slice(&sw.to_be_bytes());
        data
    }
}

impl Apdu for SoftNfc {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CtapError> {
        let (cla, ins) = (apdu[0], apdu[1]);
        assert!(apdu.len() <= 5 + 255 + 1, "a short APDU");
        let body = if apdu.len() > 5 {
            &apdu[5..5 + apdu[4] as usize]
        } else {
            &[][..]
        };
        match (cla & !0x10, ins) {
            (0x00, 0xA4) => {
                assert_eq!(body, &FIDO_AID_FOR_TESTS);
                self.selected = true;
                Ok(self.respond(b"FIDO_2_0".to_vec(), 0x9000))
            }
            (0x00, 0xC0) => {
                let take = self.pending.len().min(255);
                let mut data: Vec<u8> = self.pending.drain(..take).collect();
                if self.pending.is_empty() {
                    data.extend_from_slice(&[0x90, 0x00]);
                } else {
                    data.extend_from_slice(&[0x61, self.pending.len().min(255) as u8]);
                }
                Ok(data)
            }
            (0x80, 0x10) => {
                assert!(self.selected);
                self.chained.extend_from_slice(body);
                if cla & 0x10 != 0 {
                    return Ok(vec![0x90, 0x00]);
                }
                if self.keepalive_once {
                    self.keepalive_once = false;
                    return Ok(vec![0x01, 0x91, 0x00]);
                }
                let message = std::mem::take(&mut self.chained);
                let answer = self.key.handle(message[0], &message[1..]);
                Ok(self.respond(answer, 0x9000))
            }
            (0x80, 0x11) => {
                let message = std::mem::take(&mut self.chained);
                let answer = self.key.handle(message[0], &message[1..]);
                Ok(self.respond(answer, 0x9000))
            }
            other => panic!("APDU {other:?}"),
        }
    }
}

const FIDO_AID_FOR_TESTS: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

#[test]
fn over_nfc_long_commands_chain_and_long_answers_are_fetched() {
    let mut key = SoftKey::new(&[1]);
    key.max_list = 10;
    let mut nfc = Nfc::new(SoftNfc {
        key,
        chained: Vec::new(),
        pending: VecDeque::new(),
        keepalive_once: true,
        selected: false,
    });
    let made = make_credential(&mut nfc, VAULT, None).unwrap();
    // Nine strangers of 64 bytes put the command well past 255.
    let mut ids: Vec<Vec<u8>> = (0..9).map(|_| random_bytes::<64>().to_vec()).collect();
    ids.push(made.credential_id.clone());
    let unlocked = derive_unlock_material(&mut nfc, &ids, VAULT).unwrap();
    assert_eq!(unlocked.credential_id, made.credential_id);
}

/// The key behind 64-byte reports: a channel from INIT, keep-alives before
/// every answer, and noise on another channel.
struct SoftHid {
    key: SoftKey,
    incoming: Vec<u8>,
    expected: usize,
    command: u8,
    cid: [u8; 4],
    out: VecDeque<[u8; REPORT_LEN]>,
}

impl SoftHid {
    fn queue(&mut self, cid: [u8; 4], cmd: u8, data: &[u8]) {
        let mut first = [0u8; REPORT_LEN];
        first[..4].copy_from_slice(&cid);
        first[4] = cmd;
        first[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let n = data.len().min(57);
        first[7..7 + n].copy_from_slice(&data[..n]);
        self.out.push_back(first);
        for (seq, piece) in data[n..].chunks(59).enumerate() {
            let mut r = [0u8; REPORT_LEN];
            r[..4].copy_from_slice(&cid);
            r[4] = seq as u8;
            r[5..5 + piece.len()].copy_from_slice(piece);
            self.out.push_back(r);
        }
    }
}

impl Reports for SoftHid {
    fn write(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), CtapError> {
        if report[4] & 0x80 != 0 {
            self.command = report[4];
            self.expected = u16::from_be_bytes([report[5], report[6]]) as usize;
            self.incoming = report[7..7 + self.expected.min(57)].to_vec();
        } else {
            let take = (self.expected - self.incoming.len()).min(59);
            self.incoming.extend_from_slice(&report[5..5 + take]);
        }
        if self.incoming.len() < self.expected {
            return Ok(());
        }
        let message = std::mem::take(&mut self.incoming);
        let cid: [u8; 4] = report[..4].try_into().unwrap();
        match self.command {
            0x86 => {
                let mut data = message[..8].to_vec();
                data.extend_from_slice(&self.cid);
                data.extend_from_slice(&[2, 5, 4, 3, 0x05]);
                self.queue([9, 9, 9, 9], 0x86, &[0; 17]);
                self.queue(cid, 0x86, &data);
            }
            _ => {
                assert_eq!(cid, self.cid);
                self.queue(self.cid, 0xBB, &[2]);
                let answer = self.key.handle(message[0], &message[1..]);
                self.queue(self.cid, 0x90, &answer);
            }
        }
        Ok(())
    }

    fn read(&mut self, _timeout_ms: u32) -> Result<Option<[u8; REPORT_LEN]>, CtapError> {
        Ok(self.out.pop_front())
    }
}

#[test]
fn over_usb_messages_span_reports_and_keepalives_are_waited_out() {
    let mut hid = Hid::new(SoftHid {
        key: SoftKey::new(&[2]),
        incoming: Vec::new(),
        expected: 0,
        command: 0,
        cid: [0x11, 0x22, 0x33, 0x44],
        out: VecDeque::new(),
    });
    let made = make_credential(&mut hid, VAULT, None).unwrap();
    let unlocked =
        derive_unlock_material(&mut hid, std::slice::from_ref(&made.credential_id), VAULT).unwrap();
    assert_eq!(unlocked.credential_id, made.credential_id);
}

#[test]
fn a_silo_wrapped_by_a_platform_that_verified_opens_with_the_pin() {
    let mut key = SoftKey::new(&[2, 1]);
    key.pin = Some("4821".into());
    let made = make_credential(&mut key, VAULT, Some("4821")).unwrap();
    let ids = std::slice::from_ref(&made.credential_id);

    let plain = unlock_candidates(&mut key, ids, VAULT, None).unwrap();
    assert!(!plain.verified && plain.pin_set);
    let shapes = |c: &UnlockCandidates| {
        c.wrap_keys
            .iter()
            .map(|(s, k)| (*s, **k))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shapes(&plain),
        vec![
            (
                SaltShape::Raw,
                key.expected(&made.credential_id, false, false)
            ),
            (
                SaltShape::Prf,
                key.expected(&made.credential_id, false, true)
            ),
        ]
    );

    let with_pin = unlock_candidates(&mut key, ids, VAULT, Some("4821")).unwrap();
    assert!(with_pin.verified);
    assert_eq!(
        shapes(&with_pin),
        vec![
            (
                SaltShape::Raw,
                key.expected(&made.credential_id, true, false)
            ),
            (
                SaltShape::Prf,
                key.expected(&made.credential_id, true, true)
            ),
        ]
    );
    assert!(matches!(
        unlock_candidates(&mut key, ids, VAULT, Some("0000")),
        Err(CtapError::PinInvalid { .. })
    ));
}
