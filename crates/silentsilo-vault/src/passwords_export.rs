//! The SilentSilo password export: entries, categories and attached files in
//! one file, under a password chosen when it is made, for another silo or
//! another person who uses SilentSilo.
//!
//! ```text
//! "SSPWEXPT"   8 bytes, the marker
//! version      1 byte, FORMAT_VERSION
//! header_len   u16 little-endian
//! header       JSON: { "kdf": KdfParams, "salt": hex of 16 bytes }
//! sealed       seal_with_key(payload, Argon2id(password, salt))
//! ```
//!
//! The payload, once opened, is `manifest_len` (u32 little-endian), the
//! manifest JSON (`entries`, `categories`, `attachments` as `blob_id` and
//! `size` in order), then the attached files' bytes one after another in
//! the manifest's order. Entries are kept exactly as the silo stores them,
//! so an import gives back every kind and every setting; the app gives the
//! attachments new blobs under the target silo's keys.
//!
//! A file whose version this build does not know is refused with a message
//! to update, never read in part.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::VaultError;
use crate::kdf::KdfParams;

pub const MAGIC: &[u8; 8] = b"SSPWEXPT";
pub const FORMAT_VERSION: u8 = 1;
/// The file extension the apps write and offer to open.
pub const EXTENSION: &str = "silopwd";
/// The most a file may hold, attachments included: it is opened in memory.
pub const MAX_EXPORT_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Header {
    kdf: KdfParams,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    entries: Vec<serde_json::Value>,
    #[serde(default)]
    categories: Option<serde_json::Value>,
    #[serde(default)]
    attachments: Vec<AttachmentRef>,
}

#[derive(Serialize, Deserialize)]
struct AttachmentRef {
    blob_id: Uuid,
    size: u64,
}

/// What an export holds, opened.
pub struct PasswordsExport {
    /// Each entry as the JSON the silo stores, history included.
    pub entries: Vec<Zeroizing<String>>,
    /// The silo's category list (names and colours), when it was exported.
    pub categories: Option<String>,
    /// Attached files by the blob id their entry names.
    pub attachments: HashMap<Uuid, Zeroizing<Vec<u8>>>,
}

fn not_an_export() -> VaultError {
    VaultError::Corrupted("This is not a SilentSilo password export.".into())
}

/// Writes `entries` (the stored JSON of each), the category list and the
/// attached files under `password`.
pub fn write(
    password: &str,
    entries: &[String],
    categories: Option<&str>,
    attachments: &[(Uuid, Zeroizing<Vec<u8>>)],
) -> Result<Vec<u8>, VaultError> {
    write_with(
        password,
        entries,
        categories,
        attachments,
        KdfParams::recovery_code(),
    )
}

fn write_with(
    password: &str,
    entries: &[String],
    categories: Option<&str>,
    attachments: &[(Uuid, Zeroizing<Vec<u8>>)],
    kdf: KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let parse = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text)
            .map_err(|e| VaultError::Corrupted(format!("An entry could not be read: {e}")))
    };
    let manifest = Manifest {
        entries: entries.iter().map(|e| parse(e)).collect::<Result<_, _>>()?,
        categories: categories.map(parse).transpose()?,
        attachments: attachments
            .iter()
            .map(|(id, bytes)| AttachmentRef {
                blob_id: *id,
                size: bytes.len() as u64,
            })
            .collect(),
    };
    let mut manifest_json = Zeroizing::new(
        serde_json::to_vec(&manifest).map_err(|e| VaultError::Corrupted(e.to_string()))?,
    );
    // The parsed copies hold the secrets too; they go once serialised.
    let Manifest { mut entries, .. } = manifest;
    entries.iter_mut().for_each(wipe);

    let total = 4 + manifest_json.len() + attachments.iter().map(|(_, b)| b.len()).sum::<usize>();
    if total > MAX_EXPORT_BYTES {
        return Err(VaultError::Corrupted(
            "These entries and their files come to more than 1 GB.".into(),
        ));
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(total));
    payload.extend_from_slice(&(manifest_json.len() as u32).to_le_bytes());
    payload.extend_from_slice(&manifest_json);
    manifest_json.zeroize();
    for (_, bytes) in attachments {
        payload.extend_from_slice(bytes);
    }

    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut salt);
    let key = Zeroizing::new(kdf.derive(password.as_bytes(), &salt)?);
    let sealed = silentsilo_crypto::seal_with_key(&payload, &key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let header = serde_json::to_vec(&Header {
        kdf,
        salt: hex::encode(salt),
    })
    .map_err(|e| VaultError::Corrupted(e.to_string()))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 3 + header.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&(header.len() as u16).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens an export. A wrong password and a damaged file both fail the
/// authentication and read the same; a newer version asks for an update.
pub fn read(password: &str, file: &[u8]) -> Result<PasswordsExport, VaultError> {
    if file.len() > MAX_EXPORT_BYTES + 64 * 1024 {
        return Err(VaultError::Corrupted(
            "This export is larger than any SilentSilo writes.".into(),
        ));
    }
    if file.len() < MAGIC.len() + 3 || &file[..MAGIC.len()] != MAGIC {
        return Err(not_an_export());
    }
    let version = file[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(VaultError::Corrupted(format!(
            "This export was made by a newer SilentSilo (format {version}). Update SilentSilo to open it."
        )));
    }
    let len_at = MAGIC.len() + 1;
    let header_len = u16::from_le_bytes([file[len_at], file[len_at + 1]]) as usize;
    let header_at = len_at + 2;
    let header_bytes = file
        .get(header_at..header_at + header_len)
        .ok_or_else(not_an_export)?;
    let header: Header = serde_json::from_slice(header_bytes).map_err(|_| not_an_export())?;
    let salt = hex::decode(&header.salt).map_err(|_| not_an_export())?;
    if salt.len() != 16 {
        return Err(not_an_export());
    }
    let key = Zeroizing::new(header.kdf.derive(password.as_bytes(), &salt)?);
    let payload = Zeroizing::new(
        silentsilo_crypto::unseal_with_key(&file[header_at + header_len..], &key).map_err(
            |_| {
                VaultError::Crypto(
                    "Wrong password, or the file was changed since it was made.".into(),
                )
            },
        )?,
    );

    let manifest_len = payload
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or_else(not_an_export)?;
    let manifest_bytes = payload.get(4..4 + manifest_len).ok_or_else(not_an_export)?;
    let mut manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| not_an_export())?;

    let mut attachments = HashMap::new();
    let mut at = 4 + manifest_len;
    for item in &manifest.attachments {
        let size = usize::try_from(item.size).map_err(|_| not_an_export())?;
        let bytes = payload.get(at..at + size).ok_or_else(not_an_export)?;
        attachments.insert(item.blob_id, Zeroizing::new(bytes.to_vec()));
        at += size;
    }
    if at != payload.len() {
        return Err(not_an_export());
    }

    let entries = manifest
        .entries
        .iter()
        .map(|e| Zeroizing::new(e.to_string()))
        .collect();
    manifest.entries.iter_mut().for_each(wipe);
    Ok(PasswordsExport {
        entries,
        categories: manifest.categories.map(|c| c.to_string()),
        attachments,
    })
}

/// Overwrites every string in a parsed entry.
fn wipe(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(wipe),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap to derive: a debug build runs Argon2 slowly.
    fn quick() -> KdfParams {
        KdfParams {
            algorithm: crate::kdf::ARGON2ID.into(),
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn sample() -> (Vec<String>, Uuid, Zeroizing<Vec<u8>>) {
        let blob = Uuid::new_v4();
        let entries = vec![
            format!(
                r#"{{"id":"a","type":"card","service":"Visa","card_number":"4111","history":[{{"saved_at":1,"card_number":"4000"}}],"attachments":[{{"blob_id":"{blob}","name":"scan.pdf","size_bytes":5,"blob_key":"k"}}],"reprompt":true}}"#
            ),
            r#"{"id":"b","service":"GitHub","password":"p","ssh_agent":true}"#.to_string(),
        ];
        (entries, blob, Zeroizing::new(b"%PDF1".to_vec()))
    }

    #[test]
    fn an_export_comes_back_exactly() {
        let (entries, blob, bytes) = sample();
        let file = write_with(
            "correct horse",
            &entries,
            Some(r##"[{"name":"Money","color":"#22aa55"}]"##),
            &[(blob, bytes)],
            quick(),
        )
        .unwrap();
        assert_eq!(&file[..8], MAGIC);
        let opened = read("correct horse", &file).unwrap();
        let back: Vec<serde_json::Value> = opened
            .entries
            .iter()
            .map(|e| serde_json::from_str(e).unwrap())
            .collect();
        let sent: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| serde_json::from_str(e).unwrap())
            .collect();
        assert_eq!(back, sent);
        assert_eq!(
            opened.categories.as_deref(),
            Some(r##"[{"color":"#22aa55","name":"Money"}]"##)
        );
        assert_eq!(opened.attachments[&blob].as_slice(), b"%PDF1");
    }

    #[test]
    fn the_wrong_password_reads_nothing() {
        let (entries, blob, bytes) = sample();
        let file = write_with("right one", &entries, None, &[(blob, bytes)], quick()).unwrap();
        let err = read("wrong one", &file).err().unwrap().to_string();
        assert!(err.contains("Wrong password"), "{err}");
    }

    #[test]
    fn a_changed_byte_is_caught() {
        let (entries, _, _) = sample();
        let mut file = write_with("pw-pw-pw", &entries, None, &[], quick()).unwrap();
        let last = file.len() - 1;
        file[last] ^= 1;
        assert!(read("pw-pw-pw", &file).is_err());
    }

    #[test]
    fn a_newer_version_asks_for_an_update() {
        let (entries, _, _) = sample();
        let mut file = write_with("pw-pw-pw", &entries, None, &[], quick()).unwrap();
        file[MAGIC.len()] = FORMAT_VERSION + 1;
        let err = read("pw-pw-pw", &file).err().unwrap().to_string();
        assert!(err.contains("newer SilentSilo"), "{err}");
    }

    #[test]
    fn another_file_is_not_an_export() {
        for file in [
            &b""[..],
            b"SSPWEXP",
            b"PK\x03\x04 a zip",
            b"SSPWEXPT\x01\xff\xff{",
        ] {
            let err = read("x", file).err().unwrap().to_string();
            assert!(err.contains("not a SilentSilo password export"), "{err}");
        }
    }

    #[test]
    fn a_hostile_header_cannot_ask_for_terabytes() {
        let (entries, _, _) = sample();
        let file = write_with("pw-pw-pw", &entries, None, &[], quick()).unwrap();
        let header_len = u16::from_le_bytes([file[9], file[10]]) as usize;
        let header: serde_json::Value = serde_json::from_slice(&file[11..11 + header_len]).unwrap();
        let mut heavy = header.clone();
        heavy["kdf"]["m_cost"] = u32::MAX.into();
        let heavy = serde_json::to_vec(&heavy).unwrap();
        let mut forged = file[..9].to_vec();
        forged.extend_from_slice(&(heavy.len() as u16).to_le_bytes());
        forged.extend_from_slice(&heavy);
        forged.extend_from_slice(&file[11 + header_len..]);
        let err = read("pw-pw-pw", &forged).err().unwrap().to_string();
        assert!(err.contains("more work"), "{err}");
    }

    const FIXTURE_PASSWORD: &str = "fixture password, not a secret";

    /// The entries the v1 fixture was written with, and its one attachment.
    fn fixture_contents() -> (Vec<String>, Uuid, &'static [u8]) {
        let blob = Uuid::parse_str("6a2f0d6e-0b9e-4c55-9a3e-2b8f3f6f0c11").unwrap();
        let entries = vec![
            format!(
                r#"{{"id":"7c1e5d0a-1111-4a2b-9c3d-000000000001","type":"login","service":"GitHub","username":"you@example.com","password":"correct horse","url":"https://github.com","totp_secret":"JBSWY3DPEHPK3PXP","category":"Development","favorite":true,"ssh_agent":false,"reprompt":true,"fields":[{{"name":"Recovery","value":"abc","hidden":true}}],"history":[{{"saved_at":1700000000000,"password":"before"}}],"attachments":[{{"blob_id":"{blob}","name":"codes.txt","size_bytes":13,"blob_key":"k"}}],"created_at":1700000000000,"updated_at":1700000500000}}"#
            ),
            r#"{"id":"7c1e5d0a-1111-4a2b-9c3d-000000000002","type":"card","service":"Visa","card_holder":"A. Person","card_number":"4111111111111111","card_code":"123","created_at":0,"updated_at":0}"#.to_string(),
            r#"{"id":"7c1e5d0a-1111-4a2b-9c3d-000000000003","type":"ssh_key","service":"Server","ssh_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----","ssh_agent":true,"created_at":0,"updated_at":0}"#.to_string(),
        ];
        (
            entries,
            blob,
            b"backup codes
",
        )
    }

    /// Writes the v1 fixture. Run once, by hand, never again for v1:
    /// `FIXTURE_OUT=<path> cargo test -p silentsilo-vault write_v1_fixture -- --ignored`
    #[test]
    #[ignore]
    fn write_v1_fixture() {
        let out = std::env::var("FIXTURE_OUT").expect("FIXTURE_OUT");
        let (entries, blob, bytes) = fixture_contents();
        let file = write_with(
            FIXTURE_PASSWORD,
            &entries,
            Some(r##"[{"name":"Development","color":"#3b82f6"}]"##),
            &[(blob, Zeroizing::new(bytes.to_vec()))],
            quick(),
        )
        .unwrap();
        std::fs::write(out, file).unwrap();
    }

    /// The v1 file as the first release wrote it. Changing how it reads is a
    /// format break, not a fixture to update.
    #[test]
    fn the_v1_fixture_still_opens() {
        let file = include_bytes!("../tests/fixtures/passwords-export-v1.silopwd");
        assert_eq!(
            blake3::hash(file).to_hex().as_str(),
            V1_FIXTURE_BLAKE3,
            "the v1 fixture is never rewritten"
        );
        let opened = read(FIXTURE_PASSWORD, file).unwrap();
        let (entries, blob, bytes) = fixture_contents();
        let back: Vec<serde_json::Value> = opened
            .entries
            .iter()
            .map(|e| serde_json::from_str(e).unwrap())
            .collect();
        let sent: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| serde_json::from_str(e).unwrap())
            .collect();
        assert_eq!(back, sent);
        assert_eq!(opened.attachments[&blob].as_slice(), bytes);
        assert!(opened.categories.unwrap().contains("Development"));
    }

    const V1_FIXTURE_BLAKE3: &str =
        "c664c81909d119a351c3b7768b95edb198099e30e041d39503d369a3a7b26323";

    #[test]
    fn the_real_parameters_are_the_recovery_codes() {
        // Pinned: a release that weakens them must change this test.
        let kdf = KdfParams::recovery_code();
        assert_eq!((kdf.m_cost, kdf.t_cost, kdf.p_cost), (65_536, 3, 1));
    }
}
