//! The exact bytes of every persisted format, and what they decode to.
//! The whole-silo fixtures answer "did anything change"; these answer
//! "what changed", which is the difference between a morning and a minute.
//!
//! Every byte here was produced by a build that shipped the format. Fixing
//! a failure means fixing the code: if a vector no longer decodes, a silo
//! written before this change no longer opens.

use silentsilo_crypto::{ContentKey, decrypt_blob, unseal_with_key};
use silentsilo_sync::VaultManifest;
use silentsilo_vault::RecoveryEnvelope;
use silentsilo_vfs::{OpBody, OpRecord, VaultOp};
use uuid::Uuid;

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// `seal_with_key(b"the payload of an operation record", &[7u8; 32])`.
const SEALED: &str = "5353454101fb52a670ab2e97cc42b61f4cc496621dd88ce30c69ef878bc58a97f24e12592691135f2dba52b04687f5d93ea8adb833e985ec19b414307e2ed8cab94de6";

/// A whole `.sslo` file: `encrypt_file` over 37 bytes, content key `[9u8; 32]`.
const BLOB: &str = "53534c4f000100400000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000db03c46dabd60afaba7d693628cbe7fab5cec5b73e74935a7457d8f118d0a97e30d291c5051233693ff0485889608a5ab18e7a5d4294137f730385ebfd05cedaac0d3010893f2a66dfff72cb7e0546d1d12f82cdd3257950df76e3a5b3";

#[test]
fn the_sealed_envelope_still_decodes() {
    let key = [7u8; 32];
    let plain = unseal_with_key(&from_hex(SEALED), &key)
        .expect("a sealed payload this build wrote can no longer be opened");
    assert_eq!(plain, b"the payload of an operation record");

    // The first bytes are the discriminator, and they are what a future
    // change has to move past rather than through.
    let bytes = from_hex(SEALED);
    assert_eq!(&bytes[0..4], b"SSEA", "the magic moved");
    assert_eq!(bytes[4], 1, "the seal version moved");
}

#[test]
fn the_blob_header_still_decodes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("v.sslo");
    let out = dir.path().join("out.bin");
    std::fs::write(&source, from_hex(BLOB)).unwrap();

    // A content key, not the vault DEK: content lives on a key of its own so
    // that rotating the vault key never has to rewrite the content.
    let key = ContentKey::from_bytes([9u8; 32]);
    let blob_id = Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000);
    let header = decrypt_blob(&source, &out, &key, blob_id)
        .expect("a blob this build wrote can no longer be opened");

    assert_eq!(header.version, 1, "the blob version moved");
    assert_eq!(header.chunk_size, 4 * 1024 * 1024, "the chunk size moved");
    assert_eq!(
        header.file_id,
        Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
        "the file id field moved"
    );
    assert_eq!(header.blob_id, blob_id, "the blob id field moved");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"blob contents, short enough to commit"
    );
}

/// An operation record as written to the bucket, one field per line so a
/// failure names the field.
const OP_RECORD: &str = r#"{"op_id":"0f9a4d3e-2c1b-4a5d-8e7f-1234567890ab","lamport":7,"device_id":"1a2b3c4d-5e6f-4788-9900-aabbccddeeff","at":1700000000,"skippable":false,"seq":4,"prev":"9f2c1a","op":"create_folder","id":"22222222-3333-4444-5555-666666666666","parent_id":"77777777-8888-4999-aaaa-bbbbbbbbbbbb","name":"Documents"}"#;

#[test]
fn the_operation_record_still_decodes() {
    let record = OpRecord::from_bytes(OP_RECORD.as_bytes())
        .expect("an operation record this build wrote can no longer be read");

    assert_eq!(
        record.op_id,
        Uuid::parse_str("0f9a4d3e-2c1b-4a5d-8e7f-1234567890ab").unwrap(),
        "op_id moved"
    );
    assert_eq!(record.lamport, 7, "lamport moved");
    assert_eq!(record.at, 1_700_000_000, "at moved");
    assert!(!record.skippable, "skippable moved");
    assert_eq!(record.seq, 4, "seq moved");
    assert_eq!(record.prev.as_deref(), Some("9f2c1a"), "prev moved");

    match record.op {
        OpBody::Known(VaultOp::CreateFolder { name, .. }) => {
            assert_eq!(name, "Documents", "the operation body moved")
        }
        other => panic!("the operation no longer decodes as CreateFolder: {other:?}"),
    }
}

#[test]
fn a_record_written_now_still_looks_like_that() {
    // The other direction. Decoding an old record is half the promise; the
    // other half is that today's writer produces something an old reader
    // would have recognised.
    let record = OpRecord::from_bytes(OP_RECORD.as_bytes()).unwrap();
    let written = String::from_utf8(record.to_bytes().unwrap()).unwrap();

    for field in [
        "\"op_id\":",
        "\"lamport\":",
        "\"device_id\":",
        "\"at\":",
        "\"skippable\":",
        "\"seq\":",
        "\"prev\":",
        "\"op\":",
    ] {
        assert!(
            written.contains(field),
            "{field} is gone from what we write"
        );
    }
}

/// The password entry as it travels: base64 of a sealed payload, carried
/// whole inside the operation.
const UPSERT_PASSWORD: &str = r#"{"op_id":"aaaaaaaa-1111-4222-8333-444444444444","lamport":11,"device_id":"1a2b3c4d-5e6f-4788-9900-aabbccddeeff","at":1700000000,"skippable":false,"seq":0,"op":"upsert_password","id":"55555555-6666-4777-8888-999999999999","data":"U1NFQQFhYmNkZWZnaGlqa2xtbm9wcXJzdHV2"}"#;

#[test]
fn the_password_entry_still_travels_whole() {
    let record = OpRecord::from_bytes(UPSERT_PASSWORD.as_bytes())
        .expect("a password operation this build wrote can no longer be read");

    match record.op {
        OpBody::Known(VaultOp::UpsertPassword { id, data }) => {
            assert_eq!(
                id,
                Uuid::parse_str("55555555-6666-4777-8888-999999999999").unwrap(),
                "the entry id moved"
            );
            // Opaque on purpose: the operation carries the sealed entry
            // without looking inside, which is what lets a build that does
            // not know a field still hand it on.
            assert_eq!(
                data, "U1NFQQFhYmNkZWZnaGlqa2xtbm9wcXJzdHV2",
                "the sealed entry is no longer carried verbatim"
            );
        }
        other => panic!("no longer decodes as UpsertPassword: {other:?}"),
    }
}

const RECOVERY_ENVELOPE: &str = r#"{"version":1,"kdf":{"algorithm":"argon2id","m_cost":65536,"t_cost":3,"p_cost":1},"salt":"0102030405060708090a0b0c0d0e0f10","wrapped_dek":"deadbeef","created_at":1700000000}"#;

#[test]
fn the_recovery_envelope_still_decodes() {
    let envelope: RecoveryEnvelope = serde_json::from_str(RECOVERY_ENVELOPE)
        .expect("a recovery envelope this build wrote can no longer be read");

    assert_eq!(envelope.version, 1, "the envelope version moved");
    assert_eq!(envelope.kdf.algorithm, "argon2id", "the algorithm moved");
    assert_eq!(envelope.kdf.m_cost, 65_536, "m_cost moved");
    assert_eq!(envelope.kdf.t_cost, 3, "t_cost moved");
    assert_eq!(envelope.kdf.p_cost, 1, "p_cost moved");
    assert_eq!(
        envelope.salt, "0102030405060708090a0b0c0d0e0f10",
        "the salt moved"
    );
    assert_eq!(envelope.wrapped_dek, "deadbeef", "the wrapped dek moved");
    assert!(
        envelope.auth.is_none(),
        "an envelope from before the tag must not read as tagged"
    );
}

/// The same envelope, tagged by a silo whose content KEK is 32 bytes of
/// `0x4b`. The tag is a pure function of the fields and the KEK, so this is
/// the one vector that would catch the message the tag covers being encoded
/// differently: every envelope already in a bucket would stop verifying and
/// no device would adopt another's recovery code again.
const RECOVERY_ENVELOPE_TAGGED: &str = r#"{"version":1,"kdf":{"algorithm":"argon2id","m_cost":65536,"t_cost":3,"p_cost":1},"salt":"0102030405060708090a0b0c0d0e0f10","wrapped_dek":"deadbeef","created_at":1700000000,"auth":"734d978872c0f1f4178dd9650ba83bd507d0057b385f4fc3d9f23438b11bbb88"}"#;

#[test]
fn the_recovery_envelope_tag_still_verifies() {
    let kek = silentsilo_crypto::ContentKek::from_bytes([0x4b; 32]);
    let envelope: RecoveryEnvelope =
        serde_json::from_str(RECOVERY_ENVELOPE_TAGGED).expect("a tagged envelope no longer reads");

    assert!(
        envelope.is_authentic(&kek),
        "the tag this build makes is no longer the tag it made"
    );

    // And the tag is what it is for: the fields it covers cannot be edited
    // by anyone who does not hold the KEK.
    let mut redated = envelope.clone();
    redated.created_at += 1;
    assert!(!redated.is_authentic(&kek));
}

/// What 1.0.0 does with a tagged envelope: reads it, opens it with the code,
/// and writes it back without the field. Both halves matter. The first is
/// the compatibility rule (it ignores the new thing safely); the second is
/// why a newer device refuses to adopt an envelope a 1.0.0 device
/// republished, and says so rather than taking it.
#[test]
fn an_installed_1_0_0_client_opens_a_tagged_recovery_envelope() {
    use silentsilo_vault_v1_0_0 as v1_0_0;

    let dek = silentsilo_crypto::generate_dek();
    let kek = silentsilo_crypto::generate_content_kek();
    let (code, envelope) =
        silentsilo_vault::create_recovery_envelope(&dek, &kek).expect("this build writes one");
    let written = serde_json::to_string(&envelope).unwrap();
    assert!(written.contains("\"auth\""), "the tag is not being written");

    let old: v1_0_0::RecoveryEnvelope =
        serde_json::from_str(&written).expect("1.0.0 must parse an envelope written today");
    let opened = v1_0_0::unwrap_with_code(&old, &code)
        .expect("1.0.0 must still recover the key from the code on paper");
    assert_eq!(opened.as_bytes(), dek.as_bytes());

    // 1.0.0 saving it back drops the field it never knew about.
    let through_old = serde_json::to_string(&old).unwrap();
    assert!(!through_old.contains("auth"), "got {through_old}");
    let back: RecoveryEnvelope = serde_json::from_str(&through_old).unwrap();
    assert!(
        !back.is_authentic(&kek),
        "a stripped envelope must not read as tagged"
    );
    assert!(
        silentsilo_vault::unwrap_with_code(&back, &code).is_ok(),
        "and it must still open, or a 1.0.0 device in the fleet would cost \
         everyone their recovery code"
    );
}

/// A key envelope as published to `keys/<credential_id>.env`: plain JSON of
/// one enrolled key. It has no file version on purpose; `kind` is the whole
/// discriminator, and these vectors are what hold that story together.
const KEY_ENVELOPE: &str = r#"{"kind":"fido2","credential_id":"aa11","public_key":"3059","key_slot":0,"rp_id":"silentsilo.com","label":"Primary","wrapped_dek":"deadbeef","platform":false,"revoked":false}"#;

/// The same, written before the `kind` field existed. Every envelope already
/// in a bucket looks like this, and it must read as a FIDO2 key forever.
const KEY_ENVELOPE_PRE_KIND: &str = r#"{"credential_id":"bb22","public_key":"3059","key_slot":1,"rp_id":"silentsilo.com","label":"Backup","wrapped_dek":"cafef00d","platform":false,"revoked":false}"#;

/// A kind with a credential id that is not hex. Kept as the general case: a
/// client must carry an envelope it cannot read the id of without using it
/// and without failing over it, whatever the platform behind it.
const KEY_ENVELOPE_FOREIGN: &str = r#"{"kind":"touch-id-of-the-future","credential_id":"touch-id-key-1","public_key":"","key_slot":2,"rp_id":"silentsilo.com","label":"MacBook Touch ID","wrapped_dek":"beefcafe","platform":true,"revoked":false}"#;

/// A Secure Enclave envelope as the Apple builds write it. The credential id
/// is the 16-byte keychain tag followed by the 65-byte ephemeral public key;
/// `public_key` is the enclave key's own point. A Windows build carries it
/// and skips it; a Mac or an iPhone lists it as usable.
const KEY_ENVELOPE_SECURE_ENCLAVE: &str = r#"{"kind":"secure-enclave","derivation":"ecdh-p256-hkdf-sha256-v1","credential_id":"000102030405060708090a0b0c0d0e0f046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5","public_key":"047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1","key_slot":3,"rp_id":"silentsilo.com","label":"MacBook Air Touch ID","wrapped_dek":"beefcafe","platform":true,"revoked":false}"#;

/// An Android Keystore envelope. The credential id is the 16-byte tag
/// naming the Keystore key, the 12-byte nonce, then the wrapped 32-byte key
/// and its GCM tag. There is no public key to record.
const KEY_ENVELOPE_ANDROID_KEYSTORE: &str = r#"{"kind":"android-keystore","derivation":"keystore-aes-256-gcm-v1","credential_id":"101112131415161718191a1b1c1d1e1f202122232425262728292a2b303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","public_key":"","key_slot":4,"rp_id":"silentsilo.com","label":"Galaxy S23 Ultra","wrapped_dek":"cafebeef","platform":true,"revoked":false}"#;

#[test]
fn the_secure_enclave_envelope_still_decodes() {
    use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

    let key: StoredFidoCredential = serde_json::from_str(KEY_ENVELOPE_SECURE_ENCLAVE)
        .expect("a Secure Enclave envelope can no longer be read");
    assert_eq!(
        key.kind,
        silentsilo_vault::KIND_SECURE_ENCLAVE,
        "the kind moved"
    );
    assert_eq!(
        key.derivation,
        silentsilo_vault::DERIVATION_ECDH_P256_V1,
        "the derivation moved"
    );
    assert_eq!(key.credential_id.len(), 2 * 81, "the id is tag plus point");
    assert!(key.platform, "sealed to the machine, like Hello");

    let keys = StoredFidoKeys { keys: vec![key] };
    // The composed behaviour: on the platform that made it, it unlocks; on
    // any other, it is carried and skipped, and the id still decodes as hex
    // so the allow-list is not the thing that fails.
    let usable = if cfg!(any(target_os = "macos", target_os = "ios")) {
        1
    } else {
        0
    };
    assert_eq!(keys.usable().count(), usable);
    assert_eq!(keys.credential_ids_bytes().expect("hex").len(), usable);
}

#[test]
fn the_android_keystore_envelope_still_decodes() {
    use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

    let key: StoredFidoCredential = serde_json::from_str(KEY_ENVELOPE_ANDROID_KEYSTORE)
        .expect("an Android Keystore envelope can no longer be read");
    assert_eq!(
        key.kind,
        silentsilo_vault::KIND_ANDROID_KEYSTORE,
        "the kind moved"
    );
    assert_eq!(
        key.derivation,
        silentsilo_vault::DERIVATION_KEYSTORE_AES_GCM_V1,
        "the derivation moved"
    );
    assert_eq!(
        key.credential_id.len(),
        2 * 76,
        "the id is tag, nonce and wrapped key"
    );
    assert!(key.platform, "sealed to the phone");

    let enclave: StoredFidoCredential =
        serde_json::from_str(KEY_ENVELOPE_SECURE_ENCLAVE).expect("decodes");
    let keys = StoredFidoKeys {
        keys: vec![key, enclave],
    };
    // Each device kind unlocks only where it was made, and neither breaks
    // the allow-list anywhere else.
    let usable = if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )) {
        1
    } else {
        0
    };
    assert_eq!(keys.active().count(), 2);
    assert_eq!(keys.usable().count(), usable);
    assert_eq!(keys.credential_ids_bytes().expect("hex").len(), usable);
}

#[test]
fn the_key_envelope_still_decodes() {
    use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

    let current: StoredFidoCredential = serde_json::from_str(KEY_ENVELOPE)
        .expect("a key envelope this build wrote can no longer be read");
    assert_eq!(current.kind, silentsilo_vault::KIND_FIDO2, "the kind moved");
    assert_eq!(current.credential_id, "aa11", "the credential id moved");
    assert_eq!(current.wrapped_dek, "deadbeef", "the wrapped dek moved");

    let legacy: StoredFidoCredential = serde_json::from_str(KEY_ENVELOPE_PRE_KIND)
        .expect("an envelope from before the kind field can no longer be read");
    assert_eq!(
        legacy.kind,
        silentsilo_vault::KIND_FIDO2,
        "an envelope without a kind must read as a FIDO2 key"
    );

    let foreign: StoredFidoCredential =
        serde_json::from_str(KEY_ENVELOPE_FOREIGN).expect("an unknown kind must parse, not fail");

    // The composed behaviour the field exists for: three keys on the silo,
    // two this build can answer for, and the third neither offered to the
    // authenticator nor able to break the list.
    let keys = StoredFidoKeys {
        keys: vec![current, legacy, foreign],
    };
    assert_eq!(keys.active().count(), 3, "all three are enrolled");
    assert_eq!(
        keys.credential_ids_bytes()
            .expect("a foreign id must not fail the allow-list"),
        vec![vec![0xaa, 0x11], vec![0xbb, 0x22]],
        "the allow-list moved"
    );
}

/// `keys/fido.json` as written into the silo folder: the same credentials,
/// wrapped in the versioned silo-file envelope.
const FIDO_JSON: &str = r#"{"version":1,"data":{"keys":[{"kind":"fido2","credential_id":"aa11","public_key":"3059","key_slot":0,"rp_id":"silentsilo.com","label":"Primary","wrapped_dek":"deadbeef","platform":false,"revoked":false},{"kind":"secure-enclave","credential_id":"touch-id-key-1","public_key":"","key_slot":1,"rp_id":"silentsilo.com","label":"MacBook Touch ID","wrapped_dek":"beefcafe","platform":true,"revoked":false}]}}"#;

#[test]
fn the_enrolled_keys_file_still_loads() {
    // Through the real loader, not a bare serde call: the version envelope
    // and the refusal of newer ones are part of the format.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("keys")).unwrap();
    std::fs::write(root.path().join("keys/fido.json"), FIDO_JSON).unwrap();

    let keys = silentsilo_vault::load_fido_keys(root.path())
        .expect("a keys file this build wrote can no longer be loaded");
    assert_eq!(keys.keys.len(), 2, "a key was dropped on the way through");
    assert_eq!(keys.keys[1].kind, "secure-enclave", "the kind moved");
    assert_eq!(
        keys.usable().count(),
        1,
        "exactly one of these keys can unlock here"
    );
}

const MANIFEST: &str = r#"{"vault_id":"12345678-9abc-4def-8123-456789abcdef","version":1}"#;

#[test]
fn the_manifest_still_decodes() {
    let manifest: VaultManifest =
        serde_json::from_str(MANIFEST).expect("a manifest this build wrote can no longer be read");

    assert_eq!(
        manifest.vault_id,
        Uuid::parse_str("12345678-9abc-4def-8123-456789abcdef").unwrap(),
        "the vault id moved"
    );
    assert_eq!(manifest.version, 1, "the manifest version moved");
}

/// What 1.0.0, the release people have installed, does with every kind of
/// key written today. Its own code answers, not a description of it.
#[test]
fn an_installed_1_0_0_client_carries_device_keys_and_unlocks_with_its_own() {
    use silentsilo_vault::{Authority, StoredFidoCredential, StoredFidoKeys};
    use silentsilo_vault_v1_0_0 as v1_0_0;

    let envelopes = [
        KEY_ENVELOPE,
        KEY_ENVELOPE_SECURE_ENCLAVE,
        KEY_ENVELOPE_ANDROID_KEYSTORE,
        KEY_ENVELOPE_FOREIGN,
    ];
    let old: Vec<v1_0_0::StoredFidoCredential> = envelopes
        .iter()
        .map(|e| serde_json::from_str(e).expect("1.0.0 parses every envelope"))
        .collect();
    let old = v1_0_0::StoredFidoKeys { keys: old };
    assert_eq!(old.active().count(), 4, "all are enrolled on the silo");
    assert_eq!(old.usable().count(), 1, "only the FIDO2 key is offered");
    assert_eq!(
        old.credential_ids_bytes()
            .expect("device keys must not fail the allow-list"),
        vec![vec![0xaa, 0x11]]
    );

    // The silo file: written now, loaded and saved again by 1.0.0, read back
    // now. Every key has to survive the trip unchanged.
    let dir = tempfile::tempdir().unwrap();
    let now = StoredFidoKeys {
        keys: envelopes
            .iter()
            .map(|e| serde_json::from_str::<StoredFidoCredential>(e).expect("parses"))
            .collect(),
    };
    silentsilo_vault::save_fido_keys(dir.path(), &now, Authority::Machine).expect("saves");
    let through_old = v1_0_0::load_fido_keys(dir.path()).expect("1.0.0 loads the file");
    assert_eq!(through_old.usable().count(), 1);
    v1_0_0::save_fido_keys(dir.path(), &through_old, v1_0_0::Authority::Machine)
        .expect("1.0.0 saves it back");
    let back = silentsilo_vault::load_fido_keys(dir.path()).expect("loads again");
    assert_eq!(
        serde_json::to_value(&back.keys).unwrap(),
        serde_json::to_value(&now.keys).unwrap(),
        "1.0.0 changed a key on its way through"
    );
}

// ── The inbox ───────────────────────────────────────────────────────

/// One photo sent to a silo's inbox, exactly as a sender wrote it: vault
/// `0f1e2d3c-…`, content KEK of 32 bytes of `0x4b`, sender signing key of
/// 32 bytes of `0x22`, plaintext `hello`. The two sealed records use random
/// nonces, so these bytes are the record of one real run rather than
/// something the code can regenerate.
const INBOX_VAULT: &str = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0";
const INBOX_OBJECTS: [(&str, &str); 4] = [
    (
        "inbox/keys/01a09eb7-471c-7d43-837b-664649bc46bf.sealed",
        concat!(
            "5353454101540bc923c1dd0c22d7bf741e8fb742bbe0d8b1cd0210e45ecf06c26e71824880fad466e15d5a190967b9be",
            "2a2fe21793e83dfaf6235b8fba30fff543ed736cd96c6828d14700a7e2e8f2f02988065d50bc13a500d6d6b759c55e4f",
            "5da3031b8b0e29c86c10f08502c36c1d596cc455433af3058115e51b8998f582f0b318a8efe3b3459f382b6489c28850",
            "eaeaeab83d133496f2a48c8494d6de4f3c1c7d3bfa0787ced618652ff5cfa058f6e3ddea330ed48c47db6fcee7c443f8",
            "95d55fb85275",
        ),
    ),
    (
        "inbox/senders/5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716.sealed",
        concat!(
            "53534541014f4739ea29f5ef1151fe9814848e917af38f4e680283cd64ccef4e403b1ff664b638b876f7a9e683857526",
            "fc4afc79062c146a61de4cf40c3a134c5197df6da379d0d1a4c01ad044b1c680c183bd20bb28b9cdaabbbd65037f645c",
            "252591534e279f06c6cc7a400cba8532ee44833454aa4287dbcc3fc2ecb1b435bc6424aa3500ad211a798d25c120d4d7",
            "ebdb3e6723e0aa96437e6dccc95d05843ffa3254b578d30115709613564cefc02b05d963212c3a72b3e3dc6d023cb0d9",
            "88ae32d3fcaa49a5e98e15abcbd5ac3a8ec0db9d00ffce974f6092ebc72a2497bcff88e21beb30b57f804d426467f880",
            "1845f1d39fe10581d6df34e8b92a8e37d26b34824fc17497ad359b1ec72ec9dc58896f6d5ddd1543c31ed06aedbfa456",
            "7551decd5dc22d3c199e0020717f116405cad2ba6b0e153ad981459be185ba93c4",
        ),
    ),
    (
        "inbox/items/01920000-0000-7000-8000-000000000001.sslo",
        concat!(
            "53534c4f00010040000001920000000070008000000000000001eb70fb1f4792444b9c61969f6d27a48dea8f163db386",
            "82925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f1405d33d6a043d818dd1b3a7717818a3858519dcd169",
            "c496631fcef6dc",
        ),
    ),
    (
        "inbox/items/01920000-0000-7000-8000-000000000001.env",
        concat!(
            "7b2276657273696f6e223a312c226974656d5f6964223a2230313932303030302d303030302d373030302d383030302d",
            "303030303030303030303031222c22626c6f625f6964223a2265623730666231662d343739322d343434622d39633631",
            "2d393639663664323761343864222c226b65795f6964223a2230316130396562372d343731632d376434332d38333762",
            "2d363634363439626334366266222c2273656e745f6174223a313738393336393230362c22626c6f625f73697a65223a",
            "3130332c22657068656d6572616c223a2230343664326561616634323564353564663234323864653363316564656436",
            "626432366635623837326562323866626536316562353038666632623964333032646662666430613765346332366233",
            "303538636266623937336230636563393731366665616665623366356334646161366536633931336133353135366233",
            "643534222c227365616c6564223a22323562326662303137383265303839383363393163366132346130653365396461",
            "333864313938643332336265303665626461363162303563336239313933326664303239303262383632613263663433",
            "353334336331613333333031303961623332306534613332383966653538343036663132613437363435393434316362",
            "373836356138663234303737623365663862343864376165373937666438653636306334623831333666346561643435",
            "363966356637326435356638383133633936643833343732343631626135643636313331663630393232336364383465",
            "666639343832353438376431353831663034383133363332316232356166323165616139663433653133643666343935",
            "343662393465666264633331656433363562633238313530376561346638303334393363363564626332633535336532",
            "383736396435373232373835393562316565613630303663666135386564356630386263333130343936316166326430",
            "333032326161373561306439346336326236353330663339643330356137656461383634613961633437613965616266",
            "613166306538333639346435636665663065346135643865393665646364343934313366653330386235626665303333",
            "306332323733376232653961663265316466336632353362633661363435366263653031396563393432616266643161",
            "313235666431356531323330363666353234346465346435373034373739363539646138623465643162636530656662",
            "633430323734383032353261313536653461306438366333616664373932306362643530636235373864663835373330",
            "6139653632366135383736323737376537656635373331326164633436373032616238222c227369676e617475726522",
            "3a2239343833663032353032663337666338366434306164613837383366323764663139383939613966343131613230",
            "613035313439373536353064376665653434336430616564656531353432353561346465626133666262333830313735",
            "31323834346364663136383931316436386564396635316638626636646437656635227d",
        ),
    ),
];

/// Every inbox object above in a folder store, plus the envelope of the
/// sender's device key, which is what keeps the sender allowed.
async fn inbox_store() -> (tempfile::TempDir, silentsilo_store::FolderStore) {
    use silentsilo_store::ObjectStore;
    let dir = tempfile::tempdir().unwrap();
    let store = silentsilo_store::FolderStore::new(dir.path().to_path_buf());
    for (key, bytes) in INBOX_OBJECTS {
        store.put(key, hex::decode(bytes).unwrap()).await.unwrap();
    }
    store
        .put("keys/a1b2c3d4.env", b"{}".to_vec())
        .await
        .unwrap();
    (dir, store)
}

#[tokio::test]
async fn the_inbox_item_still_imports() {
    use silentsilo_store::ObjectStore;
    use silentsilo_sync::inbox::{scan_inbox, stage_item};

    let (_dir, store) = inbox_store().await;
    let kek = silentsilo_crypto::ContentKek::from_bytes([0x4b; 32]);
    let vault = uuid::Uuid::parse_str(INBOX_VAULT).unwrap();

    let scan = scan_inbox(&store, vault, &kek).await.expect("scans");
    assert!(scan.refused.is_empty(), "{:?}", scan.refused);
    let item = &scan.ready[0];
    assert_eq!(item.name, "IMG_0001.jpg", "the name moved");
    assert_eq!(item.mime_type.as_deref(), Some("image/jpeg"));
    assert_eq!(item.size_bytes, 5);
    assert_eq!(item.content_hash, blake3::hash(b"hello").to_hex().as_str());
    assert_eq!(item.folder, vec!["Phone".to_string(), "Photos".to_string()]);
    assert_eq!(item.source, "photos");
    assert_eq!(item.taken_at, Some(1_789_000_000));
    assert_eq!(item.sender_label, "Galaxy S23 Ultra");

    stage_item(&store, item).await.expect("stages");
    let dir = tempfile::tempdir().unwrap();
    let sealed = dir.path().join("b.sslo");
    let plain = dir.path().join("b");
    store
        .get_to_file(&format!("blobs/{}.sslo", item.blob_id), &sealed)
        .await
        .unwrap();
    let key = silentsilo_crypto::unwrap_content_key(&item.blob_key(&kek).unwrap(), &kek).unwrap();
    silentsilo_crypto::decrypt_blob(&sealed, &plain, &key, item.blob_id).expect("opens");
    assert_eq!(std::fs::read(plain).unwrap(), b"hello");
}

/// What 1.0.0 does to a store with items waiting: its orphan sweep and its
/// key rotation run over it, and the items still import afterwards.
#[tokio::test]
async fn an_installed_1_0_0_client_leaves_the_inbox_alone() {
    use silentsilo_store_v1_0_0::ObjectStore as _;
    use std::collections::HashSet;

    let (dir, _store) = inbox_store().await;
    let old_store = silentsilo_store_v1_0_0::FolderStore::new(dir.path().to_path_buf());
    // An unreferenced blob beside them, so the sweep has work to do.
    old_store
        .put(
            "blobs/6f1d0a52-9d0e-4b1a-8c7e-3f2a1b0c9d8e.sslo",
            vec![1; 10],
        )
        .await
        .unwrap();

    let nothing = HashSet::new();
    let first = silentsilo_sync_v1_0_0::sweep_orphan_blobs(&old_store, &nothing, &nothing)
        .await
        .unwrap();
    let candidates = first.candidates.into_iter().collect();
    let second = silentsilo_sync_v1_0_0::sweep_orphan_blobs(&old_store, &nothing, &candidates)
        .await
        .unwrap();
    assert_eq!(second.deleted, 1, "the sweep did run");

    let old_dek = silentsilo_crypto_v1_0_0::generate_dek();
    let new_dek = silentsilo_crypto_v1_0_0::generate_dek();
    silentsilo_sync_v1_0_0::reseal_under_new_key(&old_store, &old_dek, &new_dek, &mut |_, _| {})
        .await
        .unwrap();

    let store = silentsilo_store::FolderStore::new(dir.path().to_path_buf());
    let kek = silentsilo_crypto::ContentKek::from_bytes([0x4b; 32]);
    let vault = uuid::Uuid::parse_str(INBOX_VAULT).unwrap();
    let scan = silentsilo_sync::inbox::scan_inbox(&store, vault, &kek)
        .await
        .unwrap();
    assert_eq!(scan.ready.len(), 1, "{:?}", scan.refused);
}

// ── Revocation markers ──────────────────────────────────────────────

/// `keys/revoked/bb22.sealed` as a device wrote it after revoking key
/// `bb22`: a sealed payload under the content KEK (32 bytes of `0x4b`).
const REVOCATION_MARKER: &str = concat!(
    "53534541011d556c0c16490a216984b5ca1ecc945038c04fac0550073293b2a9a91c3a583307d83314df441732063c60",
    "bb06071eb18cb15238f8a029ed1c037dcf7ce29831eed14b7696b3181a10ea6da7e8c7760851b805a10a56cd2f",
);

#[tokio::test]
async fn the_revocation_marker_still_revokes() {
    use silentsilo_store::ObjectStore;
    use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

    let dir = tempfile::tempdir().unwrap();
    let store = silentsilo_store::FolderStore::new(dir.path().to_path_buf());
    store
        .put(
            "keys/revoked/bb22.sealed",
            hex::decode(REVOCATION_MARKER).unwrap(),
        )
        .await
        .unwrap();
    let key: StoredFidoCredential = serde_json::from_str(KEY_ENVELOPE).unwrap();
    let mut phone = key.clone();
    phone.credential_id = "bb22".into();
    let mut local = StoredFidoKeys {
        keys: vec![key, phone],
    };

    let kek = silentsilo_crypto::ContentKek::from_bytes([0x4b; 32]);
    let outcome = silentsilo_sync::reconcile_key_envelopes(&store, &kek, &mut local, 0)
        .await
        .expect("reconciles");
    assert_eq!(
        outcome.revoked,
        vec!["bb22".to_string()],
        "the marker moved"
    );
    assert!(local.keys[1].revoked);
}

/// What 1.0.0 does with a store holding a revocation marker beside the
/// envelopes: reads the envelopes, skips the marker, and a join still works.
#[tokio::test]
async fn an_installed_1_0_0_client_skips_revocation_markers() {
    use silentsilo_store_v1_0_0::ObjectStore as _;

    let dir = tempfile::tempdir().unwrap();
    let old_store = silentsilo_store_v1_0_0::FolderStore::new(dir.path().to_path_buf());
    old_store
        .put("keys/aa11.env", KEY_ENVELOPE.as_bytes().to_vec())
        .await
        .unwrap();
    old_store
        .put(
            "keys/revoked/bb22.sealed",
            hex::decode(REVOCATION_MARKER).unwrap(),
        )
        .await
        .unwrap();

    let envelopes = silentsilo_sync_v1_0_0::fetch_key_envelopes(&old_store)
        .await
        .expect("1.0.0 lists the keys without failing on the marker");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].credential_id, "aa11");
}
