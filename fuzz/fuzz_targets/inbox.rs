//! An inbox envelope anyone with write access to the bucket can put there,
//! scanned the way a pass does. The silo, its inbox key, one registered
//! sender and one real item are made once; each input becomes the envelope
//! of that item.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use silentsilo_crypto::ContentKek;
use silentsilo_crypto::inbox::EcSecret;
use silentsilo_fuzz::shaped;
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::inbox;
use uuid::Uuid;

const ITEM: Uuid = Uuid::from_u128(0x5eed);
const VAULT: Uuid = Uuid::from_u128(0x5170);

struct Silo {
    _dir: tempfile::TempDir,
    store: FolderStore,
    kek: ContentKek,
    envelope_key: String,
    valid: Vec<u8>,
    runtime: tokio::runtime::Runtime,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn silo() -> &'static Silo {
    static SILO: OnceLock<Silo> = OnceLock::new();
    SILO.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let store = FolderStore::new(dir.path().to_path_buf());
        let kek = ContentKek::from_bytes([4; 32]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let envelope_key = format!("{}{ITEM}.env", inbox::INBOX_ITEMS_PREFIX);
        let valid = runtime.block_on(async {
            let (key_id, inbox_public) = inbox::ensure_inbox_key(&store, &kek).await.unwrap();
            let secret = EcSecret::from_bytes([6; 32]).unwrap();
            let sender_id = Uuid::from_u128(2);
            inbox::register_sender(
                &store,
                &kek,
                &inbox::SenderRecord {
                    version: inbox::INBOX_VERSION,
                    sender_id,
                    public_key: hex(&secret.public_key()),
                    credential_id: "aa11".into(),
                    label: "Phone".into(),
                    created_at: 0,
                },
            )
            .await
            .unwrap();
            let source = dir.path().join("IMG_0001.jpg");
            std::fs::write(&source, b"a photo").unwrap();
            inbox::send_item(
                &store,
                &inbox::SenderIdentity {
                    vault_id: VAULT,
                    sender_id,
                    key_id,
                    inbox_public,
                },
                &inbox::OutgoingItem {
                    item_id: ITEM,
                    source: &source,
                    name: "IMG_0001.jpg".into(),
                    mime_type: Some("image/jpeg".into()),
                    taken_at: None,
                    folder: vec!["Phone".into()],
                    source_kind: "photos".into(),
                },
                &|message| Ok(secret.sign(message)),
            )
            .await
            .unwrap();
            store.get(&envelope_key).await.unwrap()
        });
        Silo {
            _dir: dir,
            store,
            kek,
            envelope_key,
            valid,
            runtime,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let silo = silo();
    let mut envelope = shaped(&silo.valid, data);
    // An envelope naming another item is refused before anything else is
    // read, so the id is set back where the input still parses.
    if let Ok(serde_json::Value::Object(mut map)) = serde_json::from_slice(&envelope) {
        map.insert("item_id".into(), ITEM.to_string().into());
        envelope = serde_json::to_vec(&map).unwrap();
    }
    silo.runtime.block_on(async {
        silo.store.put(&silo.envelope_key, envelope).await.unwrap();
        let _ = inbox::scan_inbox(&silo.store, VAULT, &silo.kek).await;
    });
});
