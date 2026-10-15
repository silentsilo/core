//! The extraction tool over every fixture: the reader someone with only a
//! bucket and a recovery code will run, years after the release that wrote
//! the bucket.
//!
//! Every fixture must open and list what `expected.txt` says it holds. The
//! ones with real content (`expected-content.txt`) must also come out
//! whole: every file, trashed ones under `_trash/`, the password entries
//! and their attachment, with the bytes that were written.

use std::path::{Path, PathBuf};

use silentsilo_fixture::{FIXTURE_CODE, store_dir};

fn fixture_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(silentsilo_fixture::fixtures_dir())
        .expect("the fixtures directory must exist")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn count(lines: &str, prefix: &str, suffix: &str) -> usize {
    lines
        .lines()
        .filter(|l| l.starts_with(prefix) && l.contains(suffix))
        .count()
}

/// Where the tool writes a file a `content file` line names, and the BLAKE3
/// that line expects.
fn written_path(line: &str) -> (String, String) {
    let rest = line.strip_prefix("content file ").unwrap();
    let (path, rest) = rest.rsplit_once(" deleted=").unwrap();
    let (folder, name) = path.split_once("::").unwrap();
    let folder = folder.trim_matches('/');
    let relative = if folder.is_empty() {
        name.to_string()
    } else {
        format!("{folder}/{name}")
    };
    let relative = if rest.starts_with('1') {
        format!("_trash/{relative}")
    } else {
        relative
    };
    (relative, blake3_of(rest))
}

fn blake3_of(line: &str) -> String {
    line.rsplit_once("blake3=").unwrap().1.to_string()
}

fn hash_file(path: &Path) -> String {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("{} was not written: {e}", path.display()));
    blake3::hash(&bytes).to_hex().to_string()
}

#[tokio::test]
async fn the_extraction_tool_reads_every_fixture() {
    let dirs = fixture_dirs();
    assert!(!dirs.is_empty(), "no fixtures found");

    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let expected = std::fs::read_to_string(dir.join("expected.txt")).unwrap();
        let store = silentsilo_extract::folder_store(&store_dir(&dir));
        let backup = silentsilo_extract::open(&*store, FIXTURE_CODE)
            .await
            .unwrap_or_else(|e| panic!("{name}: the extraction tool cannot open it: {e}"));

        assert_eq!(
            backup.file_count(),
            count(&expected, "file ", " deleted=0 "),
            "{name}: files"
        );
        assert_eq!(
            backup.trashed_count(),
            count(&expected, "file ", " deleted=1 "),
            "{name}: trashed files"
        );
        assert_eq!(
            backup.password_count(),
            count(&expected, "password ", ""),
            "{name}: password entries"
        );

        let Ok(content) = std::fs::read_to_string(dir.join("expected-content.txt")) else {
            // Stand-in content keys: there is nothing to decrypt.
            continue;
        };
        let dest = tempfile::tempdir().unwrap();
        let extracted =
            silentsilo_extract::extract(&backup, &*store, dest.path(), &mut |_, _, _| {})
                .await
                .unwrap_or_else(|e| panic!("{name}: extraction failed: {e}"));
        assert!(
            extracted.failed.is_empty(),
            "{name}: not extracted: {:?}",
            extracted.failed
        );

        let files: Vec<&str> = content
            .lines()
            .filter(|l| l.starts_with("content file "))
            .collect();
        assert!(!files.is_empty(), "{name}: no files to compare");
        for line in &files {
            let (relative, hash) = written_path(line);
            assert_eq!(
                hash_file(&dest.path().join(&relative)),
                hash,
                "{name}: {relative} came out with other bytes"
            );
        }

        for line in content
            .lines()
            .filter(|l| l.starts_with("content attachment "))
        {
            let attachment = line
                .strip_prefix("content attachment ")
                .unwrap()
                .split_once("::")
                .unwrap()
                .1
                .split_once(' ')
                .unwrap()
                .0;
            let entry = backup
                .attachments()
                .into_iter()
                .find(|a| a.name == attachment)
                .unwrap_or_else(|| panic!("{name}: the attachment is not listed"));
            let path = dest
                .path()
                .join("_passwords/attachments")
                .join(&entry.entry_title)
                .join(attachment);
            assert_eq!(hash_file(&path), blake3_of(line), "{name}: {attachment}");
        }

        let entries: Vec<serde_json::Value> = serde_json::from_slice(
            &std::fs::read(dest.path().join("_passwords/entries.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(entries.len(), backup.password_count(), "{name}");
        assert!(
            dest.path().join("_passwords/passwords.csv").is_file(),
            "{name}: no CSV"
        );
        // Every file, both password files and the attachment.
        assert_eq!(
            extracted.written,
            files.len() + 2 + backup.attachments().len(),
            "{name}"
        );
    }
}
