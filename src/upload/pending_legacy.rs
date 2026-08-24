use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

const MAX_LEGACY_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPendingUploadEntry {
    chunk_id: String,
    session_id: String,
    video_path: Option<PathBuf>,
    input_path: PathBuf,
    buffered_at_epoch_s: u64,
}

impl PendingUploadStore {
    pub(super) fn import_legacy_manifest(
        &self,
        path: &Path,
        after_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if path.parent() != Some(self.data_dir.path()) {
            bail!("legacy upload manifest is outside the private state directory");
        }
        let name = path
            .file_name()
            .context("legacy upload manifest has no filename")?;
        let mut file = match self
            .data_dir
            .open_private_file(name, false, "legacy upload manifest")
        {
            Ok(file) => file,
            Err(error) if super::super::pending_security::is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let before = self
            .data_dir
            .snapshot_file(&file, "legacy upload manifest")?;
        let bytes = read_manifest(&mut file, path)?;
        let second = read_manifest(&mut file, path)?;
        let after = self
            .data_dir
            .snapshot_file(&file, "legacy upload manifest")?;
        self.data_dir
            .verify_entry(name, &file, "legacy upload manifest")?;
        if bytes != second || before != after || bytes.len() as u64 != before.size {
            bail!("legacy upload manifest changed while reading: {path:?}");
        }
        let legacy_entries: Vec<LegacyPendingUploadEntry> = serde_json::from_slice(&bytes)
            .with_context(|| format!("legacy upload manifest is corrupt: {path:?}"))?;
        let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let mut chunk_ids = BTreeSet::new();
        let mut entries = Vec::with_capacity(legacy_entries.len());
        for entry in legacy_entries {
            if !chunk_ids.insert(entry.chunk_id.clone()) {
                bail!(
                    "legacy upload manifest contains duplicate chunk {:?}",
                    entry.chunk_id
                );
            }
            let video_path = entry.video_path.as_deref().with_context(|| {
                format!("legacy upload {:?} has no video artifact", entry.chunk_id)
            })?;
            entries.push(self.prepare_entry(
                &entry.chunk_id,
                &entry.session_id,
                video_path,
                &entry.input_path,
                entry.buffered_at_epoch_s,
            )?);
        }

        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start legacy upload migration")?;
        let prior: Option<(String, u64)> = transaction
            .query_row(
                "SELECT source_sha256, imported_entries FROM migrations
                 WHERE name = 'pending_uploads.json'",
                [],
                |row| Ok((row.get(0)?, from_i64(row.get(1)?)?)),
            )
            .optional()
            .context("failed to read legacy upload migration receipt")?;
        if let Some((prior_sha256, prior_count)) = prior {
            if prior_sha256 != source_sha256 || prior_count != entries.len() as u64 {
                bail!("legacy upload manifest differs from its durable migration receipt");
            }
            for entry in &entries {
                match load_entry(&transaction, &self.output_dir, &entry.chunk_id)? {
                    Some(existing) if existing == *entry => {}
                    _ => bail!(
                        "legacy upload migration receipt is missing durable chunk {:?}",
                        entry.chunk_id
                    ),
                }
            }
        } else {
            for entry in &entries {
                if receipt_exists_for_chunk(&transaction, &entry.chunk_id)? {
                    bail!(
                        "legacy pending upload {:?} already has a durable backend receipt",
                        entry.chunk_id
                    );
                }
                match load_entry(&transaction, &self.output_dir, &entry.chunk_id)? {
                    Some(existing) if existing == *entry => {}
                    Some(_) => bail!(
                        "legacy pending upload {:?} conflicts with durable state",
                        entry.chunk_id
                    ),
                    None => insert_entry(&transaction, entry)?,
                }
            }
            transaction
                .execute(
                    "INSERT INTO migrations (name, source_sha256, imported_entries)
                     VALUES ('pending_uploads.json', ?1, ?2)",
                    params![source_sha256, to_i64(entries.len() as u64)?],
                )
                .context("failed to persist legacy upload migration receipt")?;
        }
        transaction
            .commit()
            .context("failed to commit legacy upload migration")?;
        drop(connection);
        drop(file);
        after_commit()?;
        self.data_dir
            .remove_file_if_matches(name, before.object_id)?;
        Ok(())
    }
}

fn read_manifest(file: &mut File, path: &Path) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek legacy upload manifest {path:?}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_LEGACY_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read legacy upload manifest {path:?}"))?;
    if bytes.len() as u64 > MAX_LEGACY_MANIFEST_BYTES {
        bail!("legacy upload manifest exceeds the accepted size");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPaths {
        root: PathBuf,
        data: PathBuf,
        output: PathBuf,
    }

    impl TestPaths {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "crowd-cast-legacy-{name}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let data = root.join("data");
            let output = root.join("recordings");
            std::fs::create_dir_all(&data).unwrap();
            std::fs::create_dir_all(&output).unwrap();
            Self { root, data, output }
        }

        fn pair(&self, chunk_id: &str) -> (PathBuf, PathBuf) {
            let video = self.output.join(format!("recording_{chunk_id}.mp4"));
            let input = self.output.join(format!("input_{chunk_id}.msgpack"));
            std::fs::write(&video, b"video bytes").unwrap();
            std::fs::write(&input, b"input bytes").unwrap();
            (video, input)
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn corrupt_legacy_manifest_is_fatal() {
        let paths = TestPaths::new("corrupt");
        std::fs::write(paths.data.join("pending_uploads.json"), b"[").unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("corrupt legacy state must fail startup");

        assert!(format!("{error:#}").contains("legacy upload manifest is corrupt"));
        assert!(paths.data.join("pending_uploads.json").exists());
    }

    #[test]
    fn valid_manifest_is_imported_before_atomic_retirement() {
        let paths = TestPaths::new("valid");
        let chunk_id = "session-a_seg0000";
        let (video, input) = paths.pair(chunk_id);
        let legacy = serde_json::json!([{
            "chunk_id": chunk_id,
            "session_id": "session-a",
            "video_path": video,
            "input_path": input,
            "buffered_at_epoch_s": 17,
        }]);
        std::fs::write(
            paths.data.join("pending_uploads.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();

        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let pending = store.list_pending().unwrap();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].buffered_at_epoch_s, 17);
        assert!(!paths.data.join("pending_uploads.json").exists());
        let connection = store.lock().unwrap();
        let receipt: (String, i64) = connection
            .query_row(
                "SELECT source_sha256, imported_entries FROM migrations
                 WHERE name = 'pending_uploads.json'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(receipt.0.len(), 64);
        assert_eq!(receipt.1, 1);
    }

    #[test]
    fn migration_restart_is_idempotent() {
        let paths = TestPaths::new("restart");
        let chunk_id = "session-a_seg0000";
        let (video, input) = paths.pair(chunk_id);
        let legacy = serde_json::to_vec(&serde_json::json!([{
            "chunk_id": chunk_id,
            "session_id": "session-a",
            "video_path": video,
            "input_path": input,
            "buffered_at_epoch_s": 17,
        }]))
        .unwrap();
        let legacy_path = paths.data.join("pending_uploads.json");
        std::fs::write(&legacy_path, &legacy).unwrap();
        let error = PendingUploadStore::open_with_legacy_hook(&paths.data, &paths.output, || {
            bail!("simulated crash after legacy migration commit")
        })
        .err()
        .expect("simulated crash must interrupt manifest retirement");
        assert!(format!("{error:#}").contains("simulated crash"));
        assert!(legacy_path.exists());

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert_eq!(reopened.list_pending().unwrap().len(), 1);
        assert!(!legacy_path.exists());
    }

    #[test]
    fn duplicate_chunk_is_fatal() {
        let paths = TestPaths::new("duplicate");
        let chunk_id = "session-a_seg0000";
        let (video, input) = paths.pair(chunk_id);
        let entry = serde_json::json!({
            "chunk_id": chunk_id,
            "session_id": "session-a",
            "video_path": video,
            "input_path": input,
            "buffered_at_epoch_s": 17,
        });
        std::fs::write(
            paths.data.join("pending_uploads.json"),
            serde_json::to_vec(&serde_json::json!([entry.clone(), entry])).unwrap(),
        )
        .unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("duplicate legacy rows must fail startup");

        assert!(format!("{error:#}").contains("duplicate chunk"));
        assert!(paths.data.join("pending_uploads.json").exists());
        let connection =
            rusqlite::Connection::open(paths.data.join("pending_uploads.sqlite3")).unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM pending_uploads", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
