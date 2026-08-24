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
                "crowd-cast-pending-{name}-{}-{}",
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

    fn receipt_for(entry: &PendingUploadEntry) -> ReceiptCommit {
        ReceiptCommit {
            receipt: UploadReceipt {
                contract_version: UPLOAD_RECEIPT_CONTRACT_VERSION,
                receipt_id: "receipt-1".to_string(),
                session_id: entry.session_id.clone(),
                chunk_id: entry.chunk_id.clone(),
                video: ReceiptArtifact {
                    key: "recordings/video.mp4".to_string(),
                    size_bytes: entry.video.size_bytes,
                    sha256: entry.video.sha256.clone(),
                },
                input: ReceiptArtifact {
                    key: "keylogs/input.msgpack".to_string(),
                    size_bytes: entry.input.size_bytes,
                    sha256: entry.input.sha256.clone(),
                },
            },
            trusted_endpoint: "https://api.example.invalid/prod/presign".to_string(),
            expected_video_key: "recordings/video.mp4".to_string(),
            expected_input_key: "keylogs/input.msgpack".to_string(),
        }
    }

    #[test]
    fn reconciles_complete_local_pair_into_durable_queue() {
        let paths = TestPaths::new("reconcile");
        let chunk_id = "session-a_seg0007";
        let (video, input) = paths.pair(chunk_id);

        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let pending = store.list_pending().unwrap();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].chunk_id, chunk_id);
        assert_eq!(pending[0].session_id, "session-a");
        assert_eq!(pending[0].video.path, std::fs::canonicalize(video).unwrap());
        assert_eq!(pending[0].input.path, std::fs::canonicalize(input).unwrap());
    }

    #[test]
    fn unpaired_local_artifact_stops_startup_without_deleting_bytes() {
        let paths = TestPaths::new("unpaired");
        let video = paths.output.join("recording_session-a_seg0000.mp4");
        std::fs::write(&video, b"video bytes").unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("unpaired video must fail startup");

        assert!(format!("{error:#}").contains("has no input artifact"));
        assert_eq!(std::fs::read(video).unwrap(), b"video bytes");
    }

    #[test]
    fn pending_upload_survives_retry_window_and_restart() {
        let paths = TestPaths::new("outage");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let pending = store.list_pending().unwrap();
            assert_eq!(pending.len(), 1);
        }

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let pending = reopened.list_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].chunk_id, chunk_id);
        assert!(pending[0].video.path.exists());
        assert!(pending[0].input.path.exists());
    }

    #[test]
    fn partial_pair_upload_cannot_complete_without_receipt() {
        let paths = TestPaths::new("partial-upload");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        let error = store
            .complete_received(chunk_id)
            .expect_err("a single successful PUT has no receipt");

        assert!(format!("{error:#}").contains("no durable backend receipt"));
        assert_eq!(store.list_pending().unwrap().len(), 1);
        assert!(store.list_pending().unwrap()[0].video.path.exists());
        assert!(store.list_pending().unwrap()[0].input.path.exists());
    }

    #[test]
    fn digest_mismatch_cannot_be_recorded_as_receipt() {
        let paths = TestPaths::new("bad-receipt");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let entry = store.list_pending().unwrap().pop().unwrap();
        let mut receipt = receipt_for(&entry);
        receipt.receipt.input.sha256 = "0".repeat(64);

        let error = store
            .record_receipt(&entry, &receipt)
            .expect_err("mismatched receipt must fail");

        assert!(format!("{error:#}").contains("wrong input size or SHA-256"));
        assert_eq!(store.list_pending().unwrap(), vec![entry]);
    }

    #[test]
    fn receipt_must_bind_the_presigned_keys_and_trusted_endpoint() {
        let paths = TestPaths::new("receipt-transaction");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let entry = store.list_pending().unwrap().pop().unwrap();
        let mut wrong_key = receipt_for(&entry);
        wrong_key.expected_input_key = "keylogs/different.msgpack".to_string();

        let key_error = store
            .record_receipt(&entry, &wrong_key)
            .expect_err("receipt must match the client-presigned object key");
        assert!(format!("{key_error:#}").contains("wrong input object key"));

        let mut wrong_endpoint = receipt_for(&entry);
        wrong_endpoint.trusted_endpoint =
            "https://api.example.invalid/prod/presign?redirect=1".to_string();
        let endpoint_error = store
            .record_receipt(&entry, &wrong_endpoint)
            .expect_err("receipt must bind the exact configured endpoint");
        assert!(format!("{endpoint_error:#}").contains("transaction URL"));
        assert_eq!(store.list_pending().unwrap(), vec![entry]);
    }

    #[test]
    fn crash_after_receipt_and_one_delete_finishes_on_restart() {
        let paths = TestPaths::new("received-crash");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let (video_path, input_path) = {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store.list_pending().unwrap().pop().unwrap();
            store.record_receipt(&entry, &receipt_for(&entry)).unwrap();
            std::fs::remove_file(&entry.video.path).unwrap();
            (entry.video.path.clone(), entry.input.path.clone())
        };

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert!(reopened.list_pending().unwrap().is_empty());
        assert!(!video_path.exists());
        assert!(!input_path.exists());
        let connection = reopened.lock().unwrap();
        let completed_at: i64 = connection
            .query_row(
                "SELECT completed_at_epoch_s FROM upload_receipts WHERE receipt_id = 'receipt-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(completed_at > 0);
    }

    #[test]
    fn crash_after_receipt_before_deletes_finishes_on_restart() {
        let paths = TestPaths::new("received-before-delete");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let (video_path, input_path) = {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store.list_pending().unwrap().pop().unwrap();
            store.record_receipt(&entry, &receipt_for(&entry)).unwrap();
            (entry.video.path.clone(), entry.input.path.clone())
        };

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert!(reopened.list_pending().unwrap().is_empty());
        assert!(!video_path.exists());
        assert!(!input_path.exists());
    }

    #[test]
    fn crash_after_both_deletes_finishes_receipt_custody_on_restart() {
        let paths = TestPaths::new("received-after-deletes");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store.list_pending().unwrap().pop().unwrap();
            store.record_receipt(&entry, &receipt_for(&entry)).unwrap();
            std::fs::remove_file(&entry.video.path).unwrap();
            std::fs::remove_file(&entry.input.path).unwrap();
        }

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let connection = reopened.lock().unwrap();
        let completed: i64 = connection
            .query_row(
                "SELECT count(*) FROM upload_receipts
                 WHERE receipt_id = 'receipt-1' AND completed_at_epoch_s IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(completed, 1);
    }

    #[test]
    fn receipt_id_cannot_be_replayed_for_another_chunk() {
        let paths = TestPaths::new("receipt-replay");
        paths.pair("session-a_seg0000");
        paths.pair("session-a_seg0001");
        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let entries = store.list_pending().unwrap();
        let first = entries
            .iter()
            .find(|entry| entry.chunk_id.ends_with("0000"))
            .unwrap();
        let second = entries
            .iter()
            .find(|entry| entry.chunk_id.ends_with("0001"))
            .unwrap();
        store.record_receipt(first, &receipt_for(first)).unwrap();
        let mut replay = receipt_for(second);
        replay.receipt.session_id = second.session_id.clone();
        replay.receipt.chunk_id = second.chunk_id.clone();

        let error = store
            .record_receipt(second, &replay)
            .expect_err("one receiptId must not authorize two chunks");

        assert!(format!("{error:#}").contains("immutable backend receipt"));
        assert!(second.video.path.exists());
        assert!(second.input.path.exists());
    }

    #[test]
    fn completed_receipt_is_retained_and_rejects_recreated_chunk() {
        let paths = TestPaths::new("completed-replay");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store.list_pending().unwrap().pop().unwrap();
            store.record_receipt(&entry, &receipt_for(&entry)).unwrap();
            store.complete_received(chunk_id).unwrap();
            let connection = store.lock().unwrap();
            let completed: i64 = connection
                .query_row(
                    "SELECT count(*) FROM upload_receipts
                     WHERE chunk_id = ?1 AND completed_at_epoch_s IS NOT NULL",
                    [chunk_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(completed, 1);
        }
        let (video, input) = paths.pair(chunk_id);

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("completed chunk bytes must not be admitted again");

        assert!(format!("{error:#}").contains("durable backend receipt"));
        assert!(video.exists());
        assert!(input.exists());
    }

    #[test]
    fn corrupt_terminal_path_is_fatal_before_any_deletion() {
        let paths = TestPaths::new("terminal-path");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let outside = paths.root.join("must-not-delete.mp4");
        std::fs::write(&outside, b"video bytes").unwrap();
        {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store.list_pending().unwrap().pop().unwrap();
            store.record_receipt(&entry, &receipt_for(&entry)).unwrap();
            let connection = store.lock().unwrap();
            connection
                .execute(
                    "UPDATE pending_uploads SET video_path = ?1 WHERE chunk_id = ?2",
                    params![path_as_str(&outside).unwrap(), chunk_id],
                )
                .unwrap();
        }

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("corrupt terminal path must fail startup");

        let text = format!("{error:#}");
        assert!(text.contains("outside its private directory"), "{text}");
        assert!(outside.exists());
    }

    #[test]
    fn explicit_discard_is_crash_consistent() {
        let paths = TestPaths::new("discard-crash");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let (video_path, input_path) = {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store
                .record_discard(chunk_id, PendingDiscard::UserPanic)
                .unwrap();
            std::fs::remove_file(&entry.input.path).unwrap();
            (entry.video.path.clone(), entry.input.path.clone())
        };

        let reopened = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert!(reopened.list_pending().unwrap().is_empty());
        assert!(!video_path.exists());
        assert!(!input_path.exists());
    }

    #[test]
    fn corrupt_discard_audit_is_fatal_before_deletion() {
        let paths = TestPaths::new("discard-corrupt");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let (video_path, input_path) = {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            let entry = store
                .record_discard(chunk_id, PendingDiscard::UserPanic)
                .unwrap();
            let connection = store.lock().unwrap();
            connection
                .execute(
                    "UPDATE upload_discards SET video_sha256 = ?1 WHERE chunk_id = ?2",
                    params!["0".repeat(64), chunk_id],
                )
                .unwrap();
            (entry.video.path.clone(), entry.input.path.clone())
        };

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("corrupt discard custody must fail startup");

        let text = format!("{error:#}");
        assert!(text.contains("does not bind its pending bytes"), "{text}");
        assert!(video_path.exists());
        assert!(input_path.exists());
    }

    #[test]
    fn corrupt_database_is_fatal() {
        let paths = TestPaths::new("corrupt");
        {
            let _store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        }
        std::fs::write(
            paths.data.join("pending_uploads.sqlite3"),
            b"not a sqlite database",
        )
        .unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("corrupt database must fail startup");

        assert!(format!("{error:#}").contains("pending-upload database"));
    }

    #[test]
    fn crash_after_database_creation_before_schema_is_recovered() {
        let paths = TestPaths::new("empty-database");
        File::create(paths.data.join("pending_uploads.sqlite3")).unwrap();

        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert!(store.list_pending().unwrap().is_empty());
    }

    #[test]
    fn changed_local_bytes_are_fatal_on_restart() {
        let paths = TestPaths::new("changed-local");
        let chunk_id = "session-a_seg0000";
        paths.pair(chunk_id);
        let input_path = {
            let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
            store
                .list_pending()
                .unwrap()
                .pop()
                .unwrap()
                .input
                .path
                .clone()
        };
        std::fs::write(&input_path, b"different input bytes").unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("changed admitted bytes must fail startup");

        let text = format!("{error:#}");
        assert!(
            text.contains("identity or size changed") || text.contains("changed after admission"),
            "{text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn swapped_artifact_symlink_is_rejected_before_upload() {
        use std::os::unix::fs::symlink;

        let paths = TestPaths::new("artifact-symlink");
        paths.pair("session-a_seg0000");
        let store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();
        let entry = store.list_pending().unwrap().pop().unwrap();
        let outside = paths.root.join("secret");
        std::fs::write(&outside, b"secret bytes").unwrap();
        std::fs::remove_file(&entry.video.path).unwrap();
        symlink(&outside, &entry.video.path).unwrap();

        let error = entry
            .video
            .open_verified("video")
            .expect_err("artifact symlink must not be followed");

        let text = format!("{error:#}");
        assert!(text.contains("symbolic links"), "{text}");
        assert_eq!(std::fs::read(outside).unwrap(), b"secret bytes");
    }

    #[cfg(unix)]
    #[test]
    fn state_directory_and_database_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let paths = TestPaths::new("state-permissions");
        let _store = PendingUploadStore::open(&paths.data, &paths.output).unwrap();

        assert_eq!(
            std::fs::symlink_metadata(&paths.data)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            std::fs::symlink_metadata(&paths.output)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            std::fs::symlink_metadata(paths.data.join("pending_uploads.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_database_is_fatal_without_touching_target() {
        use std::os::unix::fs::symlink;

        let paths = TestPaths::new("state-symlink");
        let target = paths.root.join("target");
        std::fs::write(&target, b"do not touch").unwrap();
        symlink(&target, paths.data.join("pending_uploads.sqlite3")).unwrap();

        let error = PendingUploadStore::open(&paths.data, &paths.output)
            .err()
            .expect("state symlink must fail startup");

        let text = format!("{error:#}");
        assert!(text.contains("symbolic links"), "{text}");
        assert_eq!(std::fs::read(target).unwrap(), b"do not touch");
    }
}
