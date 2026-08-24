use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use super::pending_artifact::ArtifactSeal;
use super::pending_security::{secure_sqlite_files, PrivateDirectory};
use super::receipt_endpoint::trusted_endpoint_identity;

const SCHEMA_VERSION: i64 = 1;
pub(crate) const UPLOAD_RECEIPT_CONTRACT_VERSION: u32 = 1;
const MAX_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptArtifact {
    pub(crate) key: String,
    #[serde(rename = "sizeBytes")]
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UploadReceipt {
    #[serde(rename = "contractVersion")]
    pub(crate) contract_version: u32,
    #[serde(rename = "receiptId")]
    pub(crate) receipt_id: String,
    #[serde(rename = "sessionId")]
    pub(crate) session_id: String,
    #[serde(rename = "chunkId")]
    pub(crate) chunk_id: String,
    pub(crate) video: ReceiptArtifact,
    pub(crate) input: ReceiptArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptCommit {
    pub(crate) receipt: UploadReceipt,
    pub(crate) trusted_endpoint: String,
    pub(crate) expected_video_key: String,
    pub(crate) expected_input_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingDiscard {
    UserPanic,
}

impl PendingDiscard {
    fn as_str(self) -> &'static str {
        match self {
            Self::UserPanic => "user-panic",
        }
    }
}

impl UploadReceipt {
    fn validate_record(&self) -> Result<()> {
        if self.receipt_id.trim().is_empty() {
            bail!("backend upload receipt has an empty receiptId");
        }
        if self.contract_version != UPLOAD_RECEIPT_CONTRACT_VERSION {
            bail!(
                "backend upload receipt contract version {} is unsupported",
                self.contract_version
            );
        }
        validate_bounded_value(&self.receipt_id, "receipt ID", MAX_ID_BYTES)?;
        validate_chunk_session(&self.chunk_id, &self.session_id)?;
        validate_object_key(&self.video.key, "receipt video")?;
        validate_object_key(&self.input.key, "receipt input")?;
        if self.video.key == self.input.key {
            bail!("backend upload receipt has invalid object keys");
        }
        validate_sha256(&self.video.sha256, "receipt video")?;
        validate_sha256(&self.input.sha256, "receipt input")?;
        Ok(())
    }

    pub(crate) fn validate(
        &self,
        entry: &PendingUploadEntry,
        commit: &ReceiptCommit,
    ) -> Result<()> {
        self.validate_record()?;
        let endpoint = trusted_endpoint_identity(&commit.trusted_endpoint)?;
        if endpoint != commit.trusted_endpoint {
            bail!("receipt commit contains a non-canonical trusted endpoint");
        }
        validate_object_key(&commit.expected_video_key, "expected video")?;
        validate_object_key(&commit.expected_input_key, "expected input")?;
        if commit.expected_video_key == commit.expected_input_key {
            bail!("receipt commit contains duplicate expected object keys");
        }
        if self.session_id != entry.session_id || self.chunk_id != entry.chunk_id {
            bail!("backend upload receipt identifies a different session or chunk");
        }
        validate_receipt_artifact(
            "video",
            &self.video,
            &entry.video,
            &commit.expected_video_key,
        )?;
        validate_receipt_artifact(
            "input",
            &self.input,
            &entry.input,
            &commit.expected_input_key,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingState {
    Pending,
    Received,
    Discarding,
}

impl PendingState {
    fn parse(value: &str) -> std::io::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "received" => Ok(Self::Received),
            "discarding" => Ok(Self::Discarding),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid pending-upload state {value:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingUploadEntry {
    pub(crate) chunk_id: String,
    pub(crate) session_id: String,
    pub(crate) video: ArtifactSeal,
    pub(crate) input: ArtifactSeal,
    pub(crate) buffered_at_epoch_s: u64,
    pub(crate) state: PendingState,
    pub(crate) receipt: Option<ReceiptCommit>,
}

struct DiscardAudit {
    discard_id: String,
    chunk_id: String,
    session_id: String,
    reason: String,
    video_size_bytes: u64,
    video_sha256: String,
    input_size_bytes: u64,
    input_sha256: String,
    completed_at_epoch_s: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct PendingUploadStore {
    connection: Arc<Mutex<Connection>>,
    data_dir: PrivateDirectory,
    output_dir: PrivateDirectory,
    _database_file: Arc<File>,
}

impl PendingUploadStore {
    pub(crate) fn open(data_dir: &Path, output_dir: &Path) -> Result<Self> {
        let data_dir = PrivateDirectory::open_or_create(data_dir, "upload state")?;
        let output_dir = PrivateDirectory::open_or_create(output_dir, "recording")?;
        let database_name = OsStr::new("pending_uploads.sqlite3");
        let database_file =
            data_dir.prepare_private_file(database_name, "upload state database")?;
        let database_path = data_dir.path().join(database_name);
        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| format!("failed to open pending-upload database {database_path:?}"))?;
        data_dir.verify_entry(database_name, &database_file, "upload state database")?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("failed to enable WAL for pending-upload database")?;
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .context("failed to verify pending-upload journal mode")?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            bail!("pending-upload database refused WAL journal mode");
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("failed to enable FULL synchronization for pending-upload database")?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .context("failed to verify pending-upload synchronization mode")?;
        if synchronous != 2 {
            bail!("pending-upload database refused FULL synchronization");
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .context("failed to set pending-upload database busy timeout")?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .context("failed to enable pending-upload foreign keys")?;
        let foreign_keys: i64 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .context("failed to verify pending-upload foreign keys")?;
        if foreign_keys != 1 {
            bail!("pending-upload database refused foreign-key enforcement");
        }
        let integrity: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .context("pending-upload database integrity check failed")?;
        if integrity != "ok" {
            bail!("pending-upload database is corrupt: {integrity}");
        }

        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("failed to read pending-upload schema version")?;
        if version == 0 {
            let application_tables: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                    [],
                    |row| row.get(0),
                )
                .context("failed to inspect unversioned pending-upload database")?;
            if application_tables != 0 {
                bail!("unversioned pending-upload database contains unexpected tables");
            }
            let transaction = connection
                .transaction()
                .context("failed to start pending-upload schema transaction")?;
            transaction
                .execute_batch(
                    "CREATE TABLE upload_receipts (
                    receipt_id TEXT PRIMARY KEY NOT NULL,
                    chunk_id TEXT UNIQUE NOT NULL,
                    session_id TEXT NOT NULL,
                    contract_version INTEGER NOT NULL CHECK(contract_version = 1),
                    trusted_endpoint TEXT NOT NULL,
                    expected_video_key TEXT NOT NULL,
                    expected_input_key TEXT NOT NULL,
                    video_key TEXT NOT NULL,
                    video_size_bytes INTEGER NOT NULL CHECK(video_size_bytes >= 0),
                    video_sha256 TEXT NOT NULL CHECK(length(video_sha256) = 64),
                    input_key TEXT NOT NULL,
                    input_size_bytes INTEGER NOT NULL CHECK(input_size_bytes >= 0),
                    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
                    completed_at_epoch_s INTEGER CHECK(completed_at_epoch_s >= 0),
                    CHECK(video_key <> input_key),
                    CHECK(length(receipt_id) BETWEEN 1 AND 128),
                    CHECK(length(chunk_id) BETWEEN 1 AND 128),
                    CHECK(length(session_id) BETWEEN 1 AND 128),
                    CHECK(length(video_key) BETWEEN 1 AND 1024),
                    CHECK(length(input_key) BETWEEN 1 AND 1024),
                    CHECK(length(expected_video_key) BETWEEN 1 AND 1024),
                    CHECK(length(expected_input_key) BETWEEN 1 AND 1024),
                    CHECK(expected_video_key <> expected_input_key)
                );
                CREATE TABLE upload_discards (
                    discard_id TEXT PRIMARY KEY NOT NULL,
                    chunk_id TEXT UNIQUE NOT NULL,
                    session_id TEXT NOT NULL,
                    reason TEXT NOT NULL CHECK(reason = 'user-panic'),
                    video_size_bytes INTEGER NOT NULL CHECK(video_size_bytes >= 0),
                    video_sha256 TEXT NOT NULL CHECK(length(video_sha256) = 64),
                    input_size_bytes INTEGER NOT NULL CHECK(input_size_bytes >= 0),
                    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
                    initiated_at_epoch_s INTEGER NOT NULL CHECK(initiated_at_epoch_s >= 0),
                    completed_at_epoch_s INTEGER CHECK(completed_at_epoch_s >= 0),
                    CHECK(length(discard_id) BETWEEN 1 AND 128),
                    CHECK(length(chunk_id) BETWEEN 1 AND 128),
                    CHECK(length(session_id) BETWEEN 1 AND 128)
                );
                CREATE TABLE pending_uploads (
                    chunk_id TEXT PRIMARY KEY NOT NULL,
                    session_id TEXT NOT NULL,
                    video_path TEXT NOT NULL UNIQUE,
                    video_object_id TEXT NOT NULL CHECK(length(video_object_id) = 33),
                    video_size_bytes INTEGER NOT NULL CHECK(video_size_bytes >= 0),
                    video_sha256 TEXT NOT NULL CHECK(length(video_sha256) = 64),
                    input_path TEXT NOT NULL UNIQUE,
                    input_object_id TEXT NOT NULL CHECK(length(input_object_id) = 33),
                    input_size_bytes INTEGER NOT NULL CHECK(input_size_bytes >= 0),
                    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
                    buffered_at_epoch_s INTEGER NOT NULL CHECK(buffered_at_epoch_s >= 0),
                    state TEXT NOT NULL CHECK(state IN ('pending', 'received', 'discarding')),
                    receipt_id TEXT UNIQUE REFERENCES upload_receipts(receipt_id),
                    discard_id TEXT UNIQUE REFERENCES upload_discards(discard_id),
                    CHECK(length(chunk_id) BETWEEN 1 AND 128),
                    CHECK(length(session_id) BETWEEN 1 AND 128),
                    CHECK(
                        (state = 'pending' AND receipt_id IS NULL AND discard_id IS NULL) OR
                        (state = 'received' AND receipt_id IS NOT NULL AND discard_id IS NULL) OR
                        (state = 'discarding' AND receipt_id IS NULL AND discard_id IS NOT NULL)
                    )
                );
                PRAGMA user_version = 1;",
                )
                .context("failed to create pending-upload schema")?;
            transaction
                .commit()
                .context("failed to commit pending-upload schema")?;
            data_dir.sync()?;
        } else if version != SCHEMA_VERSION {
            bail!("unsupported pending-upload schema version {version}; expected {SCHEMA_VERSION}");
        }
        secure_sqlite_files(&data_dir, database_name)?;
        data_dir.sync()?;
        data_dir.verify_entry(database_name, &database_file, "upload state database")?;

        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
            data_dir,
            output_dir,
            _database_file: Arc::new(database_file),
        };
        store.validate_receipt_custody()?;
        store.validate_discard_custody()?;
        store.validate_all_entries()?;
        store.finish_terminal_entries()?;
        store.reconcile_local_segments()?;
        store.validate_receipt_custody()?;
        store.validate_discard_custody()?;
        store.validate_all_entries()?;
        Ok(store)
    }

    pub(crate) fn default_data_dir() -> Result<PathBuf> {
        directories::ProjectDirs::from("dev", "crowd-cast", "agent")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .context("failed to resolve crowd-cast data directory")
    }

    pub(crate) fn enqueue(
        &self,
        chunk_id: &str,
        session_id: &str,
        video_path: &Path,
        input_path: &Path,
        buffered_at_epoch_s: u64,
    ) -> Result<PendingUploadEntry> {
        let entry = self.prepare_entry(
            chunk_id,
            session_id,
            video_path,
            input_path,
            buffered_at_epoch_s,
        )?;

        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start pending-upload enqueue transaction")?;
        if receipt_exists_for_chunk(&transaction, chunk_id)? {
            bail!("chunk {chunk_id:?} already has a durable backend receipt");
        }
        match load_entry(&transaction, &self.output_dir, chunk_id)? {
            Some(existing) if existing == entry => {}
            Some(_) => bail!("pending upload {chunk_id:?} already exists with different bytes"),
            None => insert_entry(&transaction, &entry)?,
        }
        transaction
            .commit()
            .context("failed to commit pending upload")?;
        Ok(entry)
    }

    pub(crate) fn list_pending(&self) -> Result<Vec<PendingUploadEntry>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT p.chunk_id, p.session_id, p.video_path, p.video_object_id,
                        p.video_size_bytes, p.video_sha256,
                        p.input_path, p.input_object_id, p.input_size_bytes, p.input_sha256,
                        p.buffered_at_epoch_s,
                        p.state, r.receipt_id, r.session_id, r.chunk_id,
                        r.contract_version, r.trusted_endpoint,
                        r.video_key, r.video_size_bytes, r.video_sha256,
                        r.input_key, r.input_size_bytes, r.input_sha256,
                        r.expected_video_key, r.expected_input_key
                 FROM pending_uploads p
                 LEFT JOIN upload_receipts r ON r.receipt_id = p.receipt_id
                 WHERE p.state = 'pending' ORDER BY p.buffered_at_epoch_s, p.chunk_id",
            )
            .context("failed to prepare pending-upload query")?;
        let rows = statement
            .query_map([], |row| row_to_entry(row, &self.output_dir))
            .context("failed to query pending uploads")?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to decode pending-upload row")
    }

    pub(crate) fn record_receipt(
        &self,
        entry: &PendingUploadEntry,
        commit: &ReceiptCommit,
    ) -> Result<()> {
        let receipt = &commit.receipt;
        receipt.validate(entry, commit)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start upload-receipt transaction")?;
        let current = load_entry(&transaction, &self.output_dir, &entry.chunk_id)?
            .with_context(|| format!("missing pending upload {:?}", entry.chunk_id))?;
        if current != *entry {
            bail!("pending upload {:?} changed before receipt", entry.chunk_id);
        }
        entry.video.verify("video")?;
        entry.input.verify("input")?;
        transaction
            .execute(
                "INSERT INTO upload_receipts (
                    receipt_id, chunk_id, session_id, contract_version, trusted_endpoint,
                    expected_video_key, expected_input_key,
                    video_key, video_size_bytes, video_sha256,
                    input_key, input_size_bytes, input_sha256, completed_at_epoch_s
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL)",
                params![
                    receipt.receipt_id,
                    receipt.chunk_id,
                    receipt.session_id,
                    receipt.contract_version,
                    commit.trusted_endpoint,
                    commit.expected_video_key,
                    commit.expected_input_key,
                    receipt.video.key,
                    to_i64(receipt.video.size_bytes)?,
                    receipt.video.sha256,
                    receipt.input.key,
                    to_i64(receipt.input.size_bytes)?,
                    receipt.input.sha256,
                ],
            )
            .context("failed to persist immutable backend receipt")?;
        let changed = transaction
            .execute(
                "UPDATE pending_uploads SET state = 'received', receipt_id = ?1
                 WHERE chunk_id = ?2 AND state = 'pending'",
                params![receipt.receipt_id, entry.chunk_id],
            )
            .context("failed to persist upload receipt")?;
        if changed != 1 {
            bail!(
                "pending upload {:?} was not in pending state while recording receipt",
                entry.chunk_id
            );
        }
        transaction
            .commit()
            .context("failed to commit upload receipt")?;
        Ok(())
    }

    pub(crate) fn finish_received_if_present(&self, chunk_id: &str) -> Result<bool> {
        let entry = self
            .load(chunk_id)?
            .with_context(|| format!("missing pending upload {chunk_id:?}"))?;
        match entry.state {
            PendingState::Pending => Ok(false),
            PendingState::Received => {
                self.complete_received_entry(&entry)?;
                Ok(true)
            }
            PendingState::Discarding => {
                bail!("pending upload {chunk_id:?} is being explicitly discarded")
            }
        }
    }

    pub(crate) fn complete_received(&self, chunk_id: &str) -> Result<()> {
        let entry = self
            .load(chunk_id)?
            .with_context(|| format!("missing received pending upload {chunk_id:?}"))?;
        if entry.state != PendingState::Received {
            bail!("pending upload {chunk_id:?} has no durable backend receipt");
        }
        self.complete_received_entry(&entry)
    }

    pub(crate) fn discard(&self, chunk_id: &str, confirmation: PendingDiscard) -> Result<()> {
        let entry = self.record_discard(chunk_id, confirmation)?;
        self.complete_discard_entry(&entry)
    }

    fn record_discard(
        &self,
        chunk_id: &str,
        confirmation: PendingDiscard,
    ) -> Result<PendingUploadEntry> {
        let entry = self
            .load(chunk_id)?
            .with_context(|| format!("missing pending upload {chunk_id:?}"))?;
        if entry.state != PendingState::Pending {
            bail!("pending upload {chunk_id:?} is not discardable");
        }
        let discard_id = uuid::Uuid::new_v4().to_string();
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start pending-upload discard transaction")?;
        let current = load_entry(&transaction, &self.output_dir, chunk_id)?
            .with_context(|| format!("missing pending upload {chunk_id:?}"))?;
        if current != entry {
            bail!("pending upload {chunk_id:?} changed before discard confirmation");
        }
        entry.video.verify("video")?;
        entry.input.verify("input")?;
        transaction
            .execute(
                "INSERT INTO upload_discards (
                    discard_id, chunk_id, session_id, reason,
                    video_size_bytes, video_sha256, input_size_bytes, input_sha256,
                    initiated_at_epoch_s, completed_at_epoch_s
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, unixepoch(), NULL)",
                params![
                    discard_id,
                    entry.chunk_id,
                    entry.session_id,
                    confirmation.as_str(),
                    to_i64(entry.video.size_bytes)?,
                    entry.video.sha256,
                    to_i64(entry.input.size_bytes)?,
                    entry.input.sha256,
                ],
            )
            .context("failed to persist immutable upload discard audit")?;
        let changed = transaction
            .execute(
                "UPDATE pending_uploads SET state = 'discarding', discard_id = ?2
                 WHERE chunk_id = ?1 AND state = 'pending'",
                params![chunk_id, discard_id],
            )
            .context("failed to persist pending-upload discard")?;
        if changed != 1 {
            bail!("pending upload {chunk_id:?} is not discardable");
        }
        transaction
            .commit()
            .context("failed to commit pending-upload discard audit")?;
        drop(connection);
        self.load(chunk_id)?
            .with_context(|| format!("missing discarded pending upload {chunk_id:?}"))
    }

    fn finish_terminal_entries(&self) -> Result<()> {
        let entries = self.list_all()?;
        for entry in entries {
            match entry.state {
                PendingState::Pending => {}
                PendingState::Received => {
                    self.complete_received_entry(&entry)?;
                }
                PendingState::Discarding => {
                    self.complete_discard_entry(&entry)?;
                }
            }
        }
        Ok(())
    }

    fn prepare_entry(
        &self,
        chunk_id: &str,
        session_id: &str,
        video_path: &Path,
        input_path: &Path,
        buffered_at_epoch_s: u64,
    ) -> Result<PendingUploadEntry> {
        validate_chunk_session(chunk_id, session_id)?;
        let entry = PendingUploadEntry {
            chunk_id: chunk_id.to_string(),
            session_id: session_id.to_string(),
            video: self.seal_artifact(video_path, "video", true)?,
            input: self.seal_artifact(input_path, "input", true)?,
            buffered_at_epoch_s,
            state: PendingState::Pending,
            receipt: None,
        };
        Ok(entry)
    }

    fn reconcile_local_segments(&self) -> Result<()> {
        self.output_dir.verify_path("recording")?;
        let directory_before = self.output_dir.snapshot()?;
        let mut inputs = BTreeMap::new();
        let mut videos = BTreeMap::new();
        for item in std::fs::read_dir(self.output_dir.path())
            .with_context(|| format!("failed to scan recording directory {:?}", self.output_dir))?
        {
            let item = item.context("failed to read recording directory entry")?;
            if !item
                .file_type()
                .context("failed to read recording artifact type")?
                .is_file()
            {
                continue;
            }
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("recording artifact filename is not UTF-8"))?;
            if let Some(chunk_id) = name
                .strip_prefix("input_")
                .and_then(|value| value.strip_suffix(".msgpack"))
            {
                if chunk_id.contains("_partial_") {
                    continue;
                }
                if inputs.insert(chunk_id.to_string(), item.path()).is_some() {
                    bail!("duplicate input artifact for chunk {chunk_id:?}");
                }
                continue;
            }
            if let Some(rest) = name.strip_prefix("recording_") {
                let Some((chunk_id, extension)) = rest.rsplit_once('.') else {
                    bail!("recording artifact has no extension: {name:?}");
                };
                if !matches!(extension, "mp4" | "mov" | "mkv" | "flv" | "ts") {
                    continue;
                }
                if videos.insert(chunk_id.to_string(), item.path()).is_some() {
                    bail!("duplicate video artifact for chunk {chunk_id:?}");
                }
            }
        }
        if self.output_dir.snapshot()? != directory_before {
            bail!("recording directory changed while reconciling local artifacts");
        }
        self.output_dir.verify_path("recording")?;

        let chunk_ids: BTreeSet<_> = inputs.keys().chain(videos.keys()).cloned().collect();
        for chunk_id in chunk_ids {
            let input_path = inputs
                .get(&chunk_id)
                .with_context(|| format!("video chunk {chunk_id:?} has no input artifact"))?;
            let video_path = videos
                .get(&chunk_id)
                .with_context(|| format!("input chunk {chunk_id:?} has no video artifact"))?;
            let session_id = session_id_from_chunk(&chunk_id)?;
            if self.load(&chunk_id)?.is_none() {
                self.enqueue(&chunk_id, session_id, video_path, input_path, 0)?;
            }
        }
        Ok(())
    }

    fn validate_all_entries(&self) -> Result<()> {
        for entry in self.list_all()? {
            validate_chunk_session(&entry.chunk_id, &entry.session_id)?;
            self.validate_artifact_path(&entry, &entry.video, "video")?;
            self.validate_artifact_path(&entry, &entry.input, "input")?;
            match entry.state {
                PendingState::Pending => {
                    self.validate_seal(&entry.video, "video")?;
                    self.validate_seal(&entry.input, "input")?;
                }
                PendingState::Received => {
                    let receipt = entry.receipt.as_ref().context(
                        "received pending upload is missing its durable backend receipt",
                    )?;
                    receipt.receipt.validate(&entry, receipt)?;
                    if entry.video.exists()? {
                        self.validate_seal(&entry.video, "video")?;
                    }
                    if entry.input.exists()? {
                        self.validate_seal(&entry.input, "input")?;
                    }
                }
                PendingState::Discarding => {}
            }
        }
        Ok(())
    }

    fn validate_receipt_custody(&self) -> Result<()> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT r.receipt_id, r.session_id, r.chunk_id,
                        r.contract_version, r.trusted_endpoint,
                        r.video_key, r.video_size_bytes, r.video_sha256,
                        r.input_key, r.input_size_bytes, r.input_sha256,
                        r.expected_video_key, r.expected_input_key,
                        r.completed_at_epoch_s, p.chunk_id
                 FROM upload_receipts r
                 LEFT JOIN pending_uploads p ON p.receipt_id = r.receipt_id
                 ORDER BY r.receipt_id",
            )
            .context("failed to prepare receipt-custody query")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    ReceiptCommit {
                        receipt: UploadReceipt {
                            receipt_id: row.get(0)?,
                            session_id: row.get(1)?,
                            chunk_id: row.get(2)?,
                            contract_version: row
                                .get::<_, i64>(3)?
                                .try_into()
                                .map_err(to_sql_error)?,
                            video: ReceiptArtifact {
                                key: row.get(5)?,
                                size_bytes: from_i64(row.get(6)?)?,
                                sha256: row.get(7)?,
                            },
                            input: ReceiptArtifact {
                                key: row.get(8)?,
                                size_bytes: from_i64(row.get(9)?)?,
                                sha256: row.get(10)?,
                            },
                        },
                        trusted_endpoint: row.get(4)?,
                        expected_video_key: row.get(11)?,
                        expected_input_key: row.get(12)?,
                    },
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ))
            })
            .context("failed to query receipt custody")?;
        for row in rows {
            let (receipt, completed_at, pending_chunk) =
                row.context("failed to decode receipt-custody row")?;
            receipt.receipt.validate_record()?;
            if trusted_endpoint_identity(&receipt.trusted_endpoint)? != receipt.trusted_endpoint {
                bail!("backend receipt contains a non-canonical trusted endpoint");
            }
            validate_object_key(&receipt.expected_video_key, "expected video")?;
            validate_object_key(&receipt.expected_input_key, "expected input")?;
            if receipt.expected_video_key == receipt.expected_input_key {
                bail!("backend receipt contains duplicate expected object keys");
            }
            if receipt.receipt.video.key != receipt.expected_video_key
                || receipt.receipt.input.key != receipt.expected_input_key
            {
                bail!("backend receipt object keys do not match the presigned transaction");
            }
            match (completed_at, pending_chunk.as_deref()) {
                (None, Some(chunk_id)) if chunk_id == receipt.receipt.chunk_id => {}
                (Some(completed_at), None) if completed_at >= 0 => {}
                (None, None) => bail!(
                    "backend receipt {:?} is neither pending nor completed",
                    receipt.receipt.receipt_id
                ),
                (Some(_), Some(_)) => bail!(
                    "completed backend receipt {:?} still owns pending bytes",
                    receipt.receipt.receipt_id
                ),
                _ => bail!(
                    "backend receipt {:?} has inconsistent custody",
                    receipt.receipt.receipt_id
                ),
            }
        }
        Ok(())
    }

    fn validate_discard_custody(&self) -> Result<()> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT d.discard_id, d.chunk_id, d.session_id, d.reason,
                        d.video_size_bytes, d.video_sha256,
                        d.input_size_bytes, d.input_sha256, d.completed_at_epoch_s,
                        p.chunk_id, p.session_id, p.video_size_bytes, p.video_sha256,
                        p.input_size_bytes, p.input_sha256, p.state
                 FROM upload_discards d
                 LEFT JOIN pending_uploads p ON p.discard_id = d.discard_id
                 ORDER BY d.discard_id",
            )
            .context("failed to prepare discard-custody query")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    DiscardAudit {
                        discard_id: row.get(0)?,
                        chunk_id: row.get(1)?,
                        session_id: row.get(2)?,
                        reason: row.get(3)?,
                        video_size_bytes: from_i64(row.get(4)?)?,
                        video_sha256: row.get(5)?,
                        input_size_bytes: from_i64(row.get(6)?)?,
                        input_sha256: row.get(7)?,
                        completed_at_epoch_s: row.get(8)?,
                    },
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                ))
            })
            .context("failed to query discard custody")?;
        for row in rows {
            let (
                audit,
                pending_chunk,
                pending_session,
                pending_video_size,
                pending_video_sha,
                pending_input_size,
                pending_input_sha,
                pending_state,
            ) = row.context("failed to decode discard-custody row")?;
            validate_discard_audit(&audit)?;
            match (audit.completed_at_epoch_s, pending_chunk) {
                (None, Some(chunk_id)) => {
                    if chunk_id != audit.chunk_id
                        || pending_session.as_deref() != Some(audit.session_id.as_str())
                        || pending_video_size.map(from_i64).transpose()?
                            != Some(audit.video_size_bytes)
                        || pending_video_sha.as_deref() != Some(audit.video_sha256.as_str())
                        || pending_input_size.map(from_i64).transpose()?
                            != Some(audit.input_size_bytes)
                        || pending_input_sha.as_deref() != Some(audit.input_sha256.as_str())
                        || pending_state.as_deref() != Some("discarding")
                    {
                        bail!(
                            "upload discard {:?} does not bind its pending bytes",
                            audit.discard_id
                        );
                    }
                }
                (Some(value), None) if value >= 0 => {}
                _ => bail!(
                    "upload discard {:?} has inconsistent custody",
                    audit.discard_id
                ),
            }
        }
        Ok(())
    }

    fn validate_artifact_path(
        &self,
        entry: &PendingUploadEntry,
        artifact: &ArtifactSeal,
        role: &str,
    ) -> Result<()> {
        if !artifact.path.is_absolute() || artifact.path.parent() != Some(self.output_dir.path()) {
            bail!(
                "pending {role} artifact is outside the recording directory: {:?}",
                artifact.path
            );
        }
        let name = artifact
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .context("pending artifact filename is not UTF-8")?;
        let valid_name = if role == "input" {
            name == format!("input_{}.msgpack", entry.chunk_id)
        } else {
            name.strip_prefix(&format!("recording_{}.", entry.chunk_id))
                .is_some_and(|extension| matches!(extension, "mp4" | "mov" | "mkv" | "flv" | "ts"))
        };
        if !valid_name {
            bail!(
                "pending {role} artifact filename does not match chunk {:?}",
                entry.chunk_id
            );
        }
        Ok(())
    }

    fn complete_received_entry(&self, entry: &PendingUploadEntry) -> Result<()> {
        if entry.state != PendingState::Received {
            bail!(
                "pending upload {:?} has no durable backend receipt",
                entry.chunk_id
            );
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start upload-completion transaction")?;
        let current = load_entry(&transaction, &self.output_dir, &entry.chunk_id)?
            .with_context(|| format!("missing received upload {:?}", entry.chunk_id))?;
        if current != *entry {
            bail!(
                "received upload {:?} changed before completion",
                entry.chunk_id
            );
        }
        let receipt = entry
            .receipt
            .as_ref()
            .context("received pending upload is missing its durable backend receipt")?;
        receipt.receipt.validate(entry, receipt)?;
        if entry.video.exists()? {
            entry.video.verify("video")?;
        }
        if entry.input.exists()? {
            entry.input.verify("input")?;
        }
        entry.video.remove_if_present()?;
        entry.input.remove_if_present()?;
        let changed = transaction
            .execute(
                "UPDATE upload_receipts SET completed_at_epoch_s = unixepoch()
                 WHERE receipt_id = ?1 AND completed_at_epoch_s IS NULL",
                [receipt.receipt.receipt_id.as_str()],
            )
            .context("failed to complete immutable backend receipt")?;
        if changed != 1 {
            bail!(
                "backend receipt {:?} was already completed",
                receipt.receipt.receipt_id
            );
        }
        let changed = transaction
            .execute(
                "DELETE FROM pending_uploads
                 WHERE chunk_id = ?1 AND state = 'received' AND receipt_id = ?2",
                params![entry.chunk_id, receipt.receipt.receipt_id],
            )
            .context("failed to retire received pending upload")?;
        if changed != 1 {
            bail!(
                "received upload {:?} changed during completion",
                entry.chunk_id
            );
        }
        transaction
            .commit()
            .context("failed to commit upload completion")?;
        Ok(())
    }

    fn complete_discard_entry(&self, entry: &PendingUploadEntry) -> Result<()> {
        if entry.state != PendingState::Discarding {
            bail!(
                "pending upload {:?} has no discard confirmation",
                entry.chunk_id
            );
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .context("failed to start discard-completion transaction")?;
        let current = load_entry(&transaction, &self.output_dir, &entry.chunk_id)?
            .with_context(|| format!("missing discarded upload {:?}", entry.chunk_id))?;
        if current != *entry {
            bail!(
                "discarded upload {:?} changed before completion",
                entry.chunk_id
            );
        }
        let audit = load_discard_audit(&transaction, &entry.chunk_id)?
            .context("discarding upload is missing its immutable audit")?;
        validate_discard_for_entry(&audit, entry)?;
        if entry.video.exists()? {
            entry.video.verify("video")?;
        }
        if entry.input.exists()? {
            entry.input.verify("input")?;
        }
        entry.video.remove_if_present()?;
        entry.input.remove_if_present()?;
        let changed = transaction
            .execute(
                "UPDATE upload_discards SET completed_at_epoch_s = unixepoch()
                 WHERE discard_id = ?1 AND chunk_id = ?2 AND completed_at_epoch_s IS NULL",
                params![audit.discard_id, entry.chunk_id],
            )
            .context("failed to complete immutable discard audit")?;
        if changed != 1 {
            bail!(
                "pending upload {:?} has no incomplete discard audit",
                entry.chunk_id
            );
        }
        let changed = transaction
            .execute(
                "DELETE FROM pending_uploads WHERE chunk_id = ?1 AND state = 'discarding'",
                [entry.chunk_id.as_str()],
            )
            .context("failed to retire discarded pending upload")?;
        if changed != 1 {
            bail!(
                "discarded upload {:?} changed during completion",
                entry.chunk_id
            );
        }
        transaction
            .commit()
            .context("failed to commit discard completion")?;
        Ok(())
    }

    fn validate_seal(&self, expected: &ArtifactSeal, role: &str) -> Result<()> {
        let actual = self.seal_artifact(&expected.path, role, false)?;
        if actual != *expected {
            bail!(
                "pending {role} artifact changed after admission: {:?}",
                expected.path
            );
        }
        Ok(())
    }

    fn seal_artifact(&self, path: &Path, role: &str, synchronize: bool) -> Result<ArtifactSeal> {
        if path.parent() != Some(self.output_dir.path()) {
            bail!("pending {role} artifact is outside the recording directory: {path:?}");
        }
        let name = path
            .file_name()
            .context("pending artifact has no filename")?;
        ArtifactSeal::seal(&self.output_dir, name, role, synchronize)
    }

    fn list_all(&self) -> Result<Vec<PendingUploadEntry>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT p.chunk_id, p.session_id, p.video_path, p.video_object_id,
                        p.video_size_bytes, p.video_sha256,
                        p.input_path, p.input_object_id, p.input_size_bytes, p.input_sha256,
                        p.buffered_at_epoch_s,
                        p.state, r.receipt_id, r.session_id, r.chunk_id,
                        r.contract_version, r.trusted_endpoint,
                        r.video_key, r.video_size_bytes, r.video_sha256,
                        r.input_key, r.input_size_bytes, r.input_sha256,
                        r.expected_video_key, r.expected_input_key
                 FROM pending_uploads p
                 LEFT JOIN upload_receipts r ON r.receipt_id = p.receipt_id
                 ORDER BY p.chunk_id",
            )
            .context("failed to prepare pending-upload state query")?;
        let rows = statement
            .query_map([], |row| row_to_entry(row, &self.output_dir))
            .context("failed to query pending-upload state")?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to decode pending-upload state")
    }

    fn load(&self, chunk_id: &str) -> Result<Option<PendingUploadEntry>> {
        let connection = self.lock()?;
        load_entry(&connection, &self.output_dir, chunk_id).context("failed to load pending upload")
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("pending-upload database lock is poisoned"))
    }
}

fn validate_receipt_artifact(
    role: &str,
    receipt: &ReceiptArtifact,
    local: &ArtifactSeal,
    expected_key: &str,
) -> Result<()> {
    if receipt.key != expected_key || receipt.key.trim().is_empty() {
        bail!("backend receipt returned the wrong {role} object key");
    }
    if receipt.size_bytes != local.size_bytes || receipt.sha256 != local.sha256 {
        bail!("backend receipt returned the wrong {role} size or SHA-256");
    }
    Ok(())
}

fn load_discard_audit(connection: &Connection, chunk_id: &str) -> Result<Option<DiscardAudit>> {
    connection
        .query_row(
            "SELECT d.discard_id, d.chunk_id, d.session_id, d.reason,
                    d.video_size_bytes, d.video_sha256,
                    d.input_size_bytes, d.input_sha256, d.completed_at_epoch_s
             FROM pending_uploads p
             JOIN upload_discards d ON d.discard_id = p.discard_id
             WHERE p.chunk_id = ?1 AND p.state = 'discarding'",
            [chunk_id],
            |row| {
                Ok(DiscardAudit {
                    discard_id: row.get(0)?,
                    chunk_id: row.get(1)?,
                    session_id: row.get(2)?,
                    reason: row.get(3)?,
                    video_size_bytes: from_i64(row.get(4)?)?,
                    video_sha256: row.get(5)?,
                    input_size_bytes: from_i64(row.get(6)?)?,
                    input_sha256: row.get(7)?,
                    completed_at_epoch_s: row.get(8)?,
                })
            },
        )
        .optional()
        .context("failed to query immutable upload discard audit")
}

fn validate_discard_audit(audit: &DiscardAudit) -> Result<()> {
    validate_bounded_value(&audit.discard_id, "discard ID", MAX_ID_BYTES)?;
    validate_chunk_session(&audit.chunk_id, &audit.session_id)?;
    if audit.reason != PendingDiscard::UserPanic.as_str() {
        bail!(
            "upload discard {:?} has an unsupported confirmation reason",
            audit.discard_id
        );
    }
    validate_sha256(&audit.video_sha256, "discard video")?;
    validate_sha256(&audit.input_sha256, "discard input")?;
    Ok(())
}

fn validate_discard_for_entry(audit: &DiscardAudit, entry: &PendingUploadEntry) -> Result<()> {
    validate_discard_audit(audit)?;
    if audit.completed_at_epoch_s.is_some()
        || audit.chunk_id != entry.chunk_id
        || audit.session_id != entry.session_id
        || audit.video_size_bytes != entry.video.size_bytes
        || audit.video_sha256 != entry.video.sha256
        || audit.input_size_bytes != entry.input.size_bytes
        || audit.input_sha256 != entry.input.sha256
    {
        bail!(
            "upload discard {:?} does not bind pending chunk {:?}",
            audit.discard_id,
            entry.chunk_id
        );
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 is not lowercase hexadecimal");
    }
    Ok(())
}

fn validate_chunk_session(chunk_id: &str, session_id: &str) -> Result<()> {
    validate_bounded_value(chunk_id, "chunk ID", MAX_ID_BYTES)?;
    validate_bounded_value(session_id, "session ID", MAX_ID_BYTES)?;
    if !chunk_id
        .bytes()
        .chain(session_id.bytes())
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("chunk and session IDs contain unsupported characters");
    }
    let derived = session_id_from_chunk(chunk_id)?;
    if derived != session_id {
        bail!("chunk {chunk_id:?} does not belong to session {session_id:?}");
    }
    Ok(())
}

fn session_id_from_chunk(chunk_id: &str) -> Result<&str> {
    let (session_id, segment) = chunk_id
        .rsplit_once("_seg")
        .with_context(|| format!("invalid chunk ID {chunk_id:?}"))?;
    if session_id.is_empty()
        || segment.is_empty()
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("invalid chunk ID {chunk_id:?}");
    }
    Ok(session_id)
}

fn validate_bounded_value(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} is outside the accepted contract");
    }
    Ok(())
}

fn validate_object_key(value: &str, label: &str) -> Result<()> {
    validate_bounded_value(value, label, MAX_OBJECT_KEY_BYTES)?;
    if value.starts_with('/')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
    {
        bail!("{label} object key is not canonical");
    }
    Ok(())
}

fn insert_entry(transaction: &Transaction<'_>, entry: &PendingUploadEntry) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO pending_uploads (
                chunk_id, session_id, video_path, video_object_id, video_size_bytes, video_sha256,
                input_path, input_object_id, input_size_bytes, input_sha256, buffered_at_epoch_s,
                state, receipt_id, discard_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', NULL, NULL)",
            params![
                entry.chunk_id,
                entry.session_id,
                path_as_str(&entry.video.path)?,
                entry.video.object_id,
                to_i64(entry.video.size_bytes)?,
                entry.video.sha256,
                path_as_str(&entry.input.path)?,
                entry.input.object_id,
                to_i64(entry.input.size_bytes)?,
                entry.input.sha256,
                to_i64(entry.buffered_at_epoch_s)?,
            ],
        )
        .context("failed to insert pending upload")?;
    Ok(())
}

fn load_entry(
    connection: &Connection,
    output_dir: &PrivateDirectory,
    chunk_id: &str,
) -> Result<Option<PendingUploadEntry>> {
    connection
        .query_row(
            "SELECT p.chunk_id, p.session_id, p.video_path, p.video_object_id,
                    p.video_size_bytes, p.video_sha256,
                    p.input_path, p.input_object_id, p.input_size_bytes, p.input_sha256,
                    p.buffered_at_epoch_s,
                    p.state, r.receipt_id, r.session_id, r.chunk_id,
                    r.contract_version, r.trusted_endpoint,
                    r.video_key, r.video_size_bytes, r.video_sha256,
                    r.input_key, r.input_size_bytes, r.input_sha256,
                    r.expected_video_key, r.expected_input_key
             FROM pending_uploads p
             LEFT JOIN upload_receipts r ON r.receipt_id = p.receipt_id
             WHERE p.chunk_id = ?1",
            [chunk_id],
            |row| row_to_entry(row, output_dir),
        )
        .optional()
        .context("failed to query pending upload")
}

fn row_to_entry(
    row: &rusqlite::Row<'_>,
    output_dir: &PrivateDirectory,
) -> rusqlite::Result<PendingUploadEntry> {
    let state_text: String = row.get(11)?;
    let state = PendingState::parse(&state_text).map_err(to_sql_error)?;
    let receipt_id: Option<String> = row.get(12)?;
    let receipt = receipt_id
        .map(|receipt_id| -> rusqlite::Result<ReceiptCommit> {
            let contract_version: i64 = row.get(15)?;
            let video_key: String = row.get(17)?;
            let input_key: String = row.get(20)?;
            Ok(ReceiptCommit {
                receipt: UploadReceipt {
                    receipt_id,
                    session_id: row.get(13)?,
                    chunk_id: row.get(14)?,
                    contract_version: contract_version.try_into().map_err(to_sql_error)?,
                    video: ReceiptArtifact {
                        key: video_key.clone(),
                        size_bytes: from_i64(row.get(18)?)?,
                        sha256: row.get(19)?,
                    },
                    input: ReceiptArtifact {
                        key: input_key.clone(),
                        size_bytes: from_i64(row.get(21)?)?,
                        sha256: row.get(22)?,
                    },
                },
                trusted_endpoint: row.get(16)?,
                expected_video_key: row.get(23)?,
                expected_input_key: row.get(24)?,
            })
        })
        .transpose()?;
    Ok(PendingUploadEntry {
        chunk_id: row.get(0)?,
        session_id: row.get(1)?,
        video: ArtifactSeal::from_stored(
            output_dir,
            PathBuf::from(row.get::<_, String>(2)?),
            row.get(3)?,
            from_i64(row.get(4)?)?,
            row.get(5)?,
        )
        .map_err(to_sql_anyhow_error)?,
        input: ArtifactSeal::from_stored(
            output_dir,
            PathBuf::from(row.get::<_, String>(6)?),
            row.get(7)?,
            from_i64(row.get(8)?)?,
            row.get(9)?,
        )
        .map_err(to_sql_anyhow_error)?,
        buffered_at_epoch_s: from_i64(row.get(10)?)?,
        state,
        receipt,
    })
}

fn receipt_exists_for_chunk(connection: &Connection, chunk_id: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM upload_receipts WHERE chunk_id = ?1)",
            [chunk_id],
            |row| row.get(0),
        )
        .context("failed to query completed upload custody")
}

fn to_sql_error(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn to_sql_anyhow_error(error: anyhow::Error) -> rusqlite::Error {
    to_sql_error(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{error:#}"),
    ))
}

fn to_i64(value: u64) -> Result<i64> {
    value
        .try_into()
        .context("pending-upload integer exceeds SQLite range")
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    value.try_into().map_err(to_sql_error)
}

fn path_as_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("pending-upload path is not UTF-8: {path:?}"))
}

include!("pending_state_tests.rs");
