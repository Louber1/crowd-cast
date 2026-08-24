//! S3 upload via pre-signed URLs

mod log_shipper;
mod pending;
mod pending_artifact;
mod pending_security;
mod presigned;
mod receipt_endpoint;

pub use log_shipper::LogShipper;
pub(crate) use pending::{
    PendingDiscard, PendingUploadEntry, PendingUploadStore, ReceiptArtifact, ReceiptCommit,
    UploadReceipt, UPLOAD_RECEIPT_CONTRACT_VERSION,
};
pub(crate) use pending_artifact::ArtifactSeal;
pub use presigned::*;
