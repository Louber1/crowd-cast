//! Google OAuth authentication for crowd-cast.
//!
//! Provides optional Google Sign-In via the PKCE OAuth flow.
//! Tokens are stored by the operating-system credential service and
//! sent as Bearer tokens with presign requests.

mod credential_store;
mod oauth;

pub use oauth::{purge_legacy_plaintext, AuthManager};
