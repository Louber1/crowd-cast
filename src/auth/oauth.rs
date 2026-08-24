//! Google OAuth PKCE flow for desktop apps.
//!
//! Flow: open browser → Google consent → redirect to localhost → exchange code
//! for tokens. Tokens are refreshed transparently before expiry.

use super::credential_store::{self, CredentialStore};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub google_sub: String,
    pub email: String,
    pub name: String,
    pub id_token: String,
    pub refresh_token: String,
    /// ISO 8601 timestamp when the ID token expires.
    pub token_expiry: String,
}

impl AuthState {
    fn validate(&self) -> Result<()> {
        if self.google_sub.is_empty()
            || self.email.is_empty()
            || self.id_token.is_empty()
            || self.refresh_token.is_empty()
        {
            anyhow::bail!("Google OAuth credential is incomplete");
        }
        chrono::DateTime::parse_from_rfc3339(&self.token_expiry)
            .context("Google OAuth credential has an invalid expiry")?;
        Ok(())
    }
}

/// Manages authentication state: login, token refresh, persistence.
pub struct AuthManager {
    state: Option<AuthState>,
    client_id: String,
    store: Box<dyn CredentialStore>,
}

pub fn purge_legacy_plaintext() -> Result<()> {
    AuthManager::remove_legacy_plaintext(&AuthManager::legacy_auth_path()?)
}

impl AuthManager {
    pub fn new(client_id: &str) -> Result<Self> {
        purge_legacy_plaintext()?;
        Self::load(client_id, credential_store::system()?)
    }

    fn with_store(
        client_id: &str,
        store: Box<dyn CredentialStore>,
        legacy_path: &Path,
    ) -> Result<Self> {
        Self::remove_legacy_plaintext(legacy_path)?;
        Self::load(client_id, store)
    }

    fn load(client_id: &str, store: Box<dyn CredentialStore>) -> Result<Self> {
        let state = store
            .load()?
            .map(|secret| {
                let state: AuthState = serde_json::from_slice(&secret)
                    .context("failed to parse Google OAuth state from credential service")?;
                state.validate()?;
                Ok::<AuthState, anyhow::Error>(state)
            })
            .transpose()?;

        if let Some(ref s) = state {
            info!("Loaded auth state for {}", s.email);
        }

        Ok(Self {
            state,
            client_id: client_id.to_string(),
            store,
        })
    }

    fn legacy_auth_path() -> Result<PathBuf> {
        directories::ProjectDirs::from("dev", "crowd-cast", "agent")
            .map(|p| p.data_dir().join("auth.json"))
            .context("could not determine legacy auth file path")
    }

    fn remove_legacy_plaintext(path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                std::fs::remove_file(path).with_context(|| {
                    format!("failed to remove legacy plaintext auth state at {path:?}")
                })?;
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => anyhow::bail!("legacy plaintext auth state still exists at {path:?}"),
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to verify removal of legacy auth state at {path:?}")
                        });
                    }
                }
                warn!("Removed legacy plaintext auth state");
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to inspect legacy auth state at {path:?}")),
        }
    }

    /// Whether the user is authenticated (has a refresh token).
    pub fn is_authenticated(&self) -> bool {
        self.state.is_some()
    }

    /// Get the user's email for display.
    pub fn email(&self) -> Option<&str> {
        self.state.as_ref().map(|s| s.email.as_str())
    }

    /// Get a valid ID token, refreshing if necessary.
    /// Returns None if not authenticated or refresh fails.
    pub async fn get_valid_token(&mut self) -> Option<String> {
        let state = self.state.as_ref()?;

        // Check if token expires within 5 minutes
        let expiry = chrono::DateTime::parse_from_rfc3339(&state.token_expiry).ok()?;
        let now = chrono::Utc::now();
        let buffer = chrono::Duration::minutes(5);

        if expiry > now + buffer {
            return Some(state.id_token.clone());
        }

        // Token expired or expiring soon — refresh
        info!("ID token expiring soon, refreshing...");
        match self.refresh_token().await {
            Ok(()) => self.state.as_ref().map(|s| s.id_token.clone()),
            Err(e) => {
                warn!("Token refresh failed: {}", e);
                None
            }
        }
    }

    /// Run the full OAuth PKCE login flow.
    /// Opens the browser, waits for the callback, exchanges the code for tokens.
    pub async fn login(&mut self) -> Result<AuthState> {
        info!("Starting Google OAuth login flow...");

        // Generate PKCE code verifier + challenge
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);
        let oauth_state = generate_code_verifier();

        // Bind a localhost listener on a random port
        let listener = TcpListener::bind("127.0.0.1:0")
            .context("Failed to bind localhost listener for OAuth callback")?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{}", port);

        // Build the Google authorization URL
        let auth_url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?\
             client_id={}&\
             redirect_uri={}&\
             response_type=code&\
             scope=openid%20email%20profile&\
             code_challenge={}&\
             code_challenge_method=S256&\
             state={}&\
             access_type=offline&\
             prompt=consent",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&code_challenge),
            urlencoding::encode(&oauth_state),
        );

        // Open browser
        info!("Opening browser for Google sign-in...");
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open").arg(&auth_url).spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open")
                .arg(&auth_url)
                .spawn();
        }
        #[cfg(target_os = "windows")]
        {
            // NOTE: do NOT use `cmd /C start <url>` — cmd treats `&` as a command
            // separator and truncates the OAuth URL at the first query param, so
            // Google sees a request missing `response_type` etc. rundll32 takes
            // the full URL as a single argument with no shell parsing.
            let _ = std::process::Command::new("rundll32")
                .args(["url.dll,FileProtocolHandler", &auth_url])
                .spawn();
        }

        // Wait for the callback (blocking)
        info!("Waiting for OAuth callback on port {}...", port);
        let auth_code = Self::wait_for_callback(listener, &oauth_state)?;

        // Exchange authorization code for tokens
        info!("Exchanging authorization code for tokens...");
        let token_response =
            Self::exchange_code(&self.client_id, &auth_code, &redirect_uri, &code_verifier).await?;

        // Parse ID token to extract claims
        let claims = decode_id_token_claims(&token_response.id_token)?;

        let expiry =
            chrono::Utc::now() + chrono::Duration::seconds(token_response.expires_in as i64);

        let refresh_token = token_response
            .refresh_token
            .filter(|token| !token.is_empty())
            .or_else(|| self.state.as_ref().map(|state| state.refresh_token.clone()))
            .context("Google token response did not include a refresh token")?;
        let auth_state = AuthState {
            google_sub: claims.sub,
            email: claims.email.clone(),
            name: claims.name,
            id_token: token_response.id_token,
            refresh_token,
            token_expiry: expiry.to_rfc3339(),
        };

        // Persist
        self.save(&auth_state)?;
        self.state = Some(auth_state.clone());

        info!("Logged in as {}", claims.email);
        Ok(auth_state)
    }

    /// Refresh the ID token using the stored refresh token.
    async fn refresh_token(&mut self) -> Result<()> {
        let state = self.state.as_ref().context("Not authenticated")?;

        let client = reqwest::Client::new();
        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&refresh_form(&state.refresh_token, &self.client_id))
            .send()
            .await
            .context("Token refresh request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Token refresh failed: HTTP {} — {}",
                status,
                &body[..body.len().min(200)]
            );
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("Failed to parse refresh response")?;

        let expiry = chrono::Utc::now() + chrono::Duration::seconds(token_resp.expires_in as i64);

        let mut new_state = state.clone();
        new_state.id_token = token_resp.id_token;
        new_state.token_expiry = expiry.to_rfc3339();
        if let Some(rt) = token_resp.refresh_token.filter(|token| !token.is_empty()) {
            new_state.refresh_token = rt;
        }

        self.save(&new_state)?;
        self.state = Some(new_state);

        debug!("Token refreshed successfully");
        Ok(())
    }

    pub fn logout(&mut self) -> Result<()> {
        self.store.delete()?;
        self.state = None;
        info!("Logged out");
        Ok(())
    }

    fn save(&self, state: &AuthState) -> Result<()> {
        state.validate()?;
        self.store.save(&serde_json::to_vec(state)?)
    }

    /// Wait for the OAuth callback on the localhost listener.
    /// Returns the authorization code from the query string.
    fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
        // Set a timeout so we don't block forever
        listener.set_nonblocking(false)?;

        let (mut stream, _) = listener
            .accept()
            .context("Failed to accept OAuth callback connection")?;

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse the GET request to extract the code parameter
        let first_line = request.lines().next().unwrap_or("");
        let path = first_line.split_whitespace().nth(1).unwrap_or("");

        let code = parse_callback(path, expected_state)?;

        // Send a success page to the browser: a black-and-white confirmation card
        // matching pdoom.org's styling, with opt-in links onward (dashboard, docs)
        // rather than a redirect. Must be fully self-contained (inline CSS, no
        // external assets): it is served once over this throwaway localhost socket.
        let html = r##"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>crowd-cast &mdash; signed in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #fff; --fg: #000; --muted: #999;
    --accent: #000; --accent-fg: #fff; --border: #eee;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #000; --fg: #fff; --muted: #999;
      --accent: #fff; --accent-fg: #000; --border: #333;
    }
  }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center; min-height: 100vh;
  }
  .card {
    border: 1px solid var(--border); border-radius: 12px;
    padding: 44px 48px; max-width: 380px; text-align: center;
  }
  .check {
    width: 52px; height: 52px; border-radius: 50%; background: var(--accent);
    color: var(--accent-fg); font-size: 28px; line-height: 52px; margin: 0 auto 20px;
  }
  .name { font-family: 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace; }
  h1 { font-size: 20px; margin: 0 0 8px; font-weight: 600; }
  p  { font-size: 14px; color: var(--muted); margin: 0 0 26px; line-height: 1.5; }
  .btn {
    display: block; background: var(--accent); color: var(--accent-fg);
    text-decoration: none; font-size: 14px; font-weight: 600;
    padding: 12px 0; border-radius: 8px; margin-bottom: 14px;
  }
  .links { font-size: 13px; }
  .links a { color: var(--muted); text-decoration: none; border-bottom: 1px solid var(--border); }
  .close { font-size: 12px; color: var(--muted); margin-top: 22px; margin-bottom: 0; }
</style>
</head>
<body>
  <div class="card">
    <div class="check">&#10003;</div>
    <h1>Signed in to <span class="name">crowd-cast</span></h1>
    <p>Your contributions are now linked to you.</p>
    <a class="btn" href="https://pdoom.org/crowd_cast_dashboard.html">View contributions</a>
    <div class="links"><a href="https://pdoom.org/docs/crowd-cast/">Read the docs</a></div>
    <p class="close">You can close this tab and return to crowd-cast.</p>
  </div>
</body>
</html>"##;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();

        Ok(code)
    }

    /// Exchange the authorization code for tokens.
    async fn exchange_code(
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&authorization_code_form(
                client_id,
                code,
                redirect_uri,
                code_verifier,
            ))
            .send()
            .await
            .context("Token exchange request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Token exchange failed: HTTP {} — {}",
                status,
                &body[..body.len().min(500)]
            );
        }

        resp.json::<TokenResponse>()
            .await
            .context("Failed to parse token exchange response")
    }
}

// ---------------------------------------------------------------------------
// Token exchange response
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
}

// ---------------------------------------------------------------------------
// JWT claims (decoded without verification — Lambda verifies)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    email: String,
    #[serde(default)]
    name: String,
}

fn decode_id_token_claims(id_token: &str) -> Result<IdTokenClaims> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid ID token format");
    }

    // Decode the payload (second part), base64url
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("Failed to base64-decode ID token payload")?;

    serde_json::from_slice::<IdTokenClaims>(&payload_bytes)
        .context("Failed to parse ID token claims")
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

fn generate_code_verifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

fn authorization_code_form<'a>(
    client_id: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    code_verifier: &'a str,
) -> [(&'static str, &'a str); 5] {
    [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ]
}

fn refresh_form<'a>(refresh_token: &'a str, client_id: &'a str) -> [(&'static str, &'a str); 3] {
    [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ]
}

// ---------------------------------------------------------------------------
// URL query parsing
// ---------------------------------------------------------------------------

fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            if key == param {
                return urlencoding::decode(value)
                    .ok()
                    .map(|value| value.into_owned());
            }
        }
    }
    None
}

fn parse_callback(path: &str, expected_state: &str) -> Result<String> {
    let state = extract_query_param(path, "state").context("OAuth callback omitted state")?;
    if state != expected_state {
        anyhow::bail!("OAuth callback state did not match this login attempt");
    }
    if let Some(error) = extract_query_param(path, "error") {
        anyhow::bail!("Google OAuth authorization failed: {error}");
    }
    extract_query_param(path, "code").context("OAuth callback omitted authorization code")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestStore {
        secret: Arc<Mutex<Option<Vec<u8>>>>,
        fail_delete: bool,
    }

    impl CredentialStore for TestStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.secret.lock().unwrap().clone())
        }

        fn save(&self, secret: &[u8]) -> Result<()> {
            *self.secret.lock().unwrap() = Some(secret.to_vec());
            Ok(())
        }

        fn delete(&self) -> Result<()> {
            if self.fail_delete {
                anyhow::bail!("delete denied");
            }
            *self.secret.lock().unwrap() = None;
            Ok(())
        }
    }

    fn test_store(secret: Arc<Mutex<Option<Vec<u8>>>>) -> Box<dyn CredentialStore> {
        Box::new(TestStore {
            secret,
            fail_delete: false,
        })
    }

    fn sample_state() -> AuthState {
        AuthState {
            google_sub: "subject".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            id_token: "header.payload.signature".to_string(),
            refresh_token: "refresh".to_string(),
            token_expiry: "2030-01-01T00:00:00Z".to_string(),
        }
    }

    fn temp_auth_path() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("crowd-cast-auth-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        root.join("auth.json")
    }

    #[test]
    fn test_pkce_challenge() {
        let verifier = "test_verifier_string_here";
        let challenge = generate_code_challenge(verifier);
        // Should be a base64url string, no padding
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.is_empty());
    }

    #[test]
    fn test_extract_query_param() {
        assert_eq!(
            extract_query_param("/?code=abc123&state=xyz", "code"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_query_param("/?code=abc123&state=xyz", "state"),
            Some("xyz".to_string())
        );
        assert_eq!(extract_query_param("/?code=abc123", "missing"), None);
        assert_eq!(extract_query_param("/noquery", "code"), None);
    }

    #[test]
    fn callback_requires_the_login_attempt_state() {
        assert_eq!(
            parse_callback("/?code=abc123&state=expected", "expected").unwrap(),
            "abc123"
        );
        assert!(parse_callback("/?code=abc123&state=other", "expected").is_err());
        assert!(parse_callback("/?code=abc123", "expected").is_err());
        assert!(parse_callback("/?error=access_denied&state=expected", "expected").is_err());
    }

    #[test]
    fn token_requests_are_public_client_requests() {
        let exchange = authorization_code_form("client", "code", "redirect", "verifier");
        assert_eq!(
            exchange.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            [
                "grant_type",
                "code",
                "redirect_uri",
                "client_id",
                "code_verifier"
            ]
        );
        let refresh = refresh_form("refresh", "client");
        assert_eq!(
            refresh.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            ["grant_type", "refresh_token", "client_id"]
        );
    }

    #[test]
    fn protected_store_round_trip_has_no_plaintext_file() {
        let path = temp_auth_path();
        let secret = Arc::new(Mutex::new(None));
        let mut manager =
            AuthManager::with_store("client", test_store(secret.clone()), &path).unwrap();
        let state = sample_state();
        manager.save(&state).unwrap();
        manager.state = Some(state);
        drop(manager);

        let mut reloaded = AuthManager::with_store("client", test_store(secret), &path).unwrap();
        assert_eq!(reloaded.email(), Some("test@example.com"));
        reloaded.logout().unwrap();
        assert!(!reloaded.is_authenticated());
        assert!(!path.exists());
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn legacy_plaintext_is_removed_before_auth_loads() {
        let path = temp_auth_path();
        std::fs::write(&path, b"plaintext bearer tokens").unwrap();
        let manager =
            AuthManager::with_store("client", test_store(Arc::new(Mutex::new(None))), &path)
                .unwrap();
        assert!(!manager.is_authenticated());
        assert!(!path.exists());
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn legacy_plaintext_removal_failure_is_fatal() {
        let path = temp_auth_path();
        std::fs::create_dir(&path).unwrap();
        let result =
            AuthManager::with_store("client", test_store(Arc::new(Mutex::new(None))), &path);
        assert!(result.is_err());
        std::fs::remove_dir(&path).unwrap();
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn malformed_protected_state_is_fatal() {
        let path = temp_auth_path();
        let result = AuthManager::with_store(
            "client",
            test_store(Arc::new(Mutex::new(Some(b"not json".to_vec())))),
            &path,
        );
        assert!(result.is_err());
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn failed_credential_deletion_keeps_authenticated_state() {
        let path = temp_auth_path();
        let state = sample_state();
        let secret = Arc::new(Mutex::new(Some(serde_json::to_vec(&state).unwrap())));
        let mut manager = AuthManager::with_store(
            "client",
            Box::new(TestStore {
                secret,
                fail_delete: true,
            }),
            &path,
        )
        .unwrap();
        assert!(manager.logout().is_err());
        assert!(manager.is_authenticated());
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn test_decode_id_token_claims() {
        // Build a fake JWT with a known payload
        use base64::Engine;
        let payload = r#"{"sub":"12345","email":"test@example.com","name":"Test User"}"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let fake_jwt = format!("header.{}.signature", encoded);

        let claims = decode_id_token_claims(&fake_jwt).unwrap();
        assert_eq!(claims.sub, "12345");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.name, "Test User");
    }
}
