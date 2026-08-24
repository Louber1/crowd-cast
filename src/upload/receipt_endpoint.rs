use anyhow::{bail, Context, Result};
use url::Url;

const MAX_URL_BYTES: usize = 8192;

pub(crate) fn require_https(value: &str, label: &str) -> Result<Url> {
    let url = parse_https(value, label)?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("{label} contains forbidden credentials or fragment");
    }
    Ok(url)
}

pub(crate) fn trusted_endpoint_identity(endpoint: &str) -> Result<String> {
    let endpoint = strict_transaction_url(endpoint, "configured chunk endpoint")?;
    let segments: Vec<_> = endpoint
        .path_segments()
        .context("configured chunk endpoint has no hierarchical path")?
        .collect();
    if segments.is_empty() || segments.last() == Some(&"") {
        bail!("configured chunk endpoint must identify one exact operation path");
    }
    Ok(endpoint.to_string())
}

pub(crate) fn trusted_receipt_url(endpoint: &str, receipt_url: &str) -> Result<Url> {
    let endpoint = strict_transaction_url(endpoint, "configured chunk endpoint")?;
    let receipt = strict_transaction_url(receipt_url, "backend receipt URL")?;
    if endpoint.origin() != receipt.origin() {
        bail!("backend receipt URL is outside the trusted chunk endpoint authority");
    }
    let endpoint_segments: Vec<_> = endpoint
        .path_segments()
        .context("configured chunk endpoint has no hierarchical path")?
        .collect();
    let receipt_segments: Vec<_> = receipt
        .path_segments()
        .context("backend receipt URL has no hierarchical path")?
        .collect();
    let trusted_stage = endpoint_segments
        .get(..endpoint_segments.len().saturating_sub(1))
        .context("configured chunk endpoint has no operation path")?;
    if receipt_segments.len() <= trusted_stage.len()
        || receipt_segments.get(..trusted_stage.len()) != Some(trusted_stage)
    {
        bail!("backend receipt URL is outside the trusted endpoint stage");
    }
    Ok(receipt)
}

fn strict_transaction_url(value: &str, label: &str) -> Result<Url> {
    let url = require_https(value, label)?;
    if url.query().is_some() || url.path().contains('%') || url.as_str() != value {
        bail!("{label} is not an exact canonical transaction URL");
    }
    Ok(url)
}

fn parse_https(value: &str, label: &str) -> Result<Url> {
    if value.is_empty() || value.len() > MAX_URL_BYTES {
        bail!("{label} length is outside the accepted contract");
    }
    let url = Url::parse(value).with_context(|| format!("invalid {label}"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        bail!("{label} must use HTTPS with an explicit authority");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_urls_require_bounded_https_without_credentials() {
        assert!(
            require_https("https://uploads.example/object?signature=abc", "upload URL").is_ok()
        );
        assert!(require_https("http://uploads.example/object", "upload URL").is_err());
        assert!(require_https("https://user@uploads.example/object", "upload URL").is_err());
        assert!(require_https("not a URL", "upload URL").is_err());
        assert!(require_https(
            &format!("https://example/{}", "a".repeat(MAX_URL_BYTES)),
            "upload URL"
        )
        .is_err());
    }

    #[test]
    fn receipt_url_cannot_exfiltrate_bearer_token() {
        let endpoint = "https://api.example.invalid/prod/presign";

        assert!(trusted_receipt_url(endpoint, "https://api.example.invalid/prod/receipt").is_ok());
        assert!(trusted_receipt_url(endpoint, "https://attacker.invalid/prod/receipt").is_err());
        assert!(
            trusted_receipt_url(endpoint, "https://api.example.invalid/prod-evil/receipt").is_err()
        );
        assert!(
            trusted_receipt_url(endpoint, "https://user@api.example.invalid/prod/receipt").is_err()
        );
        assert!(trusted_receipt_url(
            endpoint,
            "https://api.example.invalid/prod/receipt?redirect=1"
        )
        .is_err());
    }

    #[test]
    fn endpoint_identity_rejects_ambiguous_forms() {
        assert_eq!(
            trusted_endpoint_identity("https://api.example.invalid/prod/presign").unwrap(),
            "https://api.example.invalid/prod/presign"
        );
        assert!(trusted_endpoint_identity("https://api.example.invalid/prod/presign?x=1").is_err());
        assert!(trusted_endpoint_identity("https://api.example.invalid/prod/../presign").is_err());
        assert!(
            trusted_endpoint_identity("https://api.example.invalid/prod/%2e%2e/presign").is_err()
        );
        assert!(trusted_endpoint_identity("https://api.example.invalid/prod%2fpresign").is_err());
        assert!(trusted_endpoint_identity("https://api.example.invalid/prod/").is_err());
    }
}
