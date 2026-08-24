use anyhow::Result;

const SERVICE: &str = "dev.crowd-cast.agent";
const ACCOUNT: &str = "google-oauth";

pub(super) trait CredentialStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, secret: &[u8]) -> Result<()>;
    fn delete(&self) -> Result<()>;
}

pub(super) fn system() -> Result<Box<dyn CredentialStore>> {
    platform::system()
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{CredentialStore, ACCOUNT, SERVICE};
    use anyhow::{Context, Result};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    struct MacOsCredentialStore;

    impl CredentialStore for MacOsCredentialStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            match get_generic_password(SERVICE, ACCOUNT) {
                Ok(secret) => Ok(Some(secret)),
                Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                Err(error) => Err(error).context("failed to read Google OAuth state from Keychain"),
            }
        }

        fn save(&self, secret: &[u8]) -> Result<()> {
            set_generic_password(SERVICE, ACCOUNT, secret)
                .context("failed to save Google OAuth state to Keychain")
        }

        fn delete(&self) -> Result<()> {
            match delete_generic_password(SERVICE, ACCOUNT) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                Err(error) => {
                    Err(error).context("failed to delete Google OAuth state from Keychain")
                }
            }
        }
    }

    pub(super) fn system() -> Result<Box<dyn CredentialStore>> {
        Ok(Box::new(MacOsCredentialStore))
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{CredentialStore, ACCOUNT, SERVICE};
    use anyhow::{Context, Result};
    use std::ffi::c_void;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };

    const MAX_CREDENTIAL_BYTES: usize = 2560;

    struct WindowsCredentialStore;

    fn target_name() -> Vec<u16> {
        format!("{SERVICE}/{ACCOUNT}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    impl CredentialStore for WindowsCredentialStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            let target = target_name();
            let mut raw = std::ptr::null_mut();
            let read =
                unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0, &mut raw) };
            if let Err(error) = read {
                if error.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(None);
                }
                return Err(error)
                    .context("failed to read Google OAuth state from Credential Manager");
            }
            if raw.is_null() {
                anyhow::bail!("Credential Manager returned a null Google OAuth credential");
            }

            let credential = unsafe { &*raw };
            if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
                unsafe { CredFree(raw.cast::<c_void>()) };
                anyhow::bail!("Credential Manager returned an empty Google OAuth credential");
            }
            let secret = unsafe {
                std::slice::from_raw_parts(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
                .to_vec()
            };
            unsafe { CredFree(raw.cast::<c_void>()) };
            Ok(Some(secret))
        }

        fn save(&self, secret: &[u8]) -> Result<()> {
            if secret.len() > MAX_CREDENTIAL_BYTES {
                anyhow::bail!(
                    "Google OAuth state is {} bytes; Credential Manager limit is {} bytes",
                    secret.len(),
                    MAX_CREDENTIAL_BYTES
                );
            }
            let mut target = target_name();
            let mut blob = secret.to_vec();
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: PWSTR(target.as_mut_ptr()),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                ..Default::default()
            };
            unsafe { CredWriteW(&credential, 0) }
                .context("failed to save Google OAuth state to Credential Manager")
        }

        fn delete(&self) -> Result<()> {
            let target = target_name();
            match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) } {
                Ok(()) => Ok(()),
                Err(error) if error.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
                Err(error) => Err(error)
                    .context("failed to delete Google OAuth state from Credential Manager"),
            }
        }
    }

    pub(super) fn system() -> Result<Box<dyn CredentialStore>> {
        Ok(Box::new(WindowsCredentialStore))
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{CredentialStore, ACCOUNT, SERVICE};
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    const DESTINATION: &str = "org.freedesktop.secrets";
    const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
    const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
    const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";

    struct LinuxCredentialStore;

    fn attributes() -> HashMap<String, String> {
        HashMap::from([
            ("service".to_string(), SERVICE.to_string()),
            ("account".to_string(), ACCOUNT.to_string()),
        ])
    }

    fn service<'a>(
        connection: &'a zbus::blocking::Connection,
    ) -> Result<zbus::blocking::Proxy<'a>> {
        zbus::blocking::Proxy::new(connection, DESTINATION, SERVICE_PATH, SERVICE_INTERFACE)
            .context("failed to connect to Secret Service")
    }

    fn open_session(service: &zbus::blocking::Proxy<'_>) -> Result<OwnedObjectPath> {
        let (_, path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .context("failed to open Secret Service session")?;
        Ok(path)
    }

    fn find_item(service: &zbus::blocking::Proxy<'_>) -> Result<Option<OwnedObjectPath>> {
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attributes(),))
            .context("failed to search Secret Service")?;
        if !locked.is_empty() {
            anyhow::bail!("Google OAuth credential is locked in Secret Service");
        }
        match unlocked.len() {
            0 => Ok(None),
            1 => Ok(unlocked.into_iter().next()),
            count => anyhow::bail!("Secret Service returned {count} Google OAuth credentials"),
        }
    }

    impl CredentialStore for LinuxCredentialStore {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            let connection = zbus::blocking::Connection::session()
                .context("failed to connect to the desktop Secret Service")?;
            let service = service(&connection)?;
            let Some(item_path) = find_item(&service)? else {
                return Ok(None);
            };
            let session = open_session(&service)?;
            let item =
                zbus::blocking::Proxy::new(&connection, DESTINATION, item_path, ITEM_INTERFACE)
                    .context("failed to open Google OAuth credential")?;
            let (_, _, secret, content_type): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = item
                .call("GetSecret", &(session,))
                .context("failed to read Google OAuth credential")?;
            if content_type != "application/json" {
                anyhow::bail!(
                    "Google OAuth credential has unexpected content type {content_type:?}"
                );
            }
            Ok(Some(secret))
        }

        fn save(&self, secret: &[u8]) -> Result<()> {
            let connection = zbus::blocking::Connection::session()
                .context("failed to connect to the desktop Secret Service")?;
            let service = service(&connection)?;
            let _ = find_item(&service)?;
            let session = open_session(&service)?;
            let collection_path: OwnedObjectPath = service
                .call("ReadAlias", &("default",))
                .context("failed to find the default Secret Service collection")?;
            if collection_path.as_str() == "/" {
                anyhow::bail!("Secret Service has no default collection");
            }

            let collection = zbus::blocking::Proxy::new(
                &connection,
                DESTINATION,
                collection_path,
                COLLECTION_INTERFACE,
            )
            .context("failed to open the default Secret Service collection")?;
            let mut properties = HashMap::new();
            properties.insert(
                "org.freedesktop.Secret.Item.Label",
                Value::from("crowd-cast Google OAuth"),
            );
            properties.insert(
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(attributes()),
            );
            let secret = (
                session,
                Vec::<u8>::new(),
                secret.to_vec(),
                "application/json".to_string(),
            );
            let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                .call("CreateItem", &(properties, secret, true))
                .context("failed to save Google OAuth credential")?;
            if prompt.as_str() != "/" {
                anyhow::bail!("Secret Service requires an unlock prompt");
            }
            Ok(())
        }

        fn delete(&self) -> Result<()> {
            let connection = zbus::blocking::Connection::session()
                .context("failed to connect to the desktop Secret Service")?;
            let service = service(&connection)?;
            let Some(item_path) = find_item(&service)? else {
                return Ok(());
            };
            let item =
                zbus::blocking::Proxy::new(&connection, DESTINATION, item_path, ITEM_INTERFACE)
                    .context("failed to open Google OAuth credential")?;
            let prompt: OwnedObjectPath = item
                .call("Delete", &())
                .context("failed to delete Google OAuth credential")?;
            if prompt.as_str() != "/" {
                anyhow::bail!("Secret Service requires an unlock prompt");
            }
            Ok(())
        }
    }

    pub(super) fn system() -> Result<Box<dyn CredentialStore>> {
        Ok(Box::new(LinuxCredentialStore))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use zbus::zvariant::Type;

        #[test]
        fn secret_service_wire_shapes_match_the_protocol() {
            type Attributes = HashMap<String, String>;
            type Properties = HashMap<&'static str, Value<'static>>;
            type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

            assert_eq!(<(&str, Value<'static>)>::SIGNATURE.to_string(), "(sv)");
            assert_eq!(<(Attributes,)>::SIGNATURE.to_string(), "(a{ss})");
            assert_eq!(<Secret>::SIGNATURE.to_string(), "(oayays)");
            assert_eq!(
                <(Properties, Secret, bool)>::SIGNATURE.to_string(),
                "(a{sv}(oayays)b)"
            );
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::CredentialStore;
    use anyhow::Result;

    pub(super) fn system() -> Result<Box<dyn CredentialStore>> {
        anyhow::bail!("OAuth credential storage is unsupported on this platform")
    }
}
