//! The password a client has to present, and when it stops being valid.
//!
//! This is the equivalent of QEMU's `VncAuthPassword` and
//! `vnc_display_pw_expire()`: the password is set over D-Bus, can be set to
//! expire at a given time, and the authentication degrades to `None` once it
//! has expired. It is *not* where the RFB handshake is — [`crate::rfb`]
//! holds the scheme, this holds the secret and its lifetime.

use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use qemu_display::{Error, Result};

use crate::rfb::Password;

/// The password, and when it stops being valid.
///
/// This is the equivalent of QEMU's `VncAuthPassword` and
/// `vnc_display_pw_expire()`: the password is set over D-Bus, can be set to
/// expire at a given time, and the authentication degrades to `None` once it
/// has expired.
#[derive(Debug, Default)]
pub struct PasswordStore {
    password: Mutex<Option<(Password, Option<SystemTime>)>>,
}

impl PasswordStore {
    /// An empty store: the clients do not have to authenticate.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current authentication requirement, dropping an expired password.
    fn current(&self) -> Option<Password> {
        let mut password = self.password.lock().unwrap();
        let (value, expiry) = password.as_ref()?;
        if let Some(expiry) = expiry
            && SystemTime::now() >= *expiry
        {
            *password = None;
            return None;
        }
        Some(value.clone())
    }

    /// The password, if the clients have to authenticate.
    pub fn password(&self) -> Option<Password> {
        self.current().filter(Password::is_required)
    }

    /// The name of the authentication method, as reported by the
    /// `org.qemu.Vnc1.Server.Auth` property.
    pub fn auth_method(&self) -> &'static str {
        self.password().map_or("none", |p| p.auth_method())
    }

    /// Set a new password, replacing the previous one. Existing clients are
    /// not affected, as in QEMU.
    pub fn set(&self, password: &str) {
        *self.password.lock().unwrap() = Some((Password::new(password), None));
    }

    /// Set when the password expires.
    ///
    /// `None` means the password never expires.
    pub fn set_expiry(&self, expiry: Option<SystemTime>) {
        let mut password = self.password.lock().unwrap();
        match password.as_mut() {
            Some((_, current)) => *current = expiry,
            // Expiring a password we do not have yet must not invent one.
            None => {
                if expiry.is_some() {
                    *password = Some((Password::none(), expiry));
                }
            }
        }
    }

    /// Load the password from a systemd credentials directory, as
    /// `setup_credentials()` does with `CREDENTIALS_DIRECTORY/vnc-password`.
    pub fn from_credentials_dir(dir: &Path) -> Result<Self> {
        let path = dir.join("vnc-password");
        let store = Self::new();
        if path.exists() {
            let password = std::fs::read_to_string(&path)
                .map_err(|e| Error::Failed(format!("Failed to read {}: {e}", path.display())))?;
            store.set(password.trim_end_matches('\n'));
        }
        Ok(store)
    }

    /// Load the password from the `CREDENTIALS_DIRECTORY` of the
    /// environment, if it is set.
    pub fn from_environment() -> Result<Self> {
        match std::env::var_os("CREDENTIALS_DIRECTORY") {
            Some(dir) => Self::from_credentials_dir(Path::new(&dir)),
            None => Ok(Self::new()),
        }
    }
}
