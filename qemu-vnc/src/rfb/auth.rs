//! The VNC password authentication (RFB security type 2).
//!
//! This is the scheme QEMU calls `VncAuthPassword`: the server sends 16 random
//! bytes, and the client sends them back DES-encrypted with a key derived from
//! the password. It is not a good authentication scheme — the challenge is
//! not bound to the session and DES is weak — but every VNC client
//! understands it, and QEMU implements it for the same reason.

use super::des;
use super::{Error, Result, SecurityType};

/// The maximum length of a VNC password: DES is 56-bit, and the RFB scheme
/// reverses the bits of every octet, so the password is truncated to 8
/// characters.
pub const PASSWORD_LEN: usize = 8;

/// A VNC password, as the DES key of the authentication scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VncPassword {
    key: [u8; 8],
}

impl VncPassword {
    /// Derive the key of a password, truncating it to 8 characters, as DES
    /// is 56-bit.
    pub fn new(password: &str) -> Self {
        let mut key = [0u8; 8];
        for (dst, src) in key
            .iter_mut()
            .zip(password.as_bytes().iter().take(PASSWORD_LEN))
        {
            // DES drops the least significant bit of every octet, and the RFB
            // scheme works around that by reversing the bits of each octet.
            *dst = src.reverse_bits();
        }
        Self { key }
    }

    /// The DES encryption of a 16 bytes challenge.
    pub fn encrypt_challenge(&self, challenge: &[u8; 16]) -> [u8; 16] {
        let mut response = [0u8; 16];
        response.copy_from_slice(&des::encrypt(challenge, &self.key));
        response
    }

    /// Check the response of a client to `challenge`.
    pub fn check(&self, challenge: &[u8; 16], response: &[u8; 16]) -> bool {
        // A constant time comparison, so that a wrong password does not leak
        // its prefix through the time it takes to reject it.
        let expected = self.encrypt_challenge(challenge);
        expected
            .iter()
            .zip(response)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

/// A password, either empty (no authentication) or set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Password(Option<VncPassword>);

impl Password {
    /// A password that authenticates nobody, i.e. security type `None`.
    pub fn none() -> Self {
        Self(None)
    }

    /// Require the clients to authenticate with `password`.
    pub fn new(password: &str) -> Self {
        Self(Some(VncPassword::new(password)))
    }

    /// Whether a password is required.
    pub fn is_required(&self) -> bool {
        self.0.is_some()
    }

    /// The name of the authentication method, as reported by the
    /// `org.qemu.Vnc1.Server.Auth` property.
    pub fn auth_method(&self) -> &'static str {
        if self.is_required() { "vnc" } else { "none" }
    }

    pub(crate) fn key(&self) -> Option<&VncPassword> {
        self.0.as_ref()
    }
}

/// What a session requires from its clients.
#[derive(Debug)]
pub enum SecurityPolicy<'a> {
    /// RFB security type 1: no authentication.
    None,
    /// RFB security type 2: the VNC password challenge/response.
    VncAuth(&'a Password),
    /// RFB security type 20: SASL, over the offered mechanisms.
    ///
    /// What is offered is the same for every client, so it is shared; the
    /// state of an exchange belongs to the connection, and the session makes
    /// one out of this. The result comes back to the caller, which is where
    /// the username and the security layer belong: the protocol does not end
    /// with them.
    Sasl(&'a crate::rfb::sasl::Mechanisms),
}

impl SecurityPolicy<'_> {
    /// The security types to offer, most preferred first.
    pub(crate) fn offered(&self) -> Vec<super::SecurityType> {
        match self {
            SecurityPolicy::None => vec![SecurityType::None],
            SecurityPolicy::VncAuth(password) => match password.key() {
                Some(_) => vec![SecurityType::VncAuthentication],
                // Expired or unset: degrade to no authentication rather than
                // refusing every client.
                None => vec![SecurityType::None],
            },
            // SASL is only offered when there is a mechanism behind it: a
            // client that is told SASL is available and finds nothing to use
            // is worse off than one that was never offered it.
            SecurityPolicy::Sasl(sasl) => {
                if sasl.is_empty() {
                    vec![]
                } else {
                    vec![super::SecurityType::Sasl]
                }
            }
        }
    }

    /// The security type the client picked, if we accept it.
    pub(crate) fn check_choice<'p>(
        &'p self,
        choice: super::SecurityType,
    ) -> Result<SecurityPolicy<'p>> {
        if self.offered().contains(&choice) {
            return match (self, choice) {
                (SecurityPolicy::VncAuth(password), SecurityType::VncAuthentication) => {
                    match password.key() {
                        Some(_) => Ok(SecurityPolicy::VncAuth(password)),
                        None => Ok(SecurityPolicy::None),
                    }
                }
                (SecurityPolicy::Sasl(sasl), SecurityType::Sasl) => Ok(SecurityPolicy::Sasl(sasl)),
                _ => Ok(SecurityPolicy::None),
            };
        }
        Err(Error::AuthenticationUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DES key is the password, truncated, with the bits of every octet
    /// reversed, as the RFB scheme requires.
    #[test]
    fn key_is_bit_reversed() {
        // 'a' is 0x61, 'b' is 0x62.
        assert_eq!(
            VncPassword::new("ab").key,
            [0b1000_0110, 0b0100_0110, 0, 0, 0, 0, 0, 0]
        );
    }

    /// Check the vendored DES against the standard test vector: the whole VNC
    /// authentication depends on it.
    #[test]
    fn des_is_a_correct_des() {
        let key: des::Key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        let block: Vec<u8> = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let ciphertext: Vec<u8> = vec![0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05];
        assert_eq!(des::encrypt(&block, &key), ciphertext);
        assert_eq!(des::decrypt(&ciphertext, &key), block);

        // The RFB challenge is two blocks, encrypted independently (ECB).
        let challenge: Vec<u8> = block.iter().chain(&block).copied().collect();
        let encrypted = des::encrypt(&challenge, &key);
        assert_eq!(encrypted, ciphertext.repeat(2));
        assert_eq!(des::decrypt(&encrypted, &key), challenge);
    }

    #[test]
    fn password_is_truncated() {
        assert_eq!(
            VncPassword::new("0123456789").key,
            VncPassword::new("01234567").key
        );
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let challenge = [0x42; 16];
        let password = Password::new("secret");
        let key = password.key().unwrap();
        assert!(key.check(&challenge, &key.encrypt_challenge(&challenge)));

        let wrong = VncPassword::new("secre7");
        assert!(!wrong.check(&challenge, &key.encrypt_challenge(&challenge)));
    }

    #[test]
    fn a_client_only_offering_none_is_rejected() {
        let policy = SecurityPolicy::VncAuth(&Password::new("secret"));
        assert!(policy.check_choice(SecurityType::None).is_err());
        assert!(policy.check_choice(SecurityType::VncAuthentication).is_ok());

        let policy = SecurityPolicy::None;
        assert!(
            policy
                .check_choice(SecurityType::VncAuthentication)
                .is_err()
        );
        assert!(policy.check_choice(SecurityType::None).is_ok());
    }
}
