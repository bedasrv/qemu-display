//! Cyrus SASL, the library behind QEMU's `-vnc ...,sasl`.
//!
//! Everything here is behind the `sasl` feature, which needs the Cyrus SASL
//! headers and library at build time — exactly the cost QEMU's
//! `--enable-vnc-sasl` has, and the reason the feature is off by default. The
//! protocol is in [`super::sasl`], which is why a build without this still
//! has working SASL: only the mechanisms that need a library are missing, and
//! `ANONYMOUS`, the one QEMU permits, is not one of them.
//!
//! The calls mirror `ui/vnc-auth-sasl.c`: `sasl_server_new` with the service
//! name `vnc` and the two addresses, a security layer of 56 bits demanded
//! over plain TCP with the anonymous and plaintext mechanisms forbidden, and
//! then `sasl_server_start` and `sasl_server_step` until the exchange ends.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr;

// The bindings are one module per header, `sasl.h` being the one the server
// API is in.
use sasl2_sys::sasl;

use super::sasl::{Anonymous, Endpoints, Error, MAX_DATA, Mechanism, Offered, Step};

/// The service name Cyrus is told this is, which is what picks the
/// `/etc/sasl2/vnc.conf` configuration.
const SERVICE: &str = "vnc";

/// The security layer SASL has to establish on its own.
///
/// QEMU's choice, and the reason `--sasl` is worth having: enough to rule out
/// the trivially crackable mechanisms. It is a minimum, so a mechanism that can
/// do better still may.
const MIN_SSF: u32 = 56;

/// An arbitrary upper bound, as QEMU puts it: the number only has to be large
/// enough not to be the thing that limits a mechanism.
const MAX_SSF: u32 = 100_000;

/// The buffer one step may use, which is what bounds a round.
const MAX_BUFSIZE: u32 = 8192;

/// The mechanisms QEMU's SASL is for.
///
/// They are offered whether or not this build of Cyrus has them: a client that
/// picks one Cyrus was not built with is refused cleanly by
/// `sasl_server_start`, which is better than a mechanism list that depends on
/// the library's build options. `ANONYMOUS` is not here because it needs no
/// library and is implemented in [`super`].
const CYRUS_MECHANISMS: [&str; 3] = ["GSSAPI", "PLAIN", "DIGEST-MD5"];

/// A Cyrus SASL mechanism, driven through the RFB framing.
///
/// The connection is created when the exchange starts and disposed of when
/// this is dropped, which is once the client is gone.
pub struct Cyrus {
    name: &'static str,
    conn: *mut sasl::sasl_conn_t,
    endpoints: Endpoints,
    /// The bytes Cyrus is reading for the call in flight.
    ///
    /// Cyrus only reads them during the call, so a borrow would do, but
    /// `start` and `step` share one body and taking the data as an argument
    /// through the FFI signature is where the borrow would have to live.
    input: Vec<u8>,
    /// Whether `input` came from the client or stands for nothing at all.
    has_input: bool,
}

impl Cyrus {
    /// Prepare the `name` mechanism for a client that connected from
    /// `endpoints`.
    pub fn new(name: &'static str, endpoints: &Endpoints) -> Self {
        Self {
            name,
            conn: ptr::null_mut(),
            endpoints: endpoints.clone(),
            input: Vec::new(),
            has_input: false,
        }
    }

    /// Create the Cyrus connection, and set the properties QEMU sets.
    fn open(&mut self) -> Result<(), Error> {
        if !self.conn.is_null() {
            return Ok(());
        }
        let service = cstr(SERVICE)?;
        let local = cstr(&self.endpoints.local)?;
        let remote = cstr(&self.endpoints.remote)?;
        let result = unsafe {
            sasl::sasl_server_new(
                service.as_ptr(),
                // A NULL is "let Cyrus decide", which is what QEMU passes for
                // the host and for the realm.
                ptr::null(),
                ptr::null(),
                local.as_ptr(),
                remote.as_ptr(),
                ptr::null(),
                sasl::SASL_SUCCESS_DATA,
                &mut self.conn,
            )
        };
        if result != sasl::SASL_OK {
            return Err(Error::Refused(format!(
                "the SASL context could not be created: {}",
                errstring(result)
            )));
        }
        // A plain socket brings no security layer of its own, so SASL is told
        // to establish one. A TLS connection announces its own with
        // `SASL_SSF_EXTERNAL` here, which is what the VeNCrypt path does, and
        // what the missing TLS support will have to do.
        let mut properties = sasl::sasl_security_properties {
            min_ssf: MIN_SSF,
            max_ssf: MAX_SSF,
            maxbufsize: MAX_BUFSIZE,
            security_flags: sasl::SASL_SEC_NOANONYMOUS | sasl::SASL_SEC_NOPLAINTEXT,
            property_names: ptr::null_mut(),
            property_values: ptr::null_mut(),
        };
        let result = unsafe {
            sasl::sasl_setprop(
                self.conn,
                sasl::SASL_SEC_PROPS as c_int,
                &mut properties as *mut _ as *const c_void,
            )
        };
        if result != sasl::SASL_OK {
            let error = self.detail("the SASL security properties were refused");
            self.dispose();
            return Err(error);
        }
        Ok(())
    }

    /// What Cyrus says went wrong on this connection.
    fn detail(&self, what: &str) -> Error {
        let detail = unsafe {
            let detail = sasl::sasl_errdetail(self.conn);
            if detail.is_null() {
                String::new()
            } else {
                CStr::from_ptr(detail).to_string_lossy().into_owned()
            }
        };
        if detail.is_empty() {
            Error::Refused(what.to_string())
        } else {
            Error::Refused(format!("{what}: {detail}"))
        }
    }

    /// Release the connection, if there is one.
    fn dispose(&mut self) {
        if !self.conn.is_null() {
            let mut conn = self.conn;
            unsafe { sasl::sasl_dispose(&mut conn) };
            self.conn = ptr::null_mut();
        }
    }

    /// Run one Cyrus call with the client's data in hand.
    fn run(
        &mut self,
        client_data: Option<&[u8]>,
        call: impl FnOnce(
            *mut sasl::sasl_conn_t,
            *const c_char,
            *const c_char,
            c_uint,
            *mut *const c_char,
            *mut c_uint,
        ) -> c_int,
        with_mechanism: bool,
    ) -> Result<Step, Error> {
        let mechanism = cstr(self.name)?;
        // A `NULL` is not an empty string to a mechanism, and which of the two
        // the client sent is why the RFB length is read before the bytes are.
        self.has_input = client_data.is_some();
        self.input = client_data.unwrap_or_default().to_vec();
        let input = if self.has_input {
            self.input.as_ptr() as *const c_char
        } else {
            ptr::null()
        };
        let input_len = self.input.len() as c_uint;
        let mechanism_ptr = if with_mechanism {
            mechanism.as_ptr()
        } else {
            // `sasl_server_step` takes no mechanism, and passing one would be
            // a different call.
            ptr::null()
        };
        let mut serverout: *const c_char = ptr::null();
        let mut serveroutlen: c_uint = 0;
        let result = call(
            self.conn,
            mechanism_ptr,
            input,
            input_len,
            &mut serverout,
            &mut serveroutlen,
        );
        // Cyrus may keep a pointer into the input for the duration of the call
        // only, so the buffer is ours to drop once it returns.
        self.input = Vec::new();
        match result {
            sasl::SASL_OK | sasl::SASL_CONTINUE => {}
            _ => {
                let error = self.detail("the SASL mechanism refused the client");
                self.dispose();
                return Err(error);
            }
        }
        if serveroutlen as usize > MAX_DATA {
            self.dispose();
            return Err(Error::TooMuchData);
        }
        // A `NULL` out is not an empty string either: the RFB framing is what
        // carries the difference to the client.
        let output = if serverout.is_null() {
            None
        } else {
            let data = unsafe {
                std::slice::from_raw_parts(serverout as *const u8, serveroutlen as usize)
            };
            Some(data.to_vec())
        };
        Ok(Step {
            output,
            complete: result == sasl::SASL_OK,
        })
    }

    /// Read one of the connection properties, as the integer it is.
    fn property_int(&self, property: c_int) -> u32 {
        if self.conn.is_null() {
            return 0;
        }
        let mut value: *const c_void = ptr::null();
        let result = unsafe { sasl::sasl_getprop(self.conn, property as c_int, &mut value) };
        if result != sasl::SASL_OK || value.is_null() {
            return 0;
        }
        // `SASL_SSF` is a `sasl_ssf_t`, which is an unsigned int.
        unsafe { *(value as *const u32) }
    }
}

// A Cyrus connection is used from the one task that serves the client, and a
// `Mechanism` is only ever held by that task's exchange. The raw pointer is
// what stops the auto trait; the connection is created in `start` and disposed
// of in `drop`, both on the same task, and is never shared.
unsafe impl Send for Cyrus {}

impl Drop for Cyrus {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl Mechanism for Cyrus {
    fn name(&self) -> &str {
        self.name
    }

    fn start(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error> {
        self.open()?;
        self.run(
            client_data,
            |conn, mechanism, input, len, out, outlen| unsafe {
                sasl::sasl_server_start(conn, mechanism, input, len, out, outlen)
            },
            true,
        )
    }

    fn step(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error> {
        if self.conn.is_null() {
            return Err(Error::Malformed("the SASL exchange is not open"));
        }
        self.run(
            client_data,
            |conn, _mechanism, input, len, out, outlen| unsafe {
                sasl::sasl_server_step(conn, input, len, out, outlen)
            },
            false,
        )
    }

    fn username(&self) -> Option<String> {
        if self.conn.is_null() {
            return None;
        }
        // `SASL_USERNAME` is the authenticated identity, which is what an
        // authorization list is checked against. It is a string property, so
        // it is read as a pointer rather than as an integer.
        let mut value: *const c_void = ptr::null();
        let result =
            unsafe { sasl::sasl_getprop(self.conn, sasl::SASL_USERNAME as c_int, &mut value) };
        if result != sasl::SASL_OK || value.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(value as *const c_char) };
        Some(name.to_string_lossy().into_owned())
    }

    fn ssf(&self) -> u32 {
        self.property_int(sasl::SASL_SSF as c_int)
    }
}

/// A `CString` from a string we control, which cannot hold a NUL.
fn cstr(value: &str) -> Result<CString, Error> {
    CString::new(value).map_err(|_| Error::Refused(format!("{value:?} has a NUL in it")))
}

/// The message for a Cyrus result code.
fn errstring(result: c_int) -> String {
    let message = unsafe { sasl::sasl_errstring(result, ptr::null(), ptr::null_mut()) };
    if message.is_null() {
        format!("error {result}")
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }
}

/// The mechanisms to offer, Cyrus's and the one that needs no library.
pub fn mechanisms() -> Vec<Offered> {
    let mut offered: Vec<Offered> = CYRUS_MECHANISMS
        .iter()
        .map(|name| {
            let name: &'static str = name;
            Offered::new(name, move |endpoints| Box::new(Cyrus::new(name, endpoints)))
        })
        .collect();
    offered.push(Offered::new("ANONYMOUS", |_| Box::new(Anonymous::new())));
    offered
}
