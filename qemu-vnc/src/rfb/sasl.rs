//! SASL authentication, the RFB security type 20.
//!
//! Cyrus SASL has no maintained pure-Rust implementation, so the exchange is
//! written against [`Mechanism`], and the Cyrus binding is a thin layer behind
//! the `sasl` feature. One mechanism needs no library at all: `ANONYMOUS`, the
//! one QEMU allows, is implemented here, which is what makes the protocol
//! itself testable on a machine with no SASL installed.
//!
//! # The exchange
//!
//! This is what QEMU's `ui/vnc-auth-sasl.c` does, and the numbers come from
//! `ui/vnc.h`:
//!
//! 1. The security type list offers 20, and the client picks it.
//! 2. The server sends `u32 length` + a comma separated mechanism list.
//! 3. The client sends `u32 length` + the name of one of them, 1 to 100 bytes.
//! 4. The client sends `u32 length` + its initial response, which is absent
//!    when the length is zero, and ends in a NUL when it is not. The NUL is
//!    padding the protocol adds, and is not part of the data.
//! 5. The server runs the mechanism and answers `u32 length` + its output + a
//!    NUL, or `u32 0` when it has none, then one byte saying whether the
//!    authentication is complete. Steps 4 and 5 repeat until it is.
//! 6. A finished exchange is accepted with the RFB security result, and a
//!    refused one is rejected with a reason.
//!
//! The distinction between no data and empty data is critical to SASL, and
//! the RFB framing is what makes it expressible: a zero length is a `NULL` and
//! a length of one is an empty string.
//!
//! # Prototypes and exchanges
//!
//! A mechanism holds the state of one client's exchange, so the server cannot
//! hold one: it holds [`Offered`], which is a name and a way to start an
//! exchange, and [`Sasl`] is the per-connection state that turns a name into
//! a live mechanism. That is the split Cyrus SASL makes too, between a
//! plugin list and a `conn`.

use std::fmt;

/// The largest mechanism name the protocol allows.
pub const MAX_MECHNAME: usize = 100;

/// The largest amount of data one step may carry.
pub const MAX_DATA: usize = 8192;

/// How far an exchange got.
#[derive(Debug)]
pub enum Error {
    /// The client named a mechanism we do not offer.
    UnsupportedMechanism(String),
    /// A message was not shaped the way the protocol says.
    Malformed(&'static str),
    /// The mechanism refused the client, with the detail it gave.
    Refused(String),
    /// A step produced more than the protocol's `MAX_DATA` bytes.
    TooMuchData,
    /// A step was refused outright, e.g. a client that gave up.
    Failed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedMechanism(name) => write!(f, "unsupported mechanism {name:?}"),
            Error::Malformed(what) => write!(f, "malformed SASL message: {what}"),
            Error::Refused(detail) => write!(f, "authentication failed: {detail}"),
            Error::TooMuchData => write!(f, "the SASL step is too long"),
            Error::Failed => write!(f, "the SASL step failed"),
        }
    }
}

impl std::error::Error for Error {}

/// One round of the exchange, from the point of view of the server.
#[derive(Debug, Default)]
pub struct Step {
    /// What the server sends back, `None` for no data at all.
    pub output: Option<Vec<u8>>,
    /// Whether the exchange is over.
    pub complete: bool,
}

/// The state of a mechanism for one client's exchange.
///
/// The lifecycle is the one Cyrus SASL has: [`Mechanism::start`] takes the
/// client's first message, and each [`Mechanism::step`] continues until it
/// reports `complete`.
pub trait Mechanism: Send {
    /// The name the client chose, as it appears in the list we sent.
    fn name(&self) -> &str;

    /// Begin the exchange, with the client's initial response if it sent one.
    fn start(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error>;

    /// Continue, with what the client sent for this round.
    fn step(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error>;

    /// The user the exchange authenticated, if it authenticated one.
    fn username(&self) -> Option<String> {
        None
    }

    /// A line about the client for the server's log, if the mechanism has
    /// one worth writing down.
    fn describe(&self) -> Option<String> {
        None
    }

    /// The strength of the security layer SASL says it established, in bits.
    fn ssf(&self) -> u32 {
        0
    }
}

/// The two ends of a connection, as a mechanism is told about them.
///
/// Cyrus SASL reports the client to its plugins by address, and QEMU passes
/// the socket addresses in `sasl_server_new` as `IP;PORT`. Nothing else in
/// the exchange knows or cares where the client is.
#[derive(Clone, Debug, Default)]
pub struct Endpoints {
    /// The address the server is listening on.
    pub local: String,
    /// The address the client connected from.
    pub remote: String,
}

impl Endpoints {
    /// The addresses of a socket, in the form SASL expects.
    pub fn new(local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Self {
        Self {
            local: format!("{};{}", local.ip(), local.port()),
            remote: format!("{};{}", remote.ip(), remote.port()),
        }
    }
}

/// A mechanism the server offers: a name, and a way to start an exchange.
///
/// The factory takes the connection's [`Endpoints`], because a mechanism is
/// created per client and some of them are told who that client is.
pub struct Offered {
    name: &'static str,
    create: MechanismFactory,
}

/// How a mechanism is started for one client.
///
/// A named type rather than a `Box<dyn Fn>` written out twice: the field and
/// the boxed constructor have to agree.
type MechanismFactory = Box<dyn Fn(&Endpoints) -> Box<dyn Mechanism> + Send + Sync>;

impl Offered {
    /// Offer a mechanism, starting each exchange with `create`.
    pub fn new(
        name: &'static str,
        create: impl Fn(&Endpoints) -> Box<dyn Mechanism> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            create: Box::new(create),
        }
    }

    /// The name the client sees in the list.
    pub fn name(&self) -> &str {
        self.name
    }

    /// A mechanism with the state a new exchange needs.
    fn create(&self, endpoints: &Endpoints) -> Box<dyn Mechanism> {
        (self.create)(endpoints)
    }
}

impl fmt::Debug for Offered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Offered")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The mechanisms a server offers, the same for every client.
pub struct Mechanisms {
    offered: Vec<Offered>,
}

impl fmt::Debug for Mechanisms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mechanisms")
            .field("offered", &self.mechanism_names())
            .finish()
    }
}

impl Default for Mechanisms {
    /// Offer nothing: a server with no SASL library and no `ANONYMOUS`.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Mechanisms {
    /// Offer `offered` to the clients that connect.
    pub fn new(offered: Vec<Offered>) -> Self {
        Self { offered }
    }

    /// The list sent to the client, as `A,B,C`.
    pub fn mechanism_list(&self) -> String {
        self.offered
            .iter()
            .map(Offered::name)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The names we accept, for what a server reports about itself.
    pub fn mechanism_names(&self) -> Vec<&str> {
        self.offered.iter().map(Offered::name).collect()
    }

    /// Whether `name` is one of the mechanisms we offered.
    ///
    /// The wire code checks this before reading the client's first message, so
    /// that a client naming something else is told so rather than being made
    /// to send data for a mechanism that does not exist.
    pub fn accepts(&self, name: &str) -> bool {
        self.offered.iter().any(|m| m.name() == name)
    }

    /// Whether there is anything to offer at all.
    pub fn is_empty(&self) -> bool {
        self.offered.is_empty()
    }

    /// A mechanism with the state a new exchange needs, if the name is ours.
    fn create(&self, name: &str, endpoints: &Endpoints) -> Option<Box<dyn Mechanism>> {
        self.offered
            .iter()
            .find(|m| m.name() == name)
            .map(|m| m.create(endpoints))
    }
}

/// One client's SASL exchange.
///
/// It borrows the mechanisms the server offers and owns the state of the
/// handshake, which is what keeps a prototype from carrying one client's
/// exchange into the next.
pub struct Sasl<'a> {
    mechanisms: &'a Mechanisms,
    endpoints: &'a Endpoints,
    current: Option<Box<dyn Mechanism>>,
}

impl fmt::Debug for Sasl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sasl")
            .field("mechanism", &self.current.as_ref().map(|m| m.name()))
            .finish()
    }
}

impl<'a> Sasl<'a> {
    /// Start an exchange with the mechanisms the server offers, for a client
    /// that connected from `endpoints`.
    pub fn new(mechanisms: &'a Mechanisms, endpoints: &'a Endpoints) -> Self {
        Self {
            mechanisms,
            endpoints,
            current: None,
        }
    }

    /// The mechanism a client is talking to, once it has named one.
    pub fn mechanism(&self) -> Option<&str> {
        self.current.as_ref().map(|m| m.name())
    }

    /// The user the exchange authenticated, if it authenticated one.
    pub fn username(&self) -> Option<String> {
        self.current.as_ref().and_then(|m| m.username())
    }

    /// The strength of the security layer SASL established, in bits.
    pub fn ssf(&self) -> u32 {
        self.current.as_ref().map_or(0, |m| m.ssf())
    }

    /// What the exchange says about the client, for the server's log.
    pub fn describe(&self) -> Option<String> {
        self.current.as_ref().and_then(|m| m.describe())
    }

    /// Start the exchange with the mechanism the client named.
    pub fn start(&mut self, mechanism: &[u8], client_data: Option<&[u8]>) -> Result<Step, Error> {
        let name = String::from_utf8(mechanism.to_vec())
            .map_err(|_| Error::Malformed("the mechanism name is not UTF-8"))?;
        let mut current = self
            .mechanisms
            .create(&name, self.endpoints)
            .ok_or(Error::UnsupportedMechanism(name))?;
        let step = current.start(client_data);
        self.current = Some(current);
        step
    }

    /// Continue the exchange, with what the client sent for this round.
    pub fn step(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error> {
        let mechanism = self
            .current
            .as_mut()
            .ok_or(Error::Malformed("no mechanism was chosen"))?;
        mechanism.step(client_data)
    }
}

/// The client data of a step, as the protocol frames it.
///
/// The protocol adds a NUL to every non-empty block, and a mechanism needs
/// that NUL to be *absent* from the data: a `NULL` and an empty string mean
/// different things, which is why the length has to be read before the bytes
/// are.
pub fn unpad(data: &[u8]) -> Result<Option<&[u8]>, Error> {
    if data.is_empty() {
        return Ok(None);
    }
    if *data.last().unwrap() != 0 {
        return Err(Error::Malformed("the SASL data has no NUL padding"));
    }
    Ok(Some(&data[..data.len() - 1]))
}

/// The `ANONYMOUS` mechanism: the one QEMU allows, and the one that needs
/// nothing installed.
pub struct Anonymous {
    trace: Option<String>,
    done: bool,
}

impl Anonymous {
    /// Accept any client, remembering the trace it sent.
    pub fn new() -> Self {
        Self {
            trace: None,
            done: false,
        }
    }

    /// The trace the client sent, if any: with `ANONYMOUS` that is all there
    /// is to know about it. [`Mechanism::describe`] is what a caller uses.
    #[cfg(test)]
    pub fn trace(&self) -> Option<&str> {
        self.trace.as_deref()
    }
}

impl Default for Anonymous {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Anonymous {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anonymous")
            .field("trace", &self.trace)
            .finish()
    }
}

impl Mechanism for Anonymous {
    fn name(&self) -> &str {
        "ANONYMOUS"
    }

    fn start(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error> {
        self.done = true;
        // A trace is a hint for the administrator, not a credential: any is
        // accepted, and none at all is the normal case.
        self.trace = client_data.map(|data| String::from_utf8_lossy(data).into_owned());
        Ok(Step {
            output: None,
            complete: true,
        })
    }

    fn step(&mut self, _client_data: Option<&[u8]>) -> Result<Step, Error> {
        if self.done {
            // The exchange is over: a client that keeps going is not the one
            // we negotiated with.
            Err(Error::Malformed("the exchange is already over"))
        } else {
            Err(Error::Failed)
        }
    }

    fn username(&self) -> Option<String> {
        // ANONYMOUS is not an identity, and inventing one would be a lie the
        // administrator then has to trust.
        None
    }

    fn describe(&self) -> Option<String> {
        // The trace is the one thing a client can say about itself, and it is
        // what makes the mechanism useful to an administrator reading a log.
        self.trace
            .as_deref()
            .map(|trace| format!("ANONYMOUS trace={trace:?}"))
    }
}

/// Whether a client authenticated with SASL is allowed in.
///
/// QEMU puts a QAuthZ object here, which has no equivalent in Rust; this is
/// the allow/deny policy that replaces it, and the default is to allow, as
/// `ANONYMOUS` is not a credential to check.
#[derive(Clone, Debug, Default)]
pub struct Authz {
    allowed: Vec<String>,
}

impl Authz {
    /// Allow every user.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Allow only the named SASL usernames.
    pub fn allow(users: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: users.into_iter().collect(),
        }
    }

    /// Whether `username` may connect.
    pub fn check(&self, username: &str) -> bool {
        self.allowed.is_empty() || self.allowed.iter().any(|u| u == username)
    }
}

/// The security a client ends up with, as SASL reports it.
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// The user name, from the `authid` or the `authcid` of the exchange.
    /// Empty for a mechanism that authenticates nobody.
    pub username: String,
    /// The security layer SASL says it established, or 0 for none.
    pub ssf: u32,
    /// The mechanism the client chose, which is what a client is reported by.
    pub mechanism: Option<String>,
    /// What the mechanism has to say about the client, for the server's log.
    /// A mechanism that authenticates a user has a name and nothing more; one
    /// that does not may still have a trace.
    pub description: Option<String>,
}

/// The mechanisms a server offers when SASL is enabled with no library.
///
/// `ANONYMOUS` is the one QEMU permits with `--sasl`, and the one that needs
/// nothing installed, so it is always available. With the `sasl` feature the
/// Cyrus ones are added.
pub fn default_mechanisms() -> Vec<Offered> {
    #[cfg(feature = "sasl")]
    {
        crate::rfb::sasl_cyrus::mechanisms()
    }
    #[cfg(not(feature = "sasl"))]
    {
        vec![Offered::new("ANONYMOUS", |_| Box::new(Anonymous::new()))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mechanism that asks for one more round, to exercise the loop.
    #[derive(Default)]
    struct Challenge {
        round: u32,
    }

    impl Mechanism for Challenge {
        fn name(&self) -> &str {
            "CHALLENGE"
        }

        fn start(&mut self, _client_data: Option<&[u8]>) -> Result<Step, Error> {
            Ok(Step {
                output: Some(b"who?".to_vec()),
                complete: false,
            })
        }

        fn step(&mut self, client_data: Option<&[u8]>) -> Result<Step, Error> {
            self.round += 1;
            let seen = client_data.unwrap_or_default();
            if self.round == 1 {
                assert_eq!(seen, b"me");
                Ok(Step {
                    output: None,
                    complete: false,
                })
            } else {
                assert_eq!(seen, b"");
                Ok(Step {
                    output: Some(b"ok".to_vec()),
                    complete: true,
                })
            }
        }
    }

    /// What a build with no SASL library offers, and what one with it does.
    ///
    /// `ANONYMOUS` is in both: it is the mechanism QEMU allows, and the only
    /// one that needs nothing installed. The others come from Cyrus and are
    /// only there with the `sasl` feature.
    #[test]
    fn the_list_is_what_is_offered() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        assert!(!mechanisms.is_empty());
        assert!(mechanisms.accepts("ANONYMOUS"));
        assert!(
            mechanisms.accepts("GSSAPI") == cfg!(feature = "sasl"),
            "Cyrus's mechanisms are only offered with the library behind them: {:?}",
            mechanisms.mechanism_names()
        );
        // The list is what a client is told, in the order it was given.
        assert_eq!(
            mechanisms.mechanism_list(),
            mechanisms.mechanism_names().join(",")
        );
        assert!(Sasl::new(&mechanisms, &endpoints).mechanism().is_none());
    }

    #[test]
    fn anonymous_completes_at_once() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        let step = sasl.start(b"ANONYMOUS", None).expect("accepted");
        assert!(step.complete);
        assert!(step.output.is_none());
        assert_eq!(sasl.mechanism(), Some("ANONYMOUS"));
    }

    #[test]
    fn an_anonymous_trace_is_worth_logging() {
        let mut anonymous = Anonymous::new();
        anonymous.start(Some(b"from the lab")).expect("accepted");
        assert_eq!(
            anonymous.describe().as_deref(),
            Some("ANONYMOUS trace=\"from the lab\"")
        );

        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        sasl.start(b"ANONYMOUS", Some(b"from the lab"))
            .expect("accepted");
        assert!(sasl.describe().is_some());

        // A client that sent no trace says nothing, rather than an empty one.
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        sasl.start(b"ANONYMOUS", None).expect("accepted");
        assert_eq!(sasl.describe(), None);
    }

    #[test]
    fn anonymous_records_the_trace() {
        let mut anonymous = Anonymous::new();
        anonymous.start(Some(b"a-trace")).expect("accepted");
        assert_eq!(anonymous.trace(), Some("a-trace"));

        // The same through the exchange, where the mechanism is behind the
        // trait and only the name and the outcome are visible.
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        sasl.start(b"ANONYMOUS", Some(b"a-trace"))
            .expect("accepted");
        assert!(sasl.step(None).is_err(), "it is already over");
    }

    #[test]
    fn an_empty_string_is_not_no_data() {
        // The distinction the protocol exists for.
        assert_eq!(unpad(&[]).unwrap(), None);
        assert_eq!(unpad(&[0]).unwrap(), Some(&[][..]));
        assert!(unpad(b"x").is_err());
    }

    #[test]
    fn a_mechanism_we_do_not_offer_is_refused() {
        let endpoints = Endpoints::default();
        // A list of our own, so the test is the same with and without Cyrus.
        let mechanisms = Mechanisms::new(vec![Offered::new("ANONYMOUS", |_| {
            Box::new(Anonymous::new())
        })]);
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        assert!(!mechanisms.accepts("GSSAPI"));
        let e = sasl.start(b"GSSAPI", None).unwrap_err();
        assert!(matches!(e, Error::UnsupportedMechanism(_)));
    }

    #[test]
    fn what_we_offer_is_what_is_accepted() {
        let mechanisms = Mechanisms::new(default_mechanisms());
        assert!(mechanisms.accepts("ANONYMOUS"));
        assert!(!mechanisms.accepts("anonymous"), "the names are exact");
        assert!(!mechanisms.accepts("ANONYMOUS,ANONYMOUS"));
        // A client can not name a mechanism by picking it out of the list it
        // was sent, which is the check QEMU does before starting Cyrus.
        for name in mechanisms.mechanism_names() {
            assert!(mechanisms.accepts(name));
            assert!(!mechanisms.accepts(&format!("X{name}")));
        }
    }

    #[test]
    fn a_mechanism_gets_fresh_state_for_each_client() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(vec![Offered::new("CHALLENGE", |_| {
            Box::<Challenge>::default()
        })]);
        let mut first = Sasl::new(&mechanisms, &endpoints);
        first.start(b"CHALLENGE", None).expect("started");
        first.step(Some(b"me")).expect("stepped");

        // A second client must not inherit the first one's round count, or it
        // would be told it is two rounds in.
        let mut second = Sasl::new(&mechanisms, &endpoints);
        let step = second.start(b"CHALLENGE", None).expect("started");
        assert!(!step.complete);
        assert_eq!(step.output.as_deref(), Some(&b"who?"[..]));
    }

    #[test]
    fn the_exchange_rounds_until_the_mechanism_is_done() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(vec![Offered::new("CHALLENGE", |_| {
            Box::<Challenge>::default()
        })]);
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        let step = sasl.start(b"CHALLENGE", None).expect("started");
        assert!(!step.complete);
        assert_eq!(step.output.as_deref(), Some(&b"who?"[..]));

        let step = sasl.step(Some(b"me")).expect("stepped");
        assert!(!step.complete);
        assert!(step.output.is_none());

        let step = sasl.step(Some(b"")).expect("stepped");
        assert!(step.complete);
        assert_eq!(step.output.as_deref(), Some(&b"ok"[..]));
    }

    #[test]
    fn a_mechanism_is_told_where_the_client_is() {
        // Cyrus needs it, and the only way it can have it is through here.
        let endpoints = Endpoints::new(
            "127.0.0.1:5900".parse().unwrap(),
            "10.0.0.1:34567".parse().unwrap(),
        );
        assert_eq!(endpoints.local, "127.0.0.1;5900");
        assert_eq!(endpoints.remote, "10.0.0.1;34567");

        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let record = seen.clone();
        let mechanisms = Mechanisms::new(vec![Offered::new("RECORD", move |endpoints| {
            *record.lock().unwrap() = endpoints.remote.clone();
            Box::new(Challenge::default())
        })]);
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        sasl.start(b"RECORD", None).expect("started");
        assert_eq!(seen.lock().unwrap().as_str(), "10.0.0.1;34567");
    }

    #[test]
    fn a_step_without_a_mechanism_is_malformed() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        assert!(matches!(sasl.step(None).unwrap_err(), Error::Malformed(_)));
    }

    #[test]
    fn an_anonymous_client_has_no_username() {
        let endpoints = Endpoints::default();
        let mechanisms = Mechanisms::new(default_mechanisms());
        let mut sasl = Sasl::new(&mechanisms, &endpoints);
        sasl.start(b"ANONYMOUS", None).expect("accepted");
        assert_eq!(sasl.username(), None);
        assert_eq!(sasl.ssf(), 0);
    }

    #[test]
    fn the_allow_list_is_empty_by_default() {
        let authz = Authz::allow_all();
        assert!(authz.check("anyone"));
        let authz = Authz::allow(["alice".to_string()]);
        assert!(authz.check("alice"));
        assert!(!authz.check("bob"));
    }
}
