//! What the server has actually done, as numbers.
//!
//! This exists because of a failure of method rather than of code. Every other
//! diagnostic in this crate is a log line, and a log line cannot see the fault
//! that matters most: a loop that runs without doing anything observable. A
//! server spinning on a socket read that never blocks, or on a future that is
//! always ready, produces no output at all — the log stays quiet, which looks
//! exactly like a server that is correctly idle, and that is how a 100% CPU
//! went unexplained through two rounds of logs.
//!
//! The counters are here so that a quiet log is *distinguishable* from a busy
//! one. If the CPU is high and `loops` is not climbing, the spin is not in this
//! crate and the next place to look is the D-Bus executor or the reactor that
//! hosts it. If `loops` is climbing, the heartbeat names which one.
//!
//! # Why this is safe to leave in
//!
//! An earlier diagnostic in this crate measured the framebuffer on every
//! message — 55 ms of `HashSet` inserts per console update — and it was a
//! `tracing` argument, so it ran whether or not anything was logged. That was
//! the second 100% CPU in this port, caused by the very thing meant to explain
//! the first. See `PORTING.md` §7.1.
//!
//! So the rule this module exists to keep is: **an increment, and nothing else.
//! No allocation, no formatting, no call.** An `AtomicU64::fetch_add` relaxed is
//! a handful of nanoseconds and cannot grow with the size of a frame or the
//! number of colours in it. The heartbeat that prints the numbers does the
//! formatting, and it does it once per interval, in one place, where the cost
//! is visible.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How often the heartbeat reports, when it is running at all.
pub const INTERVAL: Duration = Duration::from_secs(5);

/// A counter, and the same counter one interval ago.
#[derive(Debug, Default)]
pub struct Counter {
    now: AtomicU64,
    then: AtomicU64,
}

impl Counter {
    /// One more of whatever this counts.
    ///
    /// Relaxed: nothing here is published to another thread to be *read* in
    /// order — the heartbeat samples the totals, and a slightly stale count in
    /// a diagnostic is worth nothing less than a correct one would be. Relaxed
    /// is a few instructions cheaper than `SeqCst` on the hot path, which is
    /// the only place this is called from.
    #[inline]
    pub fn bump(&self) {
        self.now.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n`.
    #[inline]
    pub fn add(&self, n: u64) {
        self.now.fetch_add(n, Ordering::Relaxed);
    }

    /// The total, without disturbing the rate.
    pub fn total(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }

    /// The total, and how much of it happened since the last call.
    ///
    /// The second number is the one that says *now*: a total that is large is
    /// history, and a rate that is large is a problem.
    pub fn sample(&self) -> (u64, u64) {
        let now = self.now.load(Ordering::Relaxed);
        let then = self.then.swap(now, Ordering::Relaxed);
        (now, now.saturating_sub(then))
    }
}

/// The counters the server keeps.
#[derive(Debug, Default)]
pub struct Counters {
    /// Times the main loop came round.
    pub main_loop: Counter,
    /// And which branch woke it: one counter each for the four things the loop
    /// waits on. Without these, "the main loop is spinning" says *that* and not
    /// *which wait is not waiting*, and the difference between four candidates
    /// is the difference between one round and four.
    /// Woken by a server event.
    pub main_loop_event: Counter,
    /// Woken by a VNC connection being accepted.
    pub main_loop_accept: Counter,
    /// Woken by a WebSocket being accepted.
    pub main_loop_accept_ws: Counter,
    /// Woken by the D-Bus name-owner watch.
    pub main_loop_owner: Counter,
    /// Woken by the D-Bus connection itself closing.
    ///
    /// **Added because the loop could park for ever without it.** On a
    /// peer-to-peer connection there is no well-known name to watch, so the
    /// name-owner arm could never fire; a server whose QEMU had exited was found
    /// still running and still holding its client's socket, with the loop awake
    /// never once. This is the counter that makes that visible if it ever
    /// happens again, because a heartbeat reading zero for every other wake
    /// source is what a stalled loop looks like from outside.
    pub main_loop_conn_closed: Counter,
    /// Times a client's own loop came round.
    pub client_loop: Counter,
    /// D-Bus method calls and signals received from the VM.
    pub dbus_messages: Counter,
    /// Nanoseconds of **processor** time spent receiving D-Bus updates.
    ///
    /// **This is the counter that was missing, and its absence is why a third of
    /// this port's CPU has no owner.** `dbus_messages` counts what arrived; no
    /// counter timed what it cost, so the receive path -- deserialise, copy into
    /// the framebuffer, find the damage, notify -- appeared in no breakdown at
    /// all. Everything spent there was simply unattributed, and the log line
    /// attributed the difference to "outside the update path" without anyone
    /// knowing what was in it.
    ///
    /// On a processor clock rather than `Instant`, because this path ends in a
    /// socket read and a wait for the bus: elapsed time here is mostly *not*
    /// running. `encode_ms` had the same problem and cost a round of wrong
    /// conclusions before `encode_cpu_nanos` was added beside it; this counter
    /// starts out with the fix rather than after it.
    ///
    /// Per thread, so it is comparable with a `/proc` per-thread CPU reading.
    pub dbus_cpu_nanos: Counter,
    /// Events dispatched to a client: keyboard, pointer, cut text, requests.
    pub client_events: Counter,
    /// Framebuffer updates sent to clients.
    pub updates_sent: Counter,
    /// Blocks of samples received from the VM, over `org.qemu.Display1.Audio`.
    ///
    /// **The counter that was missing when a real client could not be made to
    /// play the guest's audio, and it is missing at the end that matters.** The
    /// heartbeat counts framebuffers to the last rectangle encoding, and nothing
    /// counted audio anywhere -- not on the way in from the VM, and not on the
    /// way out to the client. A run could log `client is receiving audio` and
    /// then say nothing more about audio for as long as it went, which is
    /// indistinguishable from a server that negotiated audio correctly and
    /// then sent silence.
    pub audio_captured: Counter,
    /// Blocks of samples written to a client's socket.
    ///
    /// **Paired with `audio_captured` because one of them alone cannot place a
    /// fault.** This one alone says a client was sent audio, and stops there:
    /// the negotiation happened, the socket accepted bytes, and there is still
    /// no answer to why nothing came out of the speakers. `audio_captured`
    /// climbing while this one stays at zero puts the fault between the two;
    /// both climbing together moves the question to the client.
    pub audio_sent: Counter,
    /// Bytes of samples written to a client's socket.
    ///
    /// **Added because `audio_sent` counted messages, and a message can carry
    /// no samples at all.** A resampler that changes the rate holds a whole
    /// chunk before it emits, so most of QEMU's ten-millisecond blocks convert
    /// to nothing; those were sent as empty `DATA` messages and counted, which
    /// made a run report `audio_sent` climbing in step with `audio_captured`
    /// while the client received nothing. Counting blocks without counting
    /// bytes cannot tell those two apart, and that is exactly the question the
    /// counters were added to answer.
    pub audio_sent_bytes: Counter,
    /// Rectangles sent as raw pixels, and each compressed kind beside it.
    ///
    /// **Added because a production log could not answer "which encoding is this
    /// server using", and that question has now been asked twice with the log in
    /// hand.** The chosen encoding was logged at `debug`, and the run that was
    /// supposed to confirm Tight works against a real viewer was started with
    /// `-T info` — so eleven seconds of `dbus_cpu_ms_per_interval=211` and 85 MB
    /// of `bytes_per_interval` sat in the log next to no evidence of what any of
    /// it was encoded with, and the only honest reading of it was "something is
    /// being sent to someone and it is not erroring".
    ///
    /// A debug log is the wrong instrument for this. An encoding choice is not a
    /// diagnostic event, it is the answer to "what is this thing doing", and the
    /// level that carries it should be the one production runs at. Worse, the
    /// count has to be here and not only the choice, because the policy *changes*
    /// the encoding at runtime — a client that cannot keep up gets pushed down the
    /// ladder, and `prefer_encoding` said one thing while what went on the wire was
    /// another. Only counting what was actually sent can tell those apart.
    pub rects_raw: Counter,
    /// See [`Counters::rects_raw`].
    pub rects_zlib: Counter,
    /// See [`Counters::rects_raw`].
    pub rects_zrle: Counter,
    /// See [`Counters::rects_raw`].
    pub rects_tight: Counter,
    /// See [`Counters::rects_raw`].
    pub rects_jpeg: Counter,
    /// The compressed bytes sent in those updates.
    pub bytes_sent: Counter,
    /// The *pixels* those updates covered, before any encoding.
    ///
    /// Added because four rounds of guessing where a hundred per cent of a core
    /// went would have been one measurement of this. `bytes_sent` cannot tell a
    /// full-screen update from a small one — both are "an update" — and every
    /// hypothesis about the cost of video needs to know which it was looking at.
    /// Divided by `updates_sent` it is the average rectangle area, and compared
    /// against the console's area it says directly whether the damage is the
    /// whole screen or a corner of it.
    pub damage_pixels: Counter,
    /// Nanoseconds spent encoding, summed over every rectangle sent.
    ///
    /// The other half of the same measurement, and the one that says whether the
    /// CPU is the encoder. `damage_pixels` divided by `updates_sent` says how
    /// much was sent; this says what it cost. Together they are the whole
    /// arithmetic of the frame rate, and neither is observable from outside the
    /// process without a profiler.
    pub encode_nanos: Counter,
    /// Nanoseconds of **CPU** the encode path consumed, over exactly the span
    /// `encode_nanos` measures, read from `CLOCK_THREAD_CPUTIME_ID` rather than
    /// `Instant`.
    ///
    /// **This exists because `encode_nanos` is wall-clock and has been read as
    /// CPU.** That measurement was the basis of "the encode is 20.4% of a core",
    /// which is what the entire CPU comparison against QEMU rests on. The span
    /// includes writing the framebuffer to the socket; a write that blocks is
    /// elapsed time, not processor time, and on a 28 MB/s stream to a viewer that
    /// cannot keep up that wait is charged to the encoder.
    ///
    /// The two together say it directly: `encode_nanos` above `encode_cpu_nanos`
    /// is time the update path spent not running. If that gap is most of the
    /// figure, the encoder was never the cost and the CPU comparison was
    /// comparing a blocked write against a running one.
    pub encode_cpu_nanos: Counter,
    /// Nanoseconds spent blocked writing an update to a client.
    ///
    /// Split out from `encode_nanos` because they mean opposite things and
    /// conflating them hides both. `encode_nanos` is measured from before the
    /// framebuffer lock to after `session.send` returns, so it includes the
    /// socket write — and a viewer that is not draining turns that into network
    /// backpressure, reported as though the encoder were slow. A report said
    /// this build was three times slower than its own release benchmark, which
    /// is either a real inefficiency or a viewer three frames behind, and the
    /// two are told apart by whether the time is before or after the write.
    ///
    /// QEMU measures the same thing and calls it throttling: `vnc_should_update`
    /// refuses to start an update when `vs->output.offset` is above
    /// `throttle_output_offset`, which is the send queue being full.
    pub send_nanos: Counter,
    /// Nanoseconds spent comparing a guest's damage against the shadow copy.
    ///
    /// **The trade this port made, on the record rather than in a comment.**
    /// Finding damage by comparison instead of trusting the guest's rectangle
    /// costs a `memcmp` and a `memcpy` over every update and saves encoding
    /// whatever did not change. That is obviously a good trade for a guest that
    /// over-reports and a terrible one for a guest that does not, and which it
    /// is cannot be argued from here: it is a property of the guest's drawing,
    /// and the only honest witness is the two numbers side by side on the
    /// machine where it runs.
    ///
    /// So `compare_nanos` is the price and `damage_pixels` is what it bought.
    /// Read them together with `encode_ms`: a falling `damage_pixels` and a
    /// rising `compare_nanos` is the trade working, and the ratio of the second
    /// to the third is the answer to whether it was worth it.
    ///
    /// It should be a rounding error against `encode_ms`. If it is not, the
    /// comparison is doing more work than the damage it saves, and
    /// `DIRTY_BLOCK` is the first thing to look at.
    pub compare_nanos: Counter,
    /// Times the console told the clients that something had changed.
    ///
    /// **A count, not a rate, and it is here to be compared with
    /// `client_events`.** The two are the ends of one path: `console_updated`
    /// broadcasts, and the client task's `handle` picks each one up. When they
    /// disagree, damage is being produced and not acted on, and the symptom is
    /// the one nothing else reports — a client that asks for ever and is sent
    /// nothing, with no error, no disconnection, and every log line saying the
    /// update arrived.
    ///
    /// That is exactly what happened here. A reference client sent 147 requests
    /// and received 2 rectangles over fifteen seconds; the console logged 70
    /// strip updates; `updates_sent` stayed at 1; and `client_events` was 153,
    /// which is 147 requests and almost nothing else. 70 damage notifications
    /// had gone missing between the two counters, and the gap is the whole
    /// story. `client_events` alone cannot show it, because 153 sounds like
    /// "the client is talking" and that is the reading that sends you looking at
    /// the client.
    pub damage_notifications: Counter,
    /// Nanoseconds in the whole per-update path, from entering it to leaving.
    ///
    /// `encode_nanos` starts **inside** this, three lines above the encodes.
    /// Everything between the two is what this file spent five rounds of
    /// bug-hunting failing to see, and it is not nothing: `Damage::rects`, the
    /// `encodings.clone()`, `desktop_resize` and `send_cursor`, all of it
    /// outside the timer that produced every "the encoder is at fault" number
    /// here.
    ///
    /// The one thing it now settles. `encode_ms_per_interval` fell from 1121 to
    /// 974 on the production log — 1.74 ms an update, against a conversion fix
    /// measured at 0.95 ms — and `vnc-client-0` moved from 30.9% to 30.0%,
    /// which is 45% of the measured saving failing to become CPU. Either
    /// something outside the encode is taking the rest, or `encode_ms` is not
    /// measuring what the thread spends. **One subtraction decides which**:
    ///
    /// ```text
    /// outside = top_cpu - update_nanos_per_interval
    /// ```
    ///
    /// and `update_nanos - encode_nanos` says how much of the update is not the
    /// encoder. If both are small then the encoder is the whole of this thread's
    /// work and the gap is `top` measuring something else, which would be the
    /// most interesting answer available.
    pub update_nanos: Counter,
    /// Nanoseconds the client task spent handling events, waiting included.
    ///
    /// The complement of `update_nanos`, and the one that catches the cost of
    /// *not* sending: the `select!` that waits on the socket and the deadline,
    /// and the parsing of every one of the 224 client messages a five-second
    /// interval carries. A client that asks faster than the interval allows
    /// spends its time here, and `encode_ms` says nothing about that at all —
    /// which is why "the encoder is at fault" and "the client is asking too
    /// often" have been indistinguishable in every report in this file.
    pub idle_nanos: Counter,
    /// Clients accepted.
    pub clients: Counter,
}

static COUNTERS: std::sync::LazyLock<Counters> = std::sync::LazyLock::new(Counters::default);

/// The server's counters.
pub fn counters() -> &'static Counters {
    &COUNTERS
}

/// What the last interval looked like, and what it means.
///
/// A plain value rather than a log call, so that the *decision* can be tested
/// without a subscriber — which is the point, because the decision is the whole
/// of this module. A heartbeat that cannot be checked in a test is a heartbeat
/// that silently stops reporting, and a diagnostic that silently stops
/// reporting is the third thing in a row that has cost a round of somebody's
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Times the main loop has come round.
    pub main_loop: u64,
    /// Of those, how many since the last report.
    pub main_loop_rate: u64,
    /// Since the last report, how many times the main loop was woken by a server
    /// event, by a VNC accept, by a WebSocket accept, and by the name-owner
    /// watch. Exactly one of these accounts for a spinning loop, and saying
    /// which is the difference between one round of investigation and four.
    pub main_loop_event_rate: u64,
    /// See [`Report::main_loop_event_rate`].
    pub main_loop_accept_rate: u64,
    /// See [`Report::main_loop_event_rate`].
    pub main_loop_accept_ws_rate: u64,
    /// See [`Report::main_loop_event_rate`].
    pub main_loop_owner_rate: u64,
    /// See [`Report::main_loop_event_rate`].
    pub main_loop_conn_closed_rate: u64,
    /// Times a client's loop has come round.
    pub client_loop: u64,
    /// Of those, how many since the last report.
    pub client_loop_rate: u64,
    /// Console messages received from the VM.
    pub dbus_messages: u64,
    /// Of those, how many since the last report.
    pub dbus_rate: u64,
    /// Events dispatched to a client.
    pub client_events: u64,
    /// Of those, how many since the last report.
    pub client_events_rate: u64,
    /// Framebuffer updates sent.
    pub updates: u64,
    /// Blocks of samples received from the VM, and how many since the last
    /// report. See [`Counters::audio_captured`].
    pub audio_captured: u64,
    /// See [`Report::audio_captured`].
    pub audio_captured_rate: u64,
    /// Blocks written to a client's socket, and how many since the last report.
    /// See [`Counters::audio_sent`].
    pub audio_sent: u64,
    /// See [`Report::audio_sent`].
    pub audio_sent_rate: u64,
    /// Bytes of samples written to a client's socket, and how many since the
    /// last report. See [`Counters::audio_sent_bytes`].
    pub audio_sent_bytes: u64,
    /// See [`Report::audio_sent_bytes`].
    pub audio_sent_bytes_rate: u64,
    /// Rectangles sent, by the encoding they went out as.
    ///
    /// Totals, and see the `_rate` fields for the same numbers per interval. A
    /// sum that is not close to `updates` is its own finding: it means updates
    /// went out carrying no rectangle at all, which is what a client asking for
    /// ever and being sent nothing looks like from in here.
    pub rects_raw: u64,
    /// See [`Report::rects_raw`].
    pub rects_zlib: u64,
    /// See [`Report::rects_raw`].
    pub rects_zrle: u64,
    /// See [`Report::rects_raw`].
    pub rects_tight: u64,
    /// See [`Report::rects_raw`].
    pub rects_jpeg: u64,
    /// See [`Report::rects_raw`].
    pub rects_raw_rate: u64,
    /// See [`Report::rects_raw_rate`].
    pub rects_zlib_rate: u64,
    /// See [`Report::rects_raw_rate`].
    pub rects_zrle_rate: u64,
    /// See [`Report::rects_raw_rate`].
    pub rects_tight_rate: u64,
    /// See [`Report::rects_raw_rate`].
    pub rects_jpeg_rate: u64,
    /// Of those, how many since the last report.
    pub updates_rate: u64,
    /// Compressed bytes sent in updates.
    pub bytes: u64,
    /// Of those, how many since the last report.
    pub bytes_rate: u64,
    /// Pixels covered by updates, before encoding.
    pub damage_pixels: u64,
    /// Of those, how many since the last report.
    pub damage_pixels_rate: u64,
    /// Nanoseconds spent encoding.
    pub encode_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub encode_ms_rate: u64,
    /// CPU nanoseconds for the same span as `encode_ms`, which is wall-clock.
    /// The difference between the two is time the update path spent blocked
    /// rather than running, which is the number that decides whether the
    /// encoder or a viewer that cannot keep up is the cost.
    pub encode_cpu_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub encode_cpu_ms_rate: u64,
    /// Processor time in the D-Bus receive path, which no other counter covers.
    pub dbus_cpu_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub dbus_cpu_ms_rate: u64,
    /// Nanoseconds spent finding the damage by comparison.
    pub compare_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub compare_ms_rate: u64,
    /// Nanoseconds spent blocked writing updates to clients.
    pub send_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub send_ms_rate: u64,
    /// Nanoseconds in the whole per-update path.
    pub update_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub update_ms_rate: u64,
    /// Nanoseconds handling events, waiting included.
    pub idle_ms: u64,
    /// Of those, how many milliseconds since the last report.
    pub idle_ms_rate: u64,
    /// Clients accepted.
    pub clients: u64,
    /// Times the console told the clients that something had changed.
    pub damage_notifications: u64,
    /// Whether a loop is turning over faster than the work could account for.
    pub spinning: bool,
}

impl Report {
    /// One line saying which of the two situations this is.
    pub fn verdict(&self) -> &'static str {
        if self.spinning {
            "a loop is spinning: iterations vastly exceed anything the work justifies"
        } else {
            "loops are idle; a high CPU here is outside this crate"
        }
    }
}

/// Sample every counter, and decide what the numbers mean.
pub fn report() -> Report {
    let c = counters();
    let (main_loop, main_loop_rate) = c.main_loop.sample();
    let (_e, main_loop_event_rate) = c.main_loop_event.sample();
    let (_a, main_loop_accept_rate) = c.main_loop_accept.sample();
    let (_w, main_loop_accept_ws_rate) = c.main_loop_accept_ws.sample();
    let (_o, main_loop_owner_rate) = c.main_loop_owner.sample();
    let (_cc, main_loop_conn_closed_rate) = c.main_loop_conn_closed.sample();
    let (client_loop, client_loop_rate) = c.client_loop.sample();
    let (dbus_messages, dbus_rate) = c.dbus_messages.sample();
    let (dbus_cpu_nanos, dbus_cpu_rate) = c.dbus_cpu_nanos.sample();
    let (client_events, client_events_rate) = c.client_events.sample();
    let (updates, updates_rate) = c.updates_sent.sample();
    let (audio_captured, audio_captured_rate) = c.audio_captured.sample();
    let (audio_sent, audio_sent_rate) = c.audio_sent.sample();
    let (audio_sent_bytes, audio_sent_bytes_rate) = c.audio_sent_bytes.sample();
    let (rects_raw, rects_raw_rate) = c.rects_raw.sample();
    let (rects_zlib, rects_zlib_rate) = c.rects_zlib.sample();
    let (rects_zrle, rects_zrle_rate) = c.rects_zrle.sample();
    let (rects_tight, rects_tight_rate) = c.rects_tight.sample();
    let (rects_jpeg, rects_jpeg_rate) = c.rects_jpeg.sample();
    let (bytes, bytes_rate) = c.bytes_sent.sample();
    let (damage_pixels, damage_pixels_rate) = c.damage_pixels.sample();
    let (encode_nanos, encode_rate) = c.encode_nanos.sample();
    let (encode_cpu_nanos, encode_cpu_rate) = c.encode_cpu_nanos.sample();
    let (send_nanos, send_rate) = c.send_nanos.sample();
    let (compare_nanos, compare_rate) = c.compare_nanos.sample();
    let (update_nanos, update_rate) = c.update_nanos.sample();
    let (idle_nanos, idle_rate) = c.idle_nanos.sample();
    let (clients, _) = c.clients.sample();
    let dbus_cpu_ms = dbus_cpu_nanos / 1_000_000;
    let dbus_cpu_ms_rate = dbus_cpu_rate / 1_000_000;
    let encode_ms = encode_nanos / 1_000_000;
    let encode_ms_rate = encode_rate / 1_000_000;
    let encode_cpu_ms = encode_cpu_nanos / 1_000_000;
    let encode_cpu_ms_rate = encode_cpu_rate / 1_000_000;
    Report {
        main_loop,
        main_loop_rate,
        main_loop_event_rate,
        main_loop_accept_rate,
        main_loop_accept_ws_rate,
        main_loop_owner_rate,
        main_loop_conn_closed_rate,
        client_loop,
        client_loop_rate,
        dbus_messages,
        dbus_rate,
        client_events,
        client_events_rate,
        updates,
        updates_rate,
        audio_captured,
        audio_captured_rate,
        audio_sent,
        audio_sent_rate,
        audio_sent_bytes,
        audio_sent_bytes_rate,
        rects_raw,
        rects_zlib,
        rects_zrle,
        rects_tight,
        rects_jpeg,
        rects_raw_rate,
        rects_zlib_rate,
        rects_zrle_rate,
        rects_tight_rate,
        rects_jpeg_rate,
        bytes,
        bytes_rate,
        damage_pixels,
        damage_pixels_rate,
        encode_ms,
        encode_ms_rate,
        encode_cpu_ms,
        encode_cpu_ms_rate,
        dbus_cpu_ms,
        dbus_cpu_ms_rate,
        compare_ms: compare_nanos / 1_000_000,
        compare_ms_rate: compare_rate / 1_000_000,
        update_ms: update_nanos / 1_000_000,
        update_ms_rate: update_rate / 1_000_000,
        idle_ms: idle_nanos / 1_000_000,
        idle_ms_rate: idle_rate / 1_000_000,
        damage_notifications: c.damage_notifications.total(),
        send_ms: send_nanos / 1_000_000,
        send_ms_rate: send_rate / 1_000_000,
        clients,
        spinning: is_spinning(main_loop_rate, client_loop_rate),
    }
}

/// A thousand loop iterations inside one interval is a thousand per five seconds,
/// or two hundred a second. Nothing this crate does legitimately turns a loop
/// over that often: the main loop runs once per event and the client loop once
/// per message or per refresh deadline, and both are bounded by what the bus
/// and the socket deliver — so a rate in the thousands can only be a loop that
/// is not waiting for anything.
///
/// A function rather than a field set by `report`, so that the decision can be
/// tested directly. As a field it was testable only by constructing a whole
/// `Report` and asserting on the literal one had just written, which is a test
/// of the test.
pub const SPINNING_THRESHOLD: u64 = 1000;

/// Whether these two rates mean a loop is spinning.
pub fn is_spinning(main_loop_rate: u64, client_loop_rate: u64) -> bool {
    main_loop_rate > SPINNING_THRESHOLD || client_loop_rate > SPINNING_THRESHOLD
}

/// Log a report.
pub fn log(r: &Report) {
    tracing::info!(
        main_loop = r.main_loop,
        main_loop_per_interval = r.main_loop_rate,
        // The branch that woke it. One of these is the whole of the fault when
        // the loop is spinning: the loop waits on four things and only one of
        // them is not waiting.
        wake_event_per_interval = r.main_loop_event_rate,
        wake_accept_per_interval = r.main_loop_accept_rate,
        wake_accept_ws_per_interval = r.main_loop_accept_ws_rate,
        wake_owner_changed_per_interval = r.main_loop_owner_rate,
        wake_connection_closed_per_interval = r.main_loop_conn_closed_rate,
        client_loop = r.client_loop,
        client_loop_per_interval = r.client_loop_rate,
        dbus_messages = r.dbus_messages,
        dbus_per_interval = r.dbus_rate,
        // Processor time in the receive path, so the part of this process that
        // is not the encoder has an owner. It is a different thread from the
        // client task, so `encode_cpu_ms` does not cover any of it.
        dbus_cpu_ms = r.dbus_cpu_ms,
        dbus_cpu_ms_per_interval = r.dbus_cpu_ms_rate,
        client_events = r.client_events,
        client_events_per_interval = r.client_events_rate,
        updates = r.updates,
        updates_per_interval = r.updates_rate,
        // Audio, both ends of it. A negotiation that succeeds and then goes
        // quiet looks identical to a working one without these: see
        // `Counters::audio_captured`. The two together place a fault, one alone
        // only reports that something happened.
        audio_captured = r.audio_captured,
        audio_captured_per_interval = r.audio_captured_rate,
        audio_sent = r.audio_sent,
        audio_sent_per_interval = r.audio_sent_rate,
        audio_sent_bytes = r.audio_sent_bytes,
        audio_sent_bytes_per_interval = r.audio_sent_bytes_rate,
        // What the rectangles were encoded as. At `info`, on purpose: the level a
        // production run actually uses, because "this server is sending 85 MB an
        // interval and it is not erroring" is not a finding, and "it is sending
        // 85 MB of Tight" is. Also the only way to see the policy move a client
        // down the ladder under load, which is invisible from the preference alone.
        rects_raw = r.rects_raw,
        rects_zlib = r.rects_zlib,
        rects_zrle = r.rects_zrle,
        rects_tight = r.rects_tight,
        rects_jpeg = r.rects_jpeg,
        rects_raw_per_interval = r.rects_raw_rate,
        rects_zlib_per_interval = r.rects_zlib_rate,
        rects_zrle_per_interval = r.rects_zrle_rate,
        rects_tight_per_interval = r.rects_tight_rate,
        rects_jpeg_per_interval = r.rects_jpeg_rate,
        bytes = r.bytes,
        bytes_per_interval = r.bytes_rate,
        // What the updates actually covered, and what they cost to encode. Four
        // rounds of guessing where a saturated core went would have been this
        // line: `bytes` cannot tell a full-screen update from a small one, so
        // every hypothesis about the cost of video needed to know which it was
        // looking at, and the only way to know was to ask for a log that the
        // person reporting the problem had not been asked for in a form they
        // could produce. `damage_per_interval` against the console's area says
        // whether the guest is damaging everything or a corner of it;
        // `encode_ms_per_interval` against `updates_per_interval` says what that
        // cost. Between them they are the whole arithmetic of the frame rate.
        damage_pixels = r.damage_pixels,
        damage_per_interval = r.damage_pixels_rate,
        encode_ms = r.encode_ms,
        encode_ms_per_interval = r.encode_ms_rate,
        encode_cpu_ms = r.encode_cpu_ms,
        encode_cpu_ms_per_interval = r.encode_cpu_ms_rate,
        // The same span on a processor clock. `encode_ms_per_interval` above is
        // elapsed time and includes the socket write, so it is an upper bound on
        // what the encoder cost and a lower bound on how much the update path
        // merely waited. Subtracting this from that is the whole question of
        // whether the encoder is the CPU.
        encode_cpu_ms = r.encode_cpu_ms,
        encode_cpu_ms_per_interval = r.encode_cpu_ms_rate,
        // Time blocked writing to a client, which is not encoding and not ours.
        // `encode_ms_per_interval` includes it, because the measurement runs
        // from before the framebuffer lock to after the write returns; comparing
        // the two says whether a slow frame is a slow encoder or a slow reader.
        send_ms = r.send_ms,
        send_ms_per_interval = r.send_ms_rate,
        // What finding the damage by comparison cost, next to what it saved.
        // These two are the whole argument for `Framebuffer::set_update`'s
        // shadow copy, and neither is visible from outside the process. The
        // claim in the source is "about 0.2 ms for 388,000 pixels, against
        // 19.7 ms of encoding" — this is where that claim gets checked on the
        // machine that matters, and it is a claim about the *guest's* drawing
        // as much as about this code, so it cannot be settled in a test.
        damage_notifications = r.damage_notifications,
        update_ms = r.update_ms,
        update_ms_per_interval = r.update_ms_rate,
        // The rest of the thread: waiting on the socket, and parsing the 224
        // messages a client sends in five seconds. `update_ms_per_interval` plus
        // this is the thread, and `top` is the thread, so the two can be
        // compared directly — which is the first time in this file that has
        // been possible.
        idle_ms = r.idle_ms,
        idle_ms_per_interval = r.idle_ms_rate,
        compare_ms = r.compare_ms,
        compare_ms_per_interval = r.compare_ms_rate,
        clients = r.clients,
        verdict = r.verdict(),
        "heartbeat"
    );
}

/// Report immediately, then every [`INTERVAL`], until `done` completes.
///
/// Cheap by construction: one timer wake-up per interval, and the format string
/// only built if `info` is enabled. The counters are bumped unconditionally,
/// which is the point — a counter that only moves when logging is on cannot tell
/// you whether logging is what is spinning.
///
/// **The first report is immediate**, and that is not cosmetic. The heartbeat
/// was added to explain a symptom that no log could, then failed to appear at
/// all — and nothing in the log could say whether that was because it was broken
/// or because the binary predated it. Reporting at startup makes "is this build
/// current?" a single grep, and gives a zero baseline to read the rates against.
pub async fn heartbeat(done: impl std::future::Future<Output = ()>) {
    log(&report());
    tracing::info!(
        heartbeat_interval_secs = INTERVAL.as_secs(),
        spinning_threshold = SPINNING_THRESHOLD,
        "heartbeat armed; a report follows every interval"
    );
    heartbeat_every(INTERVAL, done).await
}

/// [`heartbeat`], with the interval given, for the test that drives it.
pub async fn heartbeat_every(
    interval: std::time::Duration,
    done: impl std::future::Future<Output = ()>,
) {
    use futures::FutureExt;
    let done = done.fuse();
    futures::pin_mut!(done);
    let mut done = done.fuse();
    loop {
        // A timer per interval rather than an interval stream: a heartbeat that
        // drifts by its own formatting time is still a heartbeat, and this has
        // one fewer thing to be wrong.
        let sleep = async_io::Timer::after(interval).fuse();
        futures::pin_mut!(sleep);
        let mut sleep = sleep.fuse();
        futures::select! {
            _ = sleep => {}
            _ = done => return,
        }
        log(&report());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rate is the difference since the last sample, not the total.
    ///
    /// A total says what has ever happened and a rate says what is happening
    /// now, and only the second one can distinguish a busy server from a
    /// spinning one. This is the arithmetic the whole module exists for, and it
    /// is worth pinning down because the alternative — reading the total and
    /// eyeballing it — is what a log line forces you into.
    #[test]
    fn the_rate_is_what_happened_since_the_last_sample() {
        let counter = Counter::default();
        assert_eq!(counter.sample(), (0, 0), "nothing has happened yet");
        counter.bump();
        counter.bump();
        counter.add(10);
        let (total, rate) = counter.sample();
        assert_eq!((total, rate), (12, 12));
        // A second sample with nothing in between reports nothing, even though
        // the total is unchanged and still large.
        assert_eq!(counter.sample(), (12, 0));
        counter.bump();
        assert_eq!(counter.sample(), (13, 1));
    }

    /// Sampling twice must not lose counts.
    ///
    /// `swap` rather than `load`-then-`store`: with two samplers, or a sampler
    /// racing an increment, a load-then-store would drop whatever arrived in
    /// between, and the diagnostic would under-report exactly when it is being
    /// read because something looks wrong.
    #[test]
    fn sampling_does_not_lose_counts() {
        let counter = Counter::default();
        for _ in 0..1000 {
            counter.bump();
        }
        let (a, _) = counter.sample();
        let (b, _) = counter.sample();
        assert_eq!((a, b), (1000, 1000), "the total is monotonic across samples");
    }

    /// `bump` allocates nothing and formats nothing.
    ///
    /// Not measurable, so it is asserted structurally instead: `bump` is the
    /// one thing on the hot path in this crate, and the way it went wrong before
    /// was by being *more* than a counter. If this ever needs a lock, an
    /// allocation or a format string, it has stopped being the thing it claims
    /// to be, and the property is worth failing on.
    #[test]
    fn the_hot_path_operations_are_only_increments() {
        // A `Counter` is a pair of atomics and nothing else, so there is no
        // place for a buffer or a formatter to hide.
        assert!(
            std::mem::size_of::<Counter>() <= 16,
            "a Counter is {} bytes, so it holds more than its two counters",
            std::mem::size_of::<Counter>()
        );
        // And a hundred thousand increments are far too cheap to be doing
        // anything per-pixel. A single `HashSet` insert over a 1280x800 console
        // is 35 ms; this is a bound of a few milliseconds for a hundred
        // thousand, which is a per-operation cost in the nanoseconds.
        let counter = Counter::default();
        let started = std::time::Instant::now();
        for _ in 0..100_000 {
            counter.bump();
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "a hundred thousand increments took {:?}, which is not a counter any \
             more",
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod heartbeat_tests {
    use super::*;

    /// The heartbeat fires, and stops when it is told to.
    ///
    /// This is the test that the last round of logs should have had and did
    /// not. The heartbeat is the only diagnostic that can see a spin, because a
    /// spin produces no output — and if *it* is the thing that is broken, then
    /// the next log arrives with nothing in it again and the same round starts
    /// over. It had already been sent once that way: a heartbeat wired into
    /// `main` that never printed, for reasons that were in the wiring rather
    /// than in the idea, and forty-five seconds of log that read exactly like
    /// a correctly idle server.
    ///
    /// So the loop is driven here at a short interval and driven to completion,
    /// which checks the three things that can each be wrong independently: the
    /// timer wakes, the reporting runs, and the stop actually stops it.
    #[test]
    fn the_heartbeat_fires_and_stops() {
        let (stop, stopped) = async_channel::bounded::<()>(1);
        let done = async move {
            let _ = stopped.recv().await;
        };
        // A long enough interval that the loop must be sleeping, and short
        // enough that the test does not care.
        let interval = std::time::Duration::from_millis(200);
        let started = std::time::Instant::now();
        async_io::block_on(async {
            let beat = heartbeat_every(interval, done);
            // Let it tick at least twice, then stop it.
            async_io::Timer::after(interval * 3).await;
            stop.try_send(()).expect("the stop signal");
            beat.await;
        });
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the heartbeat took {:?} to stop, so it is not stopping when it is \\
             told to — which on a real run means the select is not waking",
            started.elapsed()
        );
    }

    /// The decision follows the rates, not the totals.
    ///
    /// This is the only output the module has: one number in, one yes or no
    /// out. A diagnostic whose one decision is never checked is a diagnostic
    /// that can be wrong in the only direction that matters, and it is checked
    /// here against the function rather than against a constructed `Report` —
    /// an earlier version of this test built one and asserted on the `spinning`
    /// field it had itself just set, which proved nothing at all.
    #[test]
    fn the_verdict_follows_the_rates_and_not_the_totals() {
        // A server that has done a great deal of work, slowly, is not spinning.
        assert!(!is_spinning(3, 2), "a handful of iterations is not a spin");
        assert!(!is_spinning(SPINNING_THRESHOLD, SPINNING_THRESHOLD));
        assert!(is_spinning(SPINNING_THRESHOLD + 1, 0));
        assert!(is_spinning(0, SPINNING_THRESHOLD + 1));
        assert!(is_spinning(900_000, 0));

        // And the wording each way says which situation it is, because the
        // reader of a log at 3am should not have to derive it.
        let quiet = report();
        if !quiet.spinning {
            assert!(
                quiet.verdict().contains("outside this crate"),
                "a quiet server must be reported as idle, so the search moves \
                 outside this crate"
            );
        }
    }

    /// `report` reads the live counters, and does not consume them.
    ///
    /// Sampling has a side effect — it moves the "last seen" mark — so a report
    /// that consumed the totals would make the *next* one read zero, and the
    /// numbers would describe the interval before last. Two reports in a row
    /// must both be able to see a counter that has not moved.
    #[test]
    fn reporting_twice_does_not_consume_the_counters() {
        counters().main_loop.add(7);
        let first = report();
        let second = report();
        assert_eq!(
            first.main_loop, second.main_loop,
            "the second report lost counts, so the totals are being consumed"
        );
        assert_eq!(first.main_loop_rate, 7);
        assert_eq!(second.main_loop_rate, 0, "nothing happened in between");
    }
}

#[cfg(test)]
mod wiring_tests {
    use super::*;

    /// The heartbeat branch of the `select` `main` uses is really polled.
    ///
    /// `select` on two pinned futures is the one thing about the wiring that the
    /// heartbeat's own test cannot cover, and it is exactly the thing that can
    /// be wrong in a way that looks right: `join!` compiles too and would merely
    /// never return, an unpinned future would not compile, and a heartbeat on a
    /// branch nothing polls would pass every other test here and never wake in
    /// production.
    ///
    /// Two deadlocks had to be got past to write this, and both are worth
    /// recording. Making the serving loop *never* complete — which is what
    /// `main_loop` looks like while the server runs — means nothing can end the
    /// `select`, because the heartbeat only ends when the sender is dropped and
    /// the sender is dropped after the `select` returns. And the stop signal has
    /// to be polled *alongside* the `select`: created on its own it is dropped
    /// unpolled and the test hangs, which is the same hang with a different
    /// cause. So the stop is joined to the select, and the select ends when the
    /// heartbeat does.
    #[test]
    fn the_heartbeat_branch_of_the_select_is_polled() {
        let (stop, stopped) = async_channel::bounded::<()>(1);
        let interval = std::time::Duration::from_millis(150);
        let outcome = async_io::block_on(async {
            let beat = heartbeat_every(interval, async move {
                let _ = stopped.recv().await;
            });
            // The stand-in for `main_loop`: it never completes, which is what a
            // server loop does while it is running.
            let serving = async {
                futures::future::pending::<String>().await
            };
            let stop_later = async move {
                async_io::Timer::after(interval * 2).await;
                let _ = stop.try_send(());
            };
            let (outcome, ()) = futures::join!(
                futures::future::select(Box::pin(serving), Box::pin(beat)),
                stop_later
            );
            outcome
        });
        // The heartbeat finished, which is only possible if the select polled
        // that branch and the timer inside it woke.
        assert!(
            matches!(outcome, futures::future::Either::Right(((), _))),
            "the heartbeat did not finish, so its branch of the select was never \
             polled and it would never report anything"
        );
    }
}

#[cfg(test)]
mod starvation_tests {
    use super::*;

    /// A loop that never yields must not be able to starve the heartbeat.
    ///
    /// This is the fault the first two rounds of the diagnostic actually had,
    /// and it deserves a test for a reason beyond tidiness: it is invisible
    /// unless you go looking for it. The heartbeat reported once, at startup,
    /// and then never again for the twenty-nine seconds a real run lasted — and
    /// the log read exactly like a correctly idle server, which is the very
    /// appearance it was built to distinguish. A diagnostic that shares a task
    /// with the thing it is diagnosing cannot report on it, because a spinning
    /// task never yields to anything else on that executor.
    ///
    /// The observable is indirect but sound. `report()` samples every counter,
    /// and sampling moves the "last seen" mark. So: bump a counter, let the
    /// heartbeat on its own thread take its sample, and then check the mark has
    /// moved — while this task spends its time in a loop that never yields, which
    /// is the condition that starved it before.
    #[test]
    fn a_spinning_task_cannot_starve_the_heartbeat() {
        const INTERVAL: std::time::Duration = std::time::Duration::from_millis(30);

        // Settle first, so the assertion is about the heartbeat and not about a
        // sample that happened to be pending.
        let _ = report();
        counters().main_loop.add(5);
        assert_eq!(
            report().main_loop_rate,
            5,
            "the test should start with five unseen iterations"
        );
        // That report consumed the mark again; put them back for the heartbeat
        // to find.
        let _ = report();
        counters().main_loop.add(5);

        std::thread::Builder::new()
            .name("heartbeat-test".into())
            .spawn(|| {
                async_io::block_on(heartbeat_every(INTERVAL, async {
                    futures::future::pending::<()>().await;
                }));
            })
            .expect("the heartbeat thread");

        // Busy, and deliberately not awaiting anything: the condition that
        // starved the heartbeat when the two shared a task.
        let until = std::time::Instant::now() + std::time::Duration::from_millis(400);
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }

        // If the heartbeat ran, it sampled `main_loop` and the five are gone.
        // If it was starved, they are still sitting there.
        let (total, rate) = counters().main_loop.sample();
        assert_eq!(
            rate, 0,
            "the heartbeat did not sample while this task was spinning: five \
             iterations are still unseen, and the mark is at {total}. A heartbeat \
             that can be starved by the loop it is watching cannot detect one."
        );
    }
}
