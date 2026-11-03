//! One served client: the session, the RFB events, and the console they are
//! dispatched to.
//!
//! A client runs in a task of its own ([`client_thread`]), polling its
//! connection and the [`ClientEvent`]s together. Everything the RFB protocol
//! says to a client lives here; [`super`] holds what is shared between them.

use std::collections::HashSet;
use std::time::Instant;

use async_channel::Receiver;
use futures::FutureExt;
use qemu_display::Result;
use tracing::{debug, info, warn};

use super::events::{ClientEvent, Disconnect};
use super::{ClientId, Server, ServerEvent, Share, block_on};
use crate::display::{Cursor, Display, Framebuffer, FramebufferHandle};
use crate::input::{ModifierState, PointerState};
use crate::rfb::audio;
use crate::rfb::{
    AudioCommand, ClientTransport, Codec, Encoders, Encoding, Error as RfbError, Event as VncEvent,
    FramebufferUpdate, PixelFormat, Rect, Screen, ServerOptions, TcpSession, protocol,
};

/// CPU nanoseconds consumed by *this thread*, from
/// `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`.
///
/// **This exists because `Instant` is the wrong clock for the encode
/// measurement, and that mistake was load-bearing.** `encode_nanos` is timed
/// with `Instant::now()` around the whole update path, which includes writing
/// the framebuffer to the socket. A write that blocks is *elapsed* time, not
/// processor time: on a 28 MB/s stream to a viewer that cannot drain fast
/// enough, the socket blocks and the wait is charged to the encoder.
///
/// That produced "the encode is 20.4% of a core", which is what the whole CPU
/// comparison against QEMU was argued from, and it is a wall-clock number read
/// as a CPU number. Reading the same span on both clocks settles it: the
/// difference is time the update path spent not running.
///
/// Declared here rather than pulled from `libc` because it is a handful of
/// lines and this crate does not otherwise depend on it.
pub fn thread_cpu_nanos() -> u64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    // `clockid_t` is a C `int` and `struct timespec` is as declared, on every
    // platform this builds for: 64-bit `time_t`, 64-bit `tv_nsec`.
    unsafe extern "C" {
        fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
    }
    /// Linux's `CLOCK_THREAD_CPUTIME_ID`. Per *thread*, not per process, so this
    /// is the VNC client thread alone — which is the number a per-thread CPU
    /// reading from `/proc` would show, and can be compared with one.
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, correctly aligned `timespec` and the clock id is a
    // constant Linux defines. The kernel writes at most `sizeof(struct timespec)`.
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec.max(0) as u64) * 1_000_000_000 + (ts.tv_nsec.max(0) as u64)
}

/// The floor on the delay between two framebuffer updates to one client.
///
/// QEMU's `VNC_REFRESH_INTERVAL_BASE`, which is `GUI_REFRESH_INTERVAL_DEFAULT`:
/// the fastest its console refresh timer will run when there is something to
/// send. Thirty milliseconds is about thirty frames a second, and it is a floor
/// rather than a target — a client whose updates are cheap gets them as often
/// as the guest draws, and this only stops it being asked for them faster.
const REFRESH_BASE: std::time::Duration = std::time::Duration::from_millis(30);

/// How much to back off after a round that had nothing to send.
///
/// QEMU's `VNC_REFRESH_INTERVAL_INC`.
const REFRESH_INC: std::time::Duration = std::time::Duration::from_millis(50);

/// The ceiling on the delay, for a client that is not draining its socket.
///
/// QEMU's `VNC_REFRESH_INTERVAL_MAX`, which is `GUI_REFRESH_INTERVAL_IDLE`.
const REFRESH_MAX: std::time::Duration = std::time::Duration::from_millis(3000);

/// Turn an RFB error into a `qemu_display::Error`, the crate-wide error.
fn rfb_error(e: RfbError) -> qemu_display::Error {
    qemu_display::Error::Failed(e.to_string())
}

/// The RFB pixel format matching [`crate::display::PIXMAN_X8R8G8B8`].
pub fn pixman_xrgb() -> PixelFormat {
    PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    }
}

/// The VNC client, running in its own thread.
struct Client {
    id: ClientId,
    server: Server,
    session: TcpSession,
    state: ClientState,
    events: Receiver<ClientEvent>,
    /// The pixel encoders, and the state they need between updates: a zlib
    /// stream per encoding, and the adaptation level.
    encoders: Encoders,
    /// Scratch buffer, used to convert the framebuffer to the client format.
    scratch: Vec<u8>,
    /// Converts the guest's samples into the format this client asked for.
    ///
    /// One per client, and kept between blocks, because two clients may have
    /// asked for two different formats and because a resampler has to hold the
    /// samples either side of a block boundary to interpolate across it.
    audio: crate::audio::Converter,
}

#[derive(Debug)]
struct ClientState {
    display: u32,
    dimensions: (u16, u16),
    pixel_format: PixelFormat,
    /// The client's encodings, **in the order it sent them**.
    ///
    /// A `HashSet` would answer "what did it offer" and throw away "which did
    /// it prefer", and the second is the one that decides the encoding. QEMU
    /// walks this list and takes the first entry it has a case for, so an
    /// unordered collection cannot reproduce that rule at all — it is the
    /// difference between serving a client Tight, which is what it asked for
    /// first, and serving it ZRLE, which is what this port did.
    encodings: Vec<Encoding>,
    last_update: Option<Instant>,
    /// How long to wait after the next update before sending it.
    ///
    /// QEMU's `dcl.update_interval`, and the same three constants: it halves
    /// towards [`REFRESH_BASE`] whenever an update goes out and grows by
    /// [`REFRESH_INC`] towards [`REFRESH_MAX`] whenever a round found nothing
    /// to send. That is not a throttle in the usual sense — it is the reason a
    /// client cannot make the server work harder by asking more often, which
    /// matters because one full-screen ZRLE frame of a real console costs tens
    /// of milliseconds of encoding and a client can ask several times inside
    /// that.
    refresh_interval: std::time::Duration,
    /// When deferred damage should be sent, if it has been deferred.
    ///
    /// The alternative to a deadline is to send anyway, and that is the bug
    /// this replaces: the delay used to be a `thread::sleep` on the client's own
    /// task, which held up its input handling as well as the update. Deferring
    /// means the frame is still coming — the guest can draw once and then go
    /// quiet, and a frame that waits for the *next* event that may never come is
    /// a frame the client never sees.
    deadline: Option<Instant>,
    /// The part of the framebuffer the client has not been sent yet.
    damage: Damage,
    req_update: bool,
    /// Whether the client's last request was for incremental updates, which is
    /// what QEMU's `VNC_STATE_UPDATE_INCREMENTAL` means. A non-incremental
    /// request is answered once and does not license later pushes.
    incremental: bool,
    cursor: Option<Cursor>,
    pointer: PointerState,
    /// Whether the guest console uses an absolute pointing device. It is
    /// read once when the client attaches to a console, as each D-Bus round
    /// trip would be too expensive for every pointer event.
    pointer_absolute: bool,
    modifiers: ModifierState,
    /// Whether the client asked for the audio pseudo-encoding, and whether it
    /// is receiving the samples. The first is what the acknowledgement is
    /// answered to, the second is what the samples are gated on.
    audio: AudioState,
}

/// What a client asked for of the audio, and what it is getting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AudioState {
    /// The client announced the `Audio` pseudo-encoding.
    wanted: bool,
    /// The client enabled the stream.
    enabled: bool,
    /// The format it asked for, which is what the samples are sent as when it
    /// matches the guest's, and the only thing it gets when it does not.
    format: Option<crate::rfb::audio::Format>,
}

/// Beyond this many separate rectangles, the damage is the whole framebuffer.
///
/// A dirty *bitmap* does this for free — a screen that is entirely dirty is one
/// long run — and a list of rectangles does not, so without a bound a client
/// whose guest reports a few hundred small updates per interval gets a few
/// hundred rectangles on the wire, each with its own header, when one
/// full-screen rectangle would be both smaller and cheaper to encode. At
/// `1280x800` a ZRLE encode is 23 ms; a `64x64` one is 0.02 ms, so sixty-four of
/// them is still the better answer — but five hundred is not, and the whole
/// screen is 1.0 ms of tiles that are nearly all identical.
const MAX_DAMAGE_RECTS: usize = 64;

/// What a client has not been sent yet.
///
/// **A list of rectangles, not a bounding box, and that is the whole point.**
/// This was `Damage::Part(Rect)` accumulating with `old.union(rect)`, which
/// means two damaged corners of the screen become the entire screen. A guest
/// that damages `(0, 0, 64, 64)` and `(1200, 700, 64, 64)` in one interval —
/// a video window and a taskbar clock, say — cost a `1264x764` encode, about
/// 23 ms and a near-full-screen rectangle on the wire, where the two rectangles
/// actually asked for are 0.04 ms between them.
///
/// QEMU keeps a dirty bitmap and emits **one rectangle per horizontal run of
/// dirty pixels**, extended down while the run repeats:
///
/// ```c
/// offset = find_next_bit(vs->dirty, ...);              /* first dirty row  */
/// x2     = find_next_zero_bit(&vs->dirty[y], ...);     /* the run of pixels */
/// h      = find_and_clear_dirty_height(vs, y, x, x2, height);
/// n += vnc_job_add_rect(job, x * ..., y, (x2 - x) * ..., h);
/// ```
///
/// which is why a QEMU VNC server showing the same desktop as this one does not
/// saturate a core. A list of merged rectangles is not a bitmap and does not
/// split a row into runs, but for the case that matters — several separate
/// regions dirty at once — it captures the whole of the difference, and it is
/// the difference between a rectangle the size of the screen and rectangles the
/// size of the changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Damage {
    /// Nothing new.
    #[default]
    None,
    /// The whole framebuffer: a new client, a console switch, or a pixel
    /// format change.
    Full,
    /// The separate parts of the framebuffer that changed, merged where they
    /// touch.
    Parts(Vec<Rect>),
}

impl Damage {
    /// Whether there is something to send.
    fn is_empty(&self) -> bool {
        matches!(self, Damage::None)
    }

    /// Mark the whole framebuffer as needing an update.
    fn full(&mut self) {
        *self = Damage::Full;
    }

    /// Mark a rectangle of the framebuffer as needing an update.
    ///
    /// Merging is by overlap *or adjacency*, in both axes, so a guest that walks
    /// a cursor across the screen in sixteen-pixel steps does not accumulate
    /// sixteen rectangles. The union is then re-checked against the rest of the
    /// list, because growing one rectangle can swallow another.
    fn part(&mut self, rect: Rect) {
        match self {
            Damage::None => *self = Damage::Parts(vec![rect]),
            Damage::Full => {}
            Damage::Parts(parts) => {
                let mut merged = rect;
                let mut i = 0;
                while i < parts.len() {
                    if parts[i].touches(merged) {
                        merged = merged.union(parts.remove(i));
                        // Growing `merged` may have brought it into contact with
                        // a rectangle already passed, so start again rather
                        // than carry on from `i`.
                        i = 0;
                    } else {
                        i += 1;
                    }
                }
                parts.push(merged);
                if parts.len() > MAX_DAMAGE_RECTS {
                    *self = Damage::Full;
                }
            }
        }
    }

    /// The rectangles to send, in the framebuffer's own coordinates.
    fn rects(&self, width: u16, height: u16) -> Vec<Rect> {
        match self {
            Damage::None => Vec::new(),
            Damage::Full => vec![Rect::new(0, 0, width, height)],
            Damage::Parts(parts) => parts
                .iter()
                .map(|rect| rect.clipped(width, height))
                .filter(|rect| rect.width > 0 && rect.height > 0)
                .collect(),
        }
    }

    /// Forget what has been sent.
    fn clear(&mut self) {
        *self = Damage::None;
    }
}

impl Client {
    /// Whether the console uses an absolute pointing device.
    async fn is_absolute(&self) -> bool {
        match self.display() {
            Some(Display::Graphic(console)) => console.input().is_absolute().await,
            Some(Display::Text(_)) | None => false,
        }
    }

    /// The display the client is currently attached to.
    fn display(&self) -> Option<Display> {
        self.server
            .inner
            .displays
            .read()
            .unwrap()
            .get(&self.state.display)
            .cloned()
    }

    /// The size of the console the client is attached to, for the
    /// acknowledgements, which carry it as QEMU does. A client that has not
    /// been told a size yet gets zero, which is what an empty rectangle is.
    fn framebuffer_dimensions(&self) -> (u16, u16) {
        self.framebuffer()
            .map(|fb| fb.with(|fb| fb.dimensions()))
            .map(|(width, height)| (width as u16, height as u16))
            .unwrap_or((0, 0))
    }

    fn framebuffer(&self) -> Option<FramebufferHandle> {
        self.display().map(|d| d.framebuffer())
    }

    /// Handle an event, returning `false` if the client should go away.
    async fn handle(&mut self, event: ClientEvent) -> bool {
        crate::counters::counters().client_events.bump();
        let result = match event {
            ClientEvent::Vnc(event) => self.handle_vnc(event).await,
            ClientEvent::ConsoleUpdate(index, damage) => {
                if index == self.state.display {
                    match damage {
                        // The runs of changed pixels, merged into whatever is
                        // already damaged — so a run that touches one already
                        // damaged joins it rather than becoming a second
                        // rectangle. That is `find_and_clear_dirty_height`'s job
                        // in QEMU, done by the geometry.
                        Some(rects) => {
                            for rect in rects {
                                self.state.damage.part(rect);
                            }
                        }
                        None => self.state.damage.full(),
                    }
                    // A console that draws is *recorded*, not answered.
                    //
                    // QEMU does not answer it either, and for a reason that is
                    // easy to read past. `vnc_should_update()` does pass once
                    // `has_dirty` is set — but only from a state that a client's
                    // request put the connection in, and `vnc_update_client()`
                    // clears that state the moment it queues a job:
                    //
                    //     vs->job_update = vs->update;
                    //     vs->update = VNC_STATE_UPDATE_NONE;     <- every time
                    //
                    // `vs->update` is assigned in exactly two places in
                    // `ui/vnc.c`: there, and in `framebuffer_update_request()`.
                    // So `VNC_STATE_UPDATE_INCREMENTAL` means *a request is
                    // outstanding*, not *the client once asked*, and between one
                    // update and the next QEMU has no state that permits
                    // another. An earlier version of this arm read "the client is
                    // in the incremental state its last request put it in" as
                    // though the state persisted, and pushed on damage on the
                    // strength of it. The comment claimed QEMU did the same.
                    // It does not, and the difference is a CPU difference rather
                    // than a cosmetic one:
                    //
                    //   QEMU: the frame rate is bounded by the client's request
                    //          rate, so a viewer that is struggling to decode
                    //          asks less often and the server's CPU falls with
                    //          it. The system is self-regulating.
                    //   this:  the frame rate is bounded by our own interval, so
                    //          a console drawing at sixty frames a second costs
                    //          thirty-three encodes a second whether or not the
                    //          client can use one of them.
                    //
                    // So damage is recorded, and only an outstanding request
                    // turns recorded damage into a send. It schedules rather
                    // than sends, for the reason in
                    // [`Client::schedule_update`]: the interval decides when,
                    // and a trigger must not be able to move that.
                    if self.state.req_update {
                        self.schedule_update();
                    }
                    return true;
                }
                Ok(())
            }
            ClientEvent::CutText(text) => self.send_cut_text(&text).await,
            ClientEvent::Audio(source, samples) => self.send_audio_data(source, &samples).await,
            ClientEvent::AudioBegin => self.begin_audio().await,
            ClientEvent::AudioEnd => self.end_audio().await,
            ClientEvent::Terminate => return false,
        };
        match result {
            Ok(()) => true,
            Err(e) => {
                debug!(id = self.id, "client error: {e}");
                false
            }
        }
    }

    /// Handle an event sent by the VNC client.
    async fn handle_vnc(&mut self, event: VncEvent) -> Result<()> {
        match event {
            VncEvent::FramebufferUpdateRequest {
                incremental,
                x_position,
                y_position,
                width,
                height,
            } => {
                self.state.req_update = true;
                self.state.incremental = incremental;
                // A request that is *not* incremental is the client saying it
                // has nothing to show and wants the rectangle regardless of
                // what the server thinks changed. It is how a client asks for a
                // frame on connecting, and how one recovers after losing the
                // one it had; if it were only a hint, both would break.
                //
                // So the rectangle is marked as needing an update, which is
                // what QEMU does: `framebuffer_update_request()` calls
                // `vnc_set_area_dirty(vs->dirty, ...)` on the non-incremental
                // branch and sets `VNC_STATE_UPDATE_FORCE`, and
                // `vnc_update_client()`'s `if (!vs->has_dirty && vs->update !=
                // VNC_STATE_UPDATE_FORCE) return 0;` lets it through anyway.
                //
                // Without this, a client whose earlier push consumed the damage
                // asks for a full frame and is sent nothing at all — which is a
                // viewer showing a blank screen, and no error anywhere.
                if !incremental {
                    self.state
                        .damage
                        .part(Rect::new(x_position, y_position, width, height));
                }
                self.schedule_update();
            }
            VncEvent::KeyEvent { key, down } => self.key(key, None, down).await?,
            VncEvent::ExtendedKeyEvent {
                down,
                keysym,
                keycode,
            } => self.key(keysym, Some(keycode), down).await?,
            VncEvent::PointerEvent {
                button_mask,
                x_position,
                y_position,
            } => self.pointer(button_mask, x_position, y_position).await?,
            VncEvent::SetPixelFormat(format) => {
                if format != pixman_xrgb() {
                    info!(?format, "client requested a pixel format");
                }
                self.state.pixel_format = format;
                self.state.cursor = None;
                self.state.damage.full();
            }
            VncEvent::SetEncodings(encodings) => {
                // A client may send SetEncodings more than once, and the second
                // message replaces the first rather than adding to it, so this
                // is an assignment and not an extension. The count is logged
                // because an *empty* set here is not a client that wants
                // nothing: it is a client whose message we failed to parse,
                // since the length prefix and the values disagree.
                // **The order is what the encoding depends on.** RFB says the
                // list is in order of preference and QEMU takes the first entry
                // it recognises, so the preference is computed here from the
                // list as it arrived. `self.state.encodings` used to be a
                // `HashSet`, which answers "what was offered" and cannot answer
                // "which was preferred" -- so the choice was made by this port's
                // own ladder instead, and the production viewer, which lists
                // Tight before ZRLE, was served ZRLE.
                let preferred = crate::rfb::encodings::preferred_encoding(&encodings);
                debug!(?preferred, "client encoding preference");
                self.encoders.prefer_encoding(&encodings);
                self.state.encodings = encodings;
                debug!(
                    ?self.state.encodings,
                    announced = self.state.encodings.len(),
                    "client encodings"
                );
                // The client may also say how hard it wants things compressed,
                // with the -254 pseudo-encoding. QEMU takes that as its
                // compression level; a client that asks for none gets raw
                // pixels.
                for encoding in &self.state.encodings {
                    if let Encoding::CompressionLevel(level) = encoding {
                        debug!(level, "client compression level");
                        // Two things, and for a while only the second happened.
                        //
                        // The number is a *zlib* level, 0 to 9, and QEMU gives
                        // it to `deflateInit2` — that is the whole of what the
                        // pseudo-encoding means, and it is the only mechanism in
                        // the protocol by which a client can ask for the
                        // trade-off it wants. A client that says 2 is saying "I
                        // would rather have the frames", and this port logged
                        // that and compressed at 6 anyway: 22% of the frame rate
                        // on a 1280x800 frame, for nothing, to a client that had
                        // already said where on the curve it wanted to sit.
                        self.encoders.set_deflate_level(u32::from(*level));
                        // Separately, a level of 0 means no compression at all,
                        // and the cheapest honest answer to that is the encoding
                        // that is not compression.
                        self.encoders.want_compression(*level);
                        // How many requests so far could not be taken because
                        // the stream was already in use, which is the only way
                        // this can go wrong and the only way to find out it has.
                        debug!(
                            declined = self.encoders.declined_levels(),
                            "client compression level"
                        );
                    }
                }
                // Every acknowledgement is a rectangle with the frame buffer's
                // size and no pixels — and "no pixels" is the whole of the
                // contract. A pseudo-rectangle is only payload-free for *some*
                // encodings, and the ones that carry a payload desynchronise the
                // client's byte stream the instant they are sent bare: the
                // client reads the next rectangle's header as the payload, and
                // from then on it is decoding noise. A client that meets an
                // encoding it cannot decode gives up on the connection, and
                // shows a blank screen having never drawn a pixel.
                //
                // QEMU acknowledges exactly two, and both are genuinely bare:
                // `send_ext_key_event_ack()` writes a rectangle and nothing
                // else, and so does `send_ext_audio_ack()`. The others this
                // used to send are not acknowledgements at all, and the reason
                // each one is a fault is written down with the list.
                let (width, height) = self.framebuffer_dimensions();
                let mut fbu = FramebufferUpdate::new(None);
                for encoding in protocol::Encoding::ACKNOWLEDGED {
                    if *encoding != Encoding::Audio && self.state.encodings.contains(encoding) {
                        fbu.add_pseudo_encoding(*encoding, width, height);
                    }
                }
                // The audio pseudo-encoding is acknowledged separately, and
                // only when there is audio to send: it is the only way a
                // client learns the server has audio at all, and telling it so
                // and then sending nothing is worse than silence.
                self.state.audio.wanted = self.state.encodings.contains(&Encoding::Audio);
                self.session.send(&fbu).await.map_err(rfb_error)?;
                if self.state.audio.wanted && self.server.audio_enabled() {
                    let mut ack = FramebufferUpdate::new(None);
                    ack.add_pseudo_encoding(Encoding::Audio, width, height);
                    self.session.send(&ack).await.map_err(rfb_error)?;
                }
            }
            VncEvent::SetDesktopSize { width, height, .. } => {
                info!(width, height, "client requested a resize");
                match self.display() {
                    Some(Display::Graphic(console)) => {
                        console.set_ui_info(width as u32, height as u32).await?;
                        // Wait for the guest to send us a new scanout.
                        self.state.damage.full();
                    }
                    _ => warn!("text consoles can not be resized"),
                }
            }
            VncEvent::CutText(text) => {
                debug!(?text, "client cut text");
                self.server.client_cut_text(&text);
            }
            VncEvent::QemuAudio { command } => self.audio(command).await?,
        }
        Ok(())
    }

    /// Dispatch a key event, as `vnc_key_event()` and `ext_key_event()` do.
    async fn key(&mut self, keysym: u32, keycode: Option<u32>, down: bool) -> Result<()> {
        // Ctrl+Alt-N switches to the Nth console, as QEMU's VNC server does.
        if down {
            if let Some(index) = self.state.modifiers.event(keysym, keycode, true)
                && index != self.state.display
                && self
                    .server
                    .inner
                    .displays
                    .read()
                    .unwrap()
                    .contains_key(&index)
            {
                info!(index, "switching console");
                self.state.display = index;
                self.state.damage.full();
                self.state.cursor = None;
                self.state.pointer_absolute = self.is_absolute().await;
            }
        } else {
            self.state.modifiers.event(keysym, keycode, false);
        }

        match self.display() {
            Some(Display::Graphic(console)) => {
                let input = console.input().clone();
                // Prefer the key number: it is not affected by the keymap
                // layout of the client.
                if let Some(keycode) = keycode {
                    input.key_extended(keycode, down).await?;
                } else {
                    input.key_sym(keysym, down).await?;
                }
            }
            Some(Display::Text(console)) => {
                console.keysym(keysym, down);
            }
            None => {}
        }
        Ok(())
    }

    /// Dispatch a pointer event.
    async fn pointer(&mut self, mask: u8, x: u16, y: u16) -> Result<()> {
        if let Some(Display::Graphic(console)) = self.display() {
            let input = console.input().clone();
            let absolute = self.state.pointer_absolute;
            self.state
                .pointer
                .event(&input, absolute, mask, x, y)
                .await?;
        }
        Ok(())
    }

    /// Send a new desktop size, if it changed.
    /// Tell the client the frame buffer changed size, in the form it asked for.
    ///
    /// Which form that is depends on the client's `SetEncodings`, and the size
    /// is only recorded once it has been announced — which is the whole of this
    /// function's subtlety. Recording it before is wrong in a way that loses the
    /// message: the console can draw, and the server can therefore start an
    /// update, before the client's `SetEncodings` has been read. At that point
    /// the client has announced nothing, so there is no encoding to send the
    /// resize in, and a `dimensions` already recorded means the *next* update
    /// finds nothing to do. The client is then never told, for the rest of the
    /// connection, that the size is not the one in its `ServerInit`.
    ///
    /// QEMU cannot hit this: its `vnc_set_encodings()` ends by calling
    /// `vnc_desktop_resize()`, so the size is always announced after the
    /// encoding list is known. The equivalent here is to leave the size
    /// unrecorded until it has been sent, and let the next update send it.
    async fn desktop_resize(&mut self) -> Result<()> {
        let Some(framebuffer) = self.framebuffer() else {
            return Ok(());
        };
        let (width, height) = framebuffer.with(|fb| fb.dimensions());
        let (width, height) = (width as u16, height as u16);
        if (width, height) == self.state.dimensions {
            return Ok(());
        }

        if self
            .state
            .encodings
            .contains(&Encoding::ExtendedDesktopSize)
        {
            let screens = [Screen {
                id: 0,
                flags: 0,
                rect: Rect::new(0, 0, width, height),
            }];
            let mut fbu = FramebufferUpdate::new(None);
            fbu.add_extended_desktop_size(2, 0, width, height, &screens);
            self.session.send(&fbu).await.map_err(rfb_error)?;
        } else if self.state.encodings.contains(&Encoding::DesktopSize) {
            let mut fbu = FramebufferUpdate::new(None);
            fbu.add_desktop_size(width, height);
            self.session.send(&fbu).await.map_err(rfb_error)?;
        } else {
            // The client has not said which resize encoding it wants, so there
            // is nothing to send yet. The size stays unrecorded, so the next
            // update sends it as soon as it has.
            return Ok(());
        }
        self.state.dimensions = (width, height);
        Ok(())
    }

    /// Send the new cursor, if it changed.
    async fn send_cursor(&mut self) -> Result<()> {
        let cursor = self.display().and_then(|d| d.cursor());
        if cursor == self.state.cursor {
            return Ok(());
        }
        self.state.cursor = cursor.clone();
        let Some(cursor) = cursor else {
            // An empty cursor tells the client to stop drawing it.
            let mut fbu = FramebufferUpdate::new(Some(&self.state.pixel_format));
            fbu.add_cursor(0, 0, 0, 0, &[], &[]);
            self.session.send(&fbu).await.map_err(rfb_error)?;
            return Ok(());
        };
        {
            let pixels = if self.state.pixel_format == pixman_xrgb() {
                cursor.pixels.clone()
            } else {
                let mut pixels = Vec::new();
                let dimensions = (cursor.width as u32, cursor.height as u32);
                if !convert_pixels(
                    &cursor.pixels,
                    dimensions,
                    &self.state.pixel_format,
                    &mut pixels,
                ) {
                    return Ok(());
                }
                pixels
            };
            let mut fbu = FramebufferUpdate::new(Some(&self.state.pixel_format));
            fbu.add_cursor(
                cursor.width,
                cursor.height,
                cursor.hot_x,
                cursor.hot_y,
                &pixels,
                &cursor.mask,
            );
            self.session.send(&fbu).await.map_err(rfb_error)?;
        }
        Ok(())
    }

    /// Send a framebuffer update, if the client has new content to display.
    ///
    /// The rectangle is the area the guest damaged since the last update, and
    /// the encoding is the best one the client asked for that we can produce
    /// at the current quality level.
    ///
    /// Called from every trigger — a client request, a console update, the
    /// refresh deadline — and it is this function, not the triggers, that
    /// decides whether an update happens now. That is the whole of the rate
    /// limiting, and it is here rather than in the callers because the callers
    /// arrive at whatever rate the client and the guest manage, which is not a
    /// rate the server controls.
    async fn send_framebuffer_update(&mut self) -> Result<()> {
        // Every path out of here leaves no deadline behind, except the one that
        // defers. That matters because this runs from the refresh branch of the
        // client's select loop: a deadline left in the past would be ready
        // again the instant the loop came round to it, and the client would
        // wake in a spin.
        self.state.deadline = None;
        self.desktop_resize().await?;
        self.send_cursor().await?;
        // Damage is what makes an update worth sending, and nothing else. The
        // client's last request says whether an incremental push is welcome
        // (see the `ConsoleUpdate` arm), not whether one is *allowed*: making
        // a request a precondition is what meant a console that drew after the
        // client asked had nothing to replace the frame it was already
        // showing.
        if self.state.damage.is_empty() {
            // Nothing to send, so back off, as QEMU does when a refresh round
            // finds no dirty rectangle: `update_interval +=
            // VNC_REFRESH_INTERVAL_INC`, up to the ceiling.
            self.state.refresh_interval =
                (self.state.refresh_interval + REFRESH_INC).min(REFRESH_MAX);
            return Ok(());
        }
        // The guest drew, so react as fast as the floor allows — QEMU's
        // `update_interval /= 2`, clamped to `VNC_REFRESH_INTERVAL_BASE`. The
        // halving is on the *guest* having changed, not on an update reaching
        // this client, which is QEMU's `has_dirty`: a client that has backed off
        // to the ceiling because it was asking for nothing is back at the floor
        // the moment there is something to send it, rather than having to wait
        // out the backoff it earned by being idle.
        self.state.refresh_interval = (self.state.refresh_interval / 2).max(REFRESH_BASE);
        // Too soon after the last one. The damage stays pending and a deadline
        // is set, so the frame is still coming without this call having to
        // block: the client's own input handling shares this task, and a sleep
        // here holds up its keystrokes for as long as the backoff.
        if let Some(last_update) = self.state.last_update {
            let elapsed = last_update.elapsed();
            if elapsed < self.state.refresh_interval {
                self.state.deadline =
                    Some(Instant::now() + (self.state.refresh_interval - elapsed));
                return Ok(());
            }
        }
        let Some(framebuffer) = self.framebuffer() else {
            return Ok(());
        };
        let pixel_format = self.state.pixel_format;
        // The order is kept in `state.encodings` for the preference rule; the
        // set is what the encoders test membership with, and membership does not
        // care about order.
        let encodings: HashSet<Encoding> = self.state.encodings.iter().cloned().collect();
        let damage = self.state.damage.clone();
        let started = Instant::now();
        // The same span, on a processor clock. See `thread_cpu_nanos`: the wall
        // clock above includes the socket write, so on its own it cannot tell a
        // slow encoder from a viewer that is not draining.
        let started_cpu = thread_cpu_nanos();
        // Encoded while the framebuffer is locked, sent once it is not: the lock
        // is shared with the console and the other clients, and holding it for
        // the length of a network write would serialise them behind the slowest
        // one.
        //
        // **One rectangle per damaged region, all in one message.** QEMU's
        // `vnc_update_client` walks a dirty bitmap and calls `vnc_job_add_rect`
        // once per run of dirty pixels, and the job goes out as a single
        // `FramebufferUpdate`. So the wire shape is a message carrying several
        // rectangles, and the whole of the win is that each rectangle is the
        // size of one change rather than the size of the bounding box of all of
        // them: a guest damaging two 64x64 corners cost a 1264x764 encode when
        // the damage was a bounding box, which is 23 ms against 0.04 ms.
        //
        // The encodes happen under the lock and the message is assembled outside
        // it, because `FramebufferUpdate` borrows the pixel data and cannot
        // outlive the closure that read it. One lock for the whole message, so N
        // rectangles cost one lock and N encodes.
        let updates: Vec<Update> = framebuffer.with(|fb| {
            let (fb_width, fb_height) = fb.dimensions();
            damage
                .rects(fb_width as u16, fb_height as u16)
                .iter()
                .filter_map(|rect| self.encode(fb, &pixel_format, &encodings, *rect))
                .collect()
        });
        if updates.is_empty() {
            return Ok(());
        }
        let mut fbu = FramebufferUpdate::new(Some(&pixel_format));
        let mut bytes = 0usize;
        for update in &updates {
            let Update {
                rect,
                codec,
                data,
                bytes: rect_bytes,
            } = update;
            // The ratio of the encoded size to the raw pixels is the one number
            // that says whether the framebuffer holds a picture. A desktop's
            // flat colours and palettes compress to a few percent of raw; a
            // surface of noise does not compress at all, and both look like
            // "an update was sent" in a log.
            let raw = rect.width as usize * rect.height as usize * bytes_per_pixel(&pixel_format);
            debug!(
                encoding = codec.map_or(0, |codec| codec.encoding()),
                level = self.encoders.level(),
                x = rect.left,
                y = rect.top,
                w = rect.width,
                h = rect.height,
                bytes = rect_bytes,
                raw,
                ratio = if raw == 0 {
                    0.0
                } else {
                    *rect_bytes as f32 / raw as f32
                },
                "sending framebuffer update"
            );
            match codec {
                Some(Codec::Zrle) => {
                    fbu.add_compressed_pixels(*rect, data);
                }
                Some(Codec::Zlib) => {
                    fbu.add_zlib_pixels(*rect, data);
                }
                // Tight, and the JPEG that rides on it.
                Some(_) => {
                    fbu.add_tight_pixels(*rect, data);
                }
                // The rectangle goes out raw, and the data is its pixels.
                None => {
                    fbu.add_raw_pixels(*rect, data);
                }
            }
            bytes += rect_bytes;
        }
        // The write, timed on its own. It is inside `encode_ms` — that
        // measurement runs from before the framebuffer lock to here — and it is
        // the difference between an encoder that is slow and a viewer that is
        // not draining. A viewer three frames behind does exactly this: the
        // socket blocks and the wait is accounted to the wrong thing.
        let write_started = Instant::now();
        self.session.send(&fbu).await.map_err(rfb_error)?;
        let write_nanos = write_started.elapsed().as_nanos() as u64;
        {
            let counters = crate::counters::counters();
            counters.updates_sent.bump();
            counters.bytes_sent.add(bytes as u64);
            counters.send_nanos.add(write_nanos);
            // What the rectangles covered, and what they cost. Two numbers that
            // between them say whether the CPU is the encoder and how much of
            // the screen is being encoded: `damage_pixels / updates_sent` is the
            // average rectangle area, `encode_nanos / updates_sent` the average
            // cost. Without them the only evidence available from outside the
            // process was a percentage, and four rounds of guessing at what a
            // hundred per cent of a core was spent on produced one real bug and
            // three wrong answers.
            let pixels: usize = updates
                .iter()
                .map(|u| usize::from(u.rect.width) * usize::from(u.rect.height))
                .sum();
            counters.damage_pixels.add(pixels as u64);
            counters
                .encode_nanos
                .add(started.elapsed().as_nanos() as u64);
            // The same span on a processor clock, so the two can be read against
            // each other. `encode_nanos` above is elapsed time and it includes
            // the socket write, so on its own it cannot tell a slow encoder from
            // a viewer that is not draining. See `thread_cpu_nanos`.
            //
            // Clamped, because the `clock_gettime` failure path returns zero and
            // that must not read as negative CPU and appear to save time.
            counters
                .encode_cpu_nanos
                .add(thread_cpu_nanos().saturating_sub(started_cpu));
        }

        // Tell the policy how the update went, so that it can pick a cheaper
        // encoding for a client that does not keep up.
        let now = Instant::now();
        let interval = self
            .state
            .last_update
            .map_or(self.state.refresh_interval, |last| last.elapsed());
        self.encoders.record(bytes, now - started, interval);
        self.state.last_update = Some(now);
        self.state.damage.clear();
        self.state.req_update = false;
        Ok(())
    }

    /// Ask for the pending damage to be sent as soon as the interval allows.
    ///
    /// The request and console-update paths call this rather than sending, and
    /// that is QEMU's structure rather than a detail of it. QEMU's
    /// `vnc_refresh_rect()` does not send anything: it sets the client's update
    /// state, and the console refresh timer — already scheduled, running at
    /// `dcl.update_interval` — is what calls `vnc_update_client()`. A client
    /// that sends a hundred requests inside one update therefore gets one
    /// update, not a hundred, and that is the whole reason a client cannot make
    /// the server work harder by asking more often.
    ///
    /// Sending synchronously instead is what a port does naturally, because the
    /// request handler is where "the client wants an update" arrives. It is also
    /// how one full-screen ZRLE frame of a real console — tens of milliseconds
    /// of encoding, measured — came to be attempted several times inside its own
    /// encode time. Here a trigger only ever *asks*; the deadline is the one
    /// place an update happens, and it happens at the interval.
    ///
    /// An existing deadline is left alone: it was computed to be the earliest
    /// the interval permits, and pulling it earlier would defeat the limit.
    fn schedule_update(&mut self) {
        if self.state.damage.is_empty() {
            return;
        }
        self.state.deadline.get_or_insert_with(Instant::now);
    }

    /// Build the payload of the next framebuffer update, if there is one.
    ///
    /// Returns the rectangle, the encoding to send it as, and the bytes that
    /// follow the rectangle header. The data is owned: it outlives the lock of
    /// the framebuffer, which is released before the message is written.
    fn encode(
        &mut self,
        fb: &Framebuffer,
        pixel_format: &PixelFormat,
        encodings: &HashSet<Encoding>,
        rect: Rect,
    ) -> Option<Update> {
        let (width, height) = fb.dimensions();
        let (width, height) = (width as u16, height as u16);
        // Damage recorded before a resize may no longer fit the surface.
        let rect = rect.clipped(width, height);
        if rect.width == 0 || rect.height == 0 {
            return None;
        }
        let bpp = bytes_per_pixel(pixel_format);
        let stride = width as usize * bpp;
        // The pixel data in the client format: the framebuffer is already in
        // the QEMU scanout format, which is what most clients ask for.
        self.scratch.clear();
        let pixels: &[u8] = if *pixel_format == pixman_xrgb() {
            fb.data()
        } else {
            convert_pixels_rect(
                fb.data(),
                fb.dimensions(),
                pixel_format,
                rect,
                &mut self.scratch,
            )?;
            &self.scratch
        };
        let wanted = self.encoders.choose(encodings, pixel_format, rect);
        // An encoder that does not support the client format, or content it
        // can not represent, falls back to the next one the client asked for,
        // and then to raw pixels.
        let encoded = self
            .encoders
            .encode(wanted, encodings, pixels, pixel_format, stride, rect);
        let (codec, bytes) = match &encoded {
            Some((codec, data)) => (Some(*codec), data.len()),
            None => (None, rect.width as usize * rect.height as usize * bpp),
        };
        // Counted here, where the codec is known and it is the codec that will go
        // on the wire -- not where the preference was set. The policy can move a
        // client between encodings at runtime, so the preference and what was sent
        // are two different things and only one of them is the truth.
        let c = crate::counters::counters();
        match codec {
            Some(crate::rfb::encodings::Codec::Raw) => c.rects_raw.add(1),
            Some(crate::rfb::encodings::Codec::Zlib) => c.rects_zlib.add(1),
            Some(crate::rfb::encodings::Codec::Zrle) => c.rects_zrle.add(1),
            Some(crate::rfb::encodings::Codec::Tight) => c.rects_tight.add(1),
            Some(crate::rfb::encodings::Codec::Jpeg) => c.rects_jpeg.add(1),
            // `None` means every encoder declined the content and the rectangle is
            // going out as raw pixels.
            None => c.rects_raw.add(1),
        };
        // The raw encoding has no stride, and the compressed ones own their
        // data, so either way the message ends up with bytes of its own.
        let data = match encoded {
            Some((_, data)) => data,
            None => {
                let mut rows = Vec::with_capacity(bytes);
                for y in 0..rect.height as usize {
                    let start = (rect.top as usize + y) * stride + rect.left as usize * bpp;
                    rows.extend_from_slice(&pixels[start..start + rect.width as usize * bpp]);
                }
                rows
            }
        };
        Some(Update {
            rect,
            codec,
            data,
            bytes,
        })
    }

    /// Handle one of the audio messages, which is where the client starts and
    /// stops receiving the samples.
    async fn audio(&mut self, command: AudioCommand) -> Result<()> {
        match command {
            AudioCommand::Enable => {
                if !self.state.audio.wanted {
                    // The pseudo-encoding is what the acknowledgement was for;
                    // a client that enables without it has not been told the
                    // server has audio, so there is nothing to start.
                    debug!("the client enabled audio without asking for it");
                    return Ok(());
                }
                if !self.server.audio_enabled() {
                    // The same gate as the acknowledgement, and for QEMU's
                    // reason: `audio_add()` registers a capture, and the
                    // `AUD_CNOTIFY_ENABLE` that sends `BEGIN` comes from that
                    // capture. A server with nothing to capture never makes
                    // one, so it never announces a stream — and a client told
                    // to expect samples that are not coming would sit and wait
                    // for them.
                    debug!("the client enabled audio on a server with none");
                    return Ok(());
                }
                self.state.audio.enabled = true;
                self.send_audio(audio::BEGIN).await?;
                info!(format = ?self.audio_format(), "client is receiving audio");
            }
            AudioCommand::Disable => {
                if self.state.audio.enabled {
                    self.state.audio.enabled = false;
                    self.send_audio(audio::END).await?;
                }
            }
            AudioCommand::SetFormat(format) => {
                info!(%format, "client asked for an audio format");
                self.state.audio.format = Some(format);
            }
        }
        Ok(())
    }

    /// The end of a stream: flush what this client is holding, and say so.
    ///
    /// A resampler holds back a partial chunk so that the next block carries on
    /// from it. At the end of a stream there is no next block, so without this
    /// the last fraction of a second is dropped and the client is never told
    /// the stream ended — it is left waiting for samples that are not coming.
    /// QEMU sends `VNC_MSG_SERVER_QEMU_AUDIO_END` for the same reason, from
    /// `AUD_CNOTIFY_DISABLE`.
    async fn end_audio(&mut self) -> Result<()> {
        if !self.state.audio.enabled {
            return Ok(());
        }
        let tail = self.audio.flush();
        if !tail.is_empty() {
            let bytes = audio::data(&tail);
            self.session.write_bytes(&bytes).await.map_err(rfb_error)?;
        }
        self.send_audio(audio::END).await
    }

    /// A stream has started, as QEMU's `AUD_CNOTIFY_ENABLE` reports it.
    ///
    /// A `BEGIN` for every stream, and **the client stays enabled throughout**,
    /// which is the whole of the difference from QEMU. `AUD_CNOTIFY_DISABLE`
    /// sends an `END` and changes nothing else: `vs->audio_enabled` there is set
    /// by the client's own `Enable` message and cleared by the client's `Disable`,
    /// never by the guest going quiet.
    ///
    /// This port used to set `enabled = false` at the end of a stream, which is
    /// what made audio a one-shot: every later block was dropped by
    /// `send_audio_data` and nothing re-enabled the client, because the client
    /// had already sent its `Enable` and had no reason to send another. A guest
    /// that pauses -- between two tracks of a playlist -- was audible for the
    /// first track and not the second.
    async fn begin_audio(&mut self) -> Result<()> {
        if !self.state.audio.enabled {
            return Ok(());
        }
        self.send_audio(audio::BEGIN).await
    }

    /// The format the samples go out in.
    ///
    /// What the client asked for when the server has a source to convert from
    /// and the rate matches, and the guest's own format otherwise: there is no
    /// resampler here, and a client is better served by the truth than by audio
    /// at the wrong speed.
    fn audio_format(&self) -> audio::Format {
        self.state
            .audio
            .format
            .unwrap_or(crate::audio::DEFAULT_FORMAT)
    }

    /// Send one of the audio messages that carry no samples.
    async fn send_audio(&mut self, sub: u16) -> Result<()> {
        let bytes = audio::server_message(sub);
        self.session.write_bytes(&bytes).await.map_err(rfb_error)
    }

    /// Send a block of samples, if the client is receiving them.
    async fn send_audio_data(&mut self, source: audio::Format, samples: &[u8]) -> Result<()> {
        if !self.state.audio.enabled {
            return Ok(());
        }
        // Into the format this client negotiated, which is also what
        // `audio_format()` reports: a client that asked for stereo S16 at
        // 44.1 kHz is sent stereo S16 at 44.1 kHz even when the guest is
        // producing something else. QEMU's audio backend does the same — it
        // registers each client's capture with the format that client asked
        // for, and the backend is what converts.
        let target = self.audio_format();
        let converted;
        let samples = if source == target {
            samples
        } else {
            converted = self.audio.convert(source, target, samples);
            &converted
        };
        // **Nothing converted, nothing sent.** A resampler that changes the
        // rate is stateful: `RESAMPLE_CHUNK` is 1024 input frames, and it holds
        // a whole chunk before it can emit, so a VM sending QEMU's usual
        // ten-millisecond blocks produces an empty conversion for most of them.
        // Those were being written as `255, 1, 2, 0, 0, 0, 0` -- a `DATA`
        // message carrying no samples -- which is not in the protocol and which
        // `audio_sent` counted as audio delivered.
        //
        // QEMU's own VNC server cannot produce this, which is the whole
        // difference: it registers each client's capture in the format that
        // client negotiated, so its backend converts before the capture and
        // every block arrives whole. This port receives the guest's native
        // format over D-Bus and converts per client, so the buffering is
        // unavoidable here and the empty case has to be handled rather than
        // sent.
        if samples.is_empty() {
            return Ok(());
        }
        let bytes = audio::data(samples);
        // An increment and nothing else, per the rule in `crate::counters`:
        // this runs about a hundred times a second, and a format call here is
        // the second 100% CPU this port grew.
        let counters = crate::counters::counters();
        counters.audio_sent.bump();
        counters.audio_sent_bytes.add(samples.len() as u64);
        self.session.write_bytes(&bytes).await.map_err(rfb_error)
    }

    /// Send new clipboard content to the client.
    async fn send_cut_text(&mut self, text: &str) -> Result<()> {
        // The RFB cut text is Latin-1 encoded, drop what we can not represent.
        let bytes: Vec<u8> = text.chars().map(|c| c as u32 as u8).collect();
        self.session.send(&CutText(&bytes)).await.map_err(rfb_error)
    }

    /// The event loop of a client.
    /// Serve the client until it goes away.
    ///
    /// The client stream and the events of the server are polled together:
    /// one task owns the connection, because a WebSocket or a TLS stream can
    /// not be shared with the thread that reads it.
    async fn run(mut self) {
        use crate::counters::counters;
        loop {
            // An increment, and nothing else: see `crate::counters` for why a
            // diagnostic in this crate is not allowed to grow with a frame.
            counters().client_loop.bump();
            // Handle the pending events first, so that a framebuffer update is
            // not delayed by an idle client.
            while let Ok(event) = self.events.try_recv() {
                if !self.handle(event).await {
                    return;
                }
            }
            // Then wait for the next one, or for the client to send
            // something, or for the moment a deferred update is due. The three
            // are polled by the same task: a transport that can not be
            // duplicated has no reader thread to park in.
            //
            // The deadline is what makes the rate limit a deferral rather than
            // a refusal. The guest can draw once and then go quiet, so damage
            // that arrives too soon to send cannot wait for the next request or
            // the next console event — there may not be one. QEMU has the same
            // shape, with `dcl.update_interval` driving a console refresh timer
            // that fires whether or not anything has happened.
            let (session, events) = (&mut self.session, &self.events);
            let deadline = self.state.deadline;
            enum Wake {
                Read(std::result::Result<crate::rfb::Event, crate::rfb::Error>),
                Event(std::result::Result<ClientEvent, async_channel::RecvError>),
                Refresh,
            }
            // Scoped, so the borrows of the session and the channel end with
            // the futures: the arms below need `&mut self` again, and a pinned
            // future that outlives the select would hold the borrow open.
            // **Start the idle clock here, and stop it below, rather than
            // spanning the iteration.** It used to span the iteration, with the
            // total added at the top of the next one -- and the `continue` at
            // the end of the `Wake::Refresh` arm comes straight back to that
            // top, so every deferred update added its own duration to
            // `idle_nanos`.
            //
            // So the counter named the update path as idle, and the report read
            // `idle_ms_per_interval=6596` in a 5000 ms interval, which is not
            // possible for a count of time that is not running twice over. That
            // figure is what produced `verdict="loops are idle"`, so the one
            // line whose job is to say "the CPU here is not ours" was resting on
            // a number that could not be true, and it is also why
            // `update_nanos + idle_nanos` was never this thread: it was this
            // thread plus every update.
            //
            // What is wanted is the *wait*: parked in `epoll` for a socket, or in
            // a timer for a deferred deadline. Both are below and neither is work.
            //
            // Outside the block, because the block's borrows end with it and the
            // total is added after.
            let idle_started = Instant::now();
            let wake = {
                let read = Box::pin(session.read_event()).fuse();
                let recv = Box::pin(events.recv()).fuse();
                let refresh = Box::pin(async move {
                    match deadline {
                        Some(at) => {
                            let now = Instant::now();
                            if at > now {
                                async_io::Timer::after(at - now).await;
                            }
                        }
                        // Nothing deferred: never ready, and so never
                        // cancelling the select either.
                        None => futures::future::pending().await,
                    }
                })
                .fuse();
                // `select!` polls each branch, and it wants them mutable to do
                // that; they are already pinned boxes.
                let (mut read, mut recv, mut refresh) = (read, recv, refresh);
                futures::select! {
                    result = read => Wake::Read(result),
                    event = recv => Wake::Event(event),
                    _ = refresh => Wake::Refresh,
                }
            };
            // Stopped before the `match`, so nothing below this line can be counted
            // as idle: handling the client's message, and the whole update path, are
            // work and are charged elsewhere.
            counters()
                .idle_nanos
                .add(idle_started.elapsed().as_nanos() as u64);
            let event = match wake {
                Wake::Read(Ok(event)) => ClientEvent::Vnc(event),
                // The client hung up, or sent something we can not make
                // sense of: either way it is over.
                Wake::Read(Err(e)) => {
                    debug!(id = self.id, "client read error: {e}");
                    return;
                }
                Wake::Event(Ok(event)) => event,
                Wake::Event(Err(_)) => return,
                Wake::Refresh => {
                    self.state.deadline = None;
                    // **The whole update path, from here.**
                    //
                    // `started`, inside `send_framebuffer_update`, is three lines
                    // below its first statement and it is what every `encode_ms`
                    // in this file was read off. Between the two are
                    // `Damage::rects`, `encodings.clone()`, `desktop_resize` and
                    // `send_cursor` — none of which is the encoder.
                    //
                    // Timed at the call site rather than inside, because the
                    // function has several early returns for "nothing to send" and
                    // a timer only some of them bump is a counter reporting the
                    // fast path and calling it the average. **The early returns
                    // are the interesting case**: they are the interval doing its
                    // job, and they are where a client that asks faster than the
                    // server answers spends its time.
                    let update_started = Instant::now();
                    let result = self.send_framebuffer_update().await;
                    crate::counters::counters()
                        .update_nanos
                        .add(update_started.elapsed().as_nanos() as u64);
                    if result.is_err() {
                        debug!(id = self.id, "client error sending a deferred update");
                        return;
                    }
                    continue;
                }
            };
            if !self.handle(event).await {
                return;
            }
        }
    }
}

/// The size of a pixel in an RFB pixel format, in bytes.
fn bytes_per_pixel(format: &PixelFormat) -> usize {
    (format.bits_per_pixel as usize).div_ceil(8)
}

/// A framebuffer update, ready to be sent.
///
/// The pixel data is owned: the framebuffer is composited in place, and the
/// message is written after its lock is released.
struct Update {
    rect: Rect,
    /// The encoding the data is in, `None` for raw pixels.
    codec: Option<Codec>,
    /// The bytes that follow the rectangle header and the encoding number.
    data: Vec<u8>,
    /// How many bytes they are, for the bandwidth estimate.
    bytes: usize,
}

/// Convert x8r8g8b8 pixels to an arbitrary RFB pixel format.
///
/// Returns `false` if the format is not supported.
fn convert_pixels(
    src: &[u8],
    (width, height): (u32, u32),
    format: &PixelFormat,
    out: &mut Vec<u8>,
) -> bool {
    let rect = Rect::new(
        0,
        0,
        width.min(u16::MAX as u32) as u16,
        height.min(u16::MAX as u32) as u16,
    );
    convert_pixels_rect(src, (width, height), format, rect, out).is_some()
}

/// Converts the pixels of `rect` into the client's pixel format, and reports how
/// many it converted.
///
/// **Only the rectangle, which is the entire point.** This used to convert the
/// whole framebuffer on every update, and a production viewer asks for
/// `red_shift: 0` where the framebuffer's own format is `red_shift: 16`, so it
/// took this path every time: 4.76 ms per update at 1280x800, to send a 64x64
/// rectangle. A per-update cost that does not depend on how little changed is
/// the worst kind — it survives every fix aimed at the damage, because the
/// damage is not what it is sized by. It is why fixing the bounding box changed
/// nothing for a full-screen workload, and it would have gone on surviving the
/// next four fixes.
///
/// QEMU has no such cost. Its encoders write pixels one at a time through
/// `ZRLE_WRITE_PIXEL` as they produce them, so only the pixels inside the
/// rectangle being sent are ever converted.
///
/// `out` is a whole screen's worth, screen-strided, because the encoder indexes
/// it with `RectPixels`, which offsets by the rectangle and reads nothing
/// outside it. Only the rectangle's rows are written and only the rectangle is
/// read; the rest of `out` is stale, and a test asserts the rectangle's bytes
/// match a whole-frame conversion so that the two cannot drift apart.
fn convert_pixels_rect(
    src: &[u8],
    (width, height): (u32, u32),
    format: &PixelFormat,
    rect: Rect,
    out: &mut Vec<u8>,
) -> Option<usize> {
    if !format.true_colour || !matches!(format.bits_per_pixel, 8 | 16 | 32) || format.big_endian {
        warn!(?format, "unsupported client pixel format");
        return None;
    }
    let rect = rect.clipped(
        width.min(u16::MAX as u32) as u16,
        height.min(u16::MAX as u32) as u16,
    );
    if rect.width == 0 || rect.height == 0 {
        return Some(0);
    }

    // The shape every real viewer asks for: 32 bits a pixel, the full 0-255
    // range in each channel, and little endian. Everything else is rare enough
    // to be worth a slow path.
    //
    // **This is the cost the whole `encodings.rs` file was blind to.** The
    // production viewer asks for `red_shift: 0, green_shift: 8, blue_shift: 16`
    // — BGRX, the reverse of the framebuffer's own layout — so it takes this
    // branch on every single update, and every benchmark in this crate measured
    // the fast path that skips it. Measured at 3.0-3.9 ns a pixel, which is 6%
    // to 12% of the 12.3 ms a production update spends encoding, and it was in
    // none of the arithmetic above.
    //
    // `convert_pixels_rect_general` stays as the definition of correct: it is
    // what the fast path is checked against, byte for byte, over every format
    // and rectangle the tests can think of. A faster path that nobody checks
    // against the slow one is a second implementation, and this file has
    // already been bitten by one of those.
    if format.bits_per_pixel == 32
        && format.red_max == 255
        && format.green_max == 255
        && format.blue_max == 255
    {
        return convert_rows_32(src, (width, height), format, rect, out);
    }
    convert_pixels_rect_general(src, (width, height), format, rect, out)
}

/// Convert a rectangle a row at a time, in slices.
///
/// The same arithmetic as [`convert_pixels_rect_general`], reorganised so that
/// the index maths happens once per row and the inner loop touches two slices
/// and nothing else — no `Option` per pixel, no `pixels.get`, no re-deriving
/// `y * stride` on every pixel. That is what lets it vectorise, and vectorising
/// is the whole of the win: the general loop is branchy and bounds-checked per
/// pixel, this one is a permute of four bytes.
fn convert_rows_32(
    src: &[u8],
    (width, height): (u32, u32),
    format: &PixelFormat,
    rect: Rect,
    out: &mut Vec<u8>,
) -> Option<usize> {
    let screen_stride = width as usize * 4;
    out.resize(screen_stride * height as usize, 0);
    let (red_shift, green_shift, blue_shift) = (
        format.red_shift as usize,
        format.green_shift as usize,
        format.blue_shift as usize,
    );
    let row_bytes = usize::from(rect.width) * 4;
    let mut converted = 0usize;
    for y in rect.top..rect.top + rect.height {
        let o = y as usize * screen_stride + usize::from(rect.left) * 4;
        let (Some(source), Some(target)) =
            (src.get(o..o + row_bytes), out.get_mut(o..o + row_bytes))
        else {
            warn!(y, "row outside the framebuffer");
            return None;
        };
        // `as_chunks` rather than `chunks_exact(..).zip(chunks_exact_mut(..))`.
        // Both slices are `row_bytes`, which is `width * 4`, so neither has a
        // remainder -- and if one did, silently dropping it would be exactly
        // the sort of thing a stride mistake produces, so the remainders are
        // named rather than ignored.
        let (source, source_rest) = source.as_chunks::<4>();
        let (target, target_rest) = target.as_chunks_mut::<4>();
        if !source_rest.is_empty() || !target_rest.is_empty() {
            warn!("a row of {row_bytes} bytes is not a whole number of pixels");
            return None;
        }
        for (s, d) in source.iter().zip(target.iter_mut()) {
            let (blue, green, red) = (s[0], s[1], s[2]);
            let value = (red as u32) << red_shift
                | (green as u32) << green_shift
                | (blue as u32) << blue_shift;
            d.copy_from_slice(&value.to_le_bytes());
            converted += 1;
        }
    }
    Some(converted)
}

/// The original, pixel-at-a-time conversion, kept as the reference.
///
/// Deliberately not optimised: it is what `convert_rows_32` is checked against,
/// and a reference that shares code with the thing it is checking is not a
/// reference.
fn convert_pixels_rect_general(
    src: &[u8],
    (width, height): (u32, u32),
    format: &PixelFormat,
    rect: Rect,
    out: &mut Vec<u8>,
) -> Option<usize> {
    let bytes_per_pixel = bytes_per_pixel(format);
    // The screen's stride, not the rectangle's: `RectPixels` is handed this
    // buffer with the screen stride and offsets by the rectangle itself, so a
    // rectangle-shaped buffer would be read at the wrong place.
    let screen_stride = width as usize * bytes_per_pixel;
    out.resize(screen_stride * height as usize, 0);
    let (pixels, _) = src.as_chunks::<4>();
    // Counted as it goes, and not derived from the rectangle afterwards. A first
    // version returned `rect.width * rect.height`, which is the count the
    // function *should* have done, and a mutation that converted the whole
    // framebuffer while leaving that expression alone passed the test that
    // exists precisely to catch it. A number computed from what was asked for
    // cannot check what was done; only one counted on the way can.
    let mut converted = 0usize;
    for y in rect.top..rect.top + rect.height {
        for x in rect.left..rect.left + rect.width {
            let i = y as usize * width as usize + x as usize;
            let Some(pixel) = pixels.get(i) else {
                warn!(i, "pixel outside the framebuffer");
                return None;
            };
            let (red, green, blue) = (pixel[2], pixel[1], pixel[0]);
            let value = (red as u32 & format.red_max as u32) << format.red_shift
                | (green as u32 & format.green_max as u32) << format.green_shift
                | (blue as u32 & format.blue_max as u32) << format.blue_shift;
            let o = y as usize * screen_stride + x as usize * bytes_per_pixel;
            // Little endian, because a big endian client was refused above: the
            // client reads a pixel as a number from the wire in *its* byte order,
            // and RFB says that is the host order, which for a client that did not
            // ask otherwise is little.
            //
            // Two things went wrong here before, and the second only shows up once
            // the first is fixed. The bytes were written big-endian, which put red
            // in the wrong byte for every client with `red_shift: 0` — the order
            // reversed from ours — so a red pixel went out as `[0, 0, 0, 255]` and
            // that client read black. And a pixel narrower than four bytes was cut
            // from the wrong end of the value: `[4 - n..]` is the top half, which
            // is what you want when the bytes are big-endian and the wrong half
            // when they are not, so a 16 bit client got two zero bytes. The low
            // `bytes_per_pixel` bytes are the whole of a little-endian pixel.
            out[o..o + bytes_per_pixel].copy_from_slice(&value.to_le_bytes()[..bytes_per_pixel]);
            converted += 1;
        }
    }
    Some(converted)
}

/// A `ServerCutText` RFB message.
struct CutText<'a>(&'a [u8]);

impl crate::rfb::ServerMessage for CutText<'_> {
    fn write_to<W: std::io::Write>(&self, writer: &mut W) -> crate::rfb::Result<()> {
        writer.write_all(&[3, 0, 0, 0])?;
        writer.write_all(&(self.0.len() as u32).to_be_bytes())?;
        writer.write_all(self.0)?;
        Ok(())
    }
}

/// Handle a new client, from the RFB handshake to the disconnection.
///
/// The whole thing runs in one task: the handshake, then the loop that reads
/// the client and sends the updates on the same stream. It is driven by
/// `async_io::block_on`, whose reactor is what makes the socket readable
/// without a thread parked in a read.
pub(super) fn client_thread(
    server: Server,
    id: ClientId,
    stream: ClientTransport,
    events: Receiver<ClientEvent>,
    jpeg_quality: Option<u8>,
) {
    let dimensions = server
        .default_display()
        .map(|d| d.framebuffer())
        .map(|fb| fb.with(Framebuffer::dimensions))
        .unwrap_or((640, 480));

    block_on(async move {
        // The password may expire while the client is being served, so take
        // it for the duration of the handshake only.
        let password = server.password();
        let name = server.name();
        // SASL takes precedence over the password, as it does in QEMU: it is
        // the stronger of the two, and a client is offered one or the other.
        // The offered mechanisms are held by the server, so the clone of the
        // configuration is only read: what is offered is the same for every
        // client.
        let sasl = server.sasl();
        let options = match sasl.as_ref().filter(|sasl| !sasl.mechanisms.is_empty()) {
            Some(sasl) => ServerOptions::with_sasl(name, pixman_xrgb(), &sasl.mechanisms),
            None => match &password {
                Some(password) => ServerOptions::authenticated(name, pixman_xrgb(), password),
                None => ServerOptions::anonymous(name, pixman_xrgb()),
            },
        };
        // A SASL mechanism is told where the client connected from, which is
        // the one thing the handshake needs that the options do not carry.
        let endpoints = stream.endpoints().unwrap_or_default();
        let options = options.at(endpoints);
        let (session, handshake) = match TcpSession::from_stream(
            stream,
            dimensions.0 as u16,
            dimensions.1 as u16,
            options,
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                debug!(id, "RFB handshake failed: {e}");
                server.remove_client(id);
                return;
            }
        };

        // The handle can shut the connection down from another thread, which
        // is how a client is disconnected: the task is parked on its stream,
        // not on a channel.
        if let Some(handle) = server.inner.clients.read().unwrap().get(&id) {
            *handle.disconnect.write().unwrap() = Some(Disconnect::new(&session));
            // The name a SASL exchange established is reported over D-Bus, and
            // it is only known now, after the handshake: the client was
            // announced as connected before it proved anything.
            if let Some(credentials) = &handshake.credentials {
                *handle.info.sasl_username.write().unwrap() = credentials.username.clone();
            }
        }
        let _ = server
            .inner
            .events
            .try_send(ServerEvent::ClientInitialized(id));
        info!(
            id,
            shared = handshake.shared,
            mechanism = ?handshake.credentials.as_ref().and_then(|c| c.mechanism.as_ref()),
            ssf = handshake.credentials.as_ref().map(|c| c.ssf).unwrap_or(0),
            // What an `ANONYMOUS` client has to say about itself, which is the
            // only thing that mechanism gives an administrator to go on.
            sasl = ?handshake.credentials.as_ref().and_then(|c| c.description.as_ref()),
            websocket = session.is_websocket(),
            "client initialized"
        );

        // A SASL client is checked against the authorization list, which is
        // what its username is for.
        if let Some(credentials) = &handshake.credentials
            && !server.sasl_authz().check(credentials.username.as_str())
        {
            info!(
                id,
                username = %credentials.username,
                "client is not authorized to connect"
            );
            server.disconnect_client(id);
            server.remove_client(id);
            return;
        }

        // Enforce the sharing policy.
        if server.inner.share == Share::AllowExclusive && !handshake.shared {
            for (other, handle) in server.inner.clients.read().unwrap().iter() {
                if *other != id {
                    info!(other, "disconnecting client for exclusive access");
                    let _ = handle.events.try_send(ClientEvent::Terminate);
                    handle.disconnect();
                }
            }
        }

        let display = server
            .inner
            .displays
            .read()
            .unwrap()
            .keys()
            .next()
            .copied()
            .unwrap_or_default();
        let server_ref = server.clone();
        let mut client = Client {
            id,
            server,
            session,
            state: ClientState {
                incremental: true,
                display,
                dimensions: (0, 0),
                pixel_format: pixman_xrgb(),
                encodings: Vec::new(),
                last_update: None,
                // Start at the floor rather than at zero: a client that has
                // just connected gets its first frame at once, and the interval
                // only grows from there if it proves it cannot keep up.
                refresh_interval: REFRESH_BASE,
                deadline: None,
                // A new client has no content: send the console as soon as
                // it asks for it.
                damage: Damage::Full,
                req_update: false,
                cursor: None,
                pointer: PointerState::default(),
                pointer_absolute: true,
                modifiers: ModifierState::default(),
                audio: AudioState::default(),
            },
            encoders: Encoders::new(jpeg_quality),
            events,
            scratch: Vec::new(),
            audio: crate::audio::Converter::new(),
        };
        client.state.pointer_absolute = client.is_absolute().await;
        client.run().await;
        debug!(id, "client disconnected");
        server_ref.remove_client(id);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A framebuffer pixel in the server's own x8r8g8b8: B, G, R, and an
    /// unused byte.
    fn xrgb(red: u8, green: u8, blue: u8) -> [u8; 4] {
        [blue, green, red, 0]
    }

    /// Read a converted pixel back the way a client would: a number in its byte
    /// order, channels pulled out with its shifts.
    fn decode(data: &[u8], format: &PixelFormat) -> [u8; 3] {
        let width = format.bits_per_pixel as usize / 8;
        let value = match (width, format.big_endian) {
            (2, false) => u32::from(u16::from_le_bytes([data[0], data[1]])),
            (2, true) => u32::from(u16::from_be_bytes([data[0], data[1]])),
            (4, false) => u32::from_le_bytes(data[..4].try_into().unwrap()),
            (4, true) => u32::from_be_bytes(data[..4].try_into().unwrap()),
            other => panic!("no decoding for {other:?}"),
        };
        [
            ((value >> format.red_shift) & format.red_max as u32) as u8,
            ((value >> format.green_shift) & format.green_max as u32) as u8,
            ((value >> format.blue_shift) & format.blue_max as u32) as u8,
        ]
    }

    fn convert_one(red: u8, green: u8, blue: u8, format: &PixelFormat) -> [u8; 3] {
        let src = xrgb(red, green, blue);
        let mut out = Vec::new();
        assert!(convert_pixels(&src, (1, 1), format, &mut out));
        decode(&out, format)
    }

    #[test]
    fn a_client_with_the_same_byte_order_gets_the_colour() {
        // The server's own format: red at 16, so red is the third byte.
        let format = pixman_xrgb();
        assert_eq!(convert_one(0x11, 0x22, 0x33, &format), [0x11, 0x22, 0x33]);
    }

    #[test]
    fn a_client_with_the_other_byte_order_gets_the_colour() {
        // The format a real viewer asked for, which has red in the *first*
        // byte. This is the case that went out as black: the conversion wrote
        // big-endian bytes into a little-endian format, so a red pixel became
        // `[0, 0, 0, 255]` and this client read nothing at all out of it.
        let format = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        assert_eq!(convert_one(0x11, 0x22, 0x33, &format), [0x11, 0x22, 0x33]);
        // And the one that showed it most clearly: pure red, whose big-endian
        // form is all zeroes but the last byte.
        assert_eq!(convert_one(0xff, 0x00, 0x00, &format), [0xff, 0x00, 0x00]);
        assert_eq!(convert_one(0x00, 0xff, 0x00, &format), [0x00, 0xff, 0x00]);
        assert_eq!(convert_one(0x00, 0x00, 0xff, &format), [0x00, 0x00, 0xff]);
    }

    #[test]
    fn a_sixteen_bit_client_gets_its_channels_scaled() {
        // RGB565: the channels are not shifted into place whole, they are
        // scaled to the maxima, so green has twice the range of the others.
        let format = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..pixman_xrgb()
        };
        let got = convert_one(0xff, 0xff, 0xff, &format);
        assert_eq!(
            got,
            [31, 63, 31],
            "a white pixel is the largest each channel"
        );
        assert_eq!(convert_one(0x00, 0x00, 0x00, &format), [0, 0, 0]);
    }

    #[test]
    fn a_big_endian_client_is_refused_rather_than_mangled() {
        // `convert_pixels` says so in its own guard, and returns false so the
        // update is skipped rather than sent in the wrong order.
        let format = PixelFormat {
            big_endian: true,
            ..pixman_xrgb()
        };
        let mut out = Vec::new();
        assert!(!convert_pixels(&xrgb(1, 2, 3), (1, 1), &format, &mut out));
    }
}

#[cfg(test)]
mod cost_tests {
    use std::collections::HashSet;

    use super::convert_pixels_rect_general;
    use super::{Damage, convert_pixels, convert_pixels_rect, pixman_xrgb};
    use crate::display::Coalescer;
    use crate::rfb::encodings::Zlib;
    use crate::rfb::protocol::Rect;
    use crate::rfb::{Codec, Encoders, Encoding, PixelFormat};

    /// What the pixel-format conversion costs, and what it costs per update.
    ///
    /// This is the last of the CPU hunt, and it was in the encode path the whole
    /// time, in one line:
    ///
    /// ```ignore
    /// if !convert_pixels(fb.data(), fb.dimensions(), pixel_format, &mut self.scratch)
    /// ```
    ///
    /// The whole *framebuffer*, on every update, whenever the client's pixel
    /// format is not byte-for-byte `pixman_xrgb()`. A production viewer asks for
    /// `red_shift: 0` where the fast path is `red_shift: 16`, so it took the
    /// converting path on every single update — and converted 1,024,000 pixels
    /// to send a 64x64 rectangle. That is a per-update cost *independent of how
    /// little changed*, so thirty updates a second is thirty-one million pixel
    /// conversions a second and no amount of making the encode cheaper touches
    /// it. It is also why fixing the damage rectangles changed nothing for this
    /// workload: the conversion is per update, not per pixel of damage.
    ///
    /// QEMU has no such cost: its encoders write pixels one at a time through
    /// `ZRLE_WRITE_PIXEL` as they go, so only the pixels inside the rectangle
    /// being sent are ever converted.
    ///
    /// **Run this in release.** ```sh
    /// cargo test -p qemu-vnc --release --lib what_the_pixel_conversion_costs -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn what_the_pixel_conversion_costs() {
        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 20;

        // The same content the other cost measurements use.
        let source: Vec<u8> = (0..usize::from(W) * usize::from(H) * 4)
            .map(|i| match i % 4 {
                0 => (i / 4) as u8,
                1 => ((i / 4) % 251) as u8,
                2 => ((i / 4) / 251) as u8,
                _ => 0,
            })
            .collect();
        let mut out = Vec::new();

        // The format the production viewer asked for: the same depths and maxima
        // as the fast path, and the opposite channel order.
        let viewer = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        assert_ne!(
            viewer,
            pixman_xrgb(),
            "the two formats must differ, or this is measuring the fast path"
        );

        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            assert!(convert_pixels(
                &source,
                (u32::from(W), u32::from(H)),
                &viewer,
                &mut out
            ));
        }
        let each = started.elapsed().as_secs_f64() / f64::from(ROUNDS);
        println!(
            "\n  one 1280x800 frame, converted whole, release build\n\n  \
             {:>7.2} ms per update  {:>6.1} Mpixel/s  {} bytes out\n\n  \
             so at thirty updates a second this is {:>5.0} ms of every second, \
             spent converting\n  pixels that were not sent. A 64x64 damage rect costs exactly \
             the same,\n  because the conversion is of the whole framebuffer and not of the \
             rectangle.\n",
            each * 1000.0,
            f64::from(u32::from(W) * u32::from(H)) / each / 1e6,
            out.len(),
            each * 30.0 * 1000.0,
        );
    }

    /// What the fast conversion is worth, measured on production's shape.
    ///
    /// The production viewer asks for `red_shift: 0, green_shift: 8, blue_shift: 16`,
    /// so it takes the converting path on every update, and every other benchmark
    /// in this crate measured the path that skips it. Measured on a debug build
    /// this says nothing at all — `pixel_to_xrgb` alone was 40 ns a pixel there —
    /// so the numbers below are release only and the test is `#[ignore]`d for the
    /// same reason as the others in this file.
    ///
    /// Both arms are the same function's two implementations, on the same bytes,
    /// so the only difference is how they walk them. That is the whole claim:
    /// a per-row slice loop against a per-pixel `Option` loop.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_the_fast_conversion_is_worth() {
        use std::time::Instant;

        /// The production log's own arithmetic: 1280x308, 12.32 ms an update of
        /// which this is a part.
        const W: u16 = 1280;
        const H: u16 = 308;
        const LOG_ENCODE_MS: f64 = 12.32;
        const ROUNDS: u32 = 40;

        let format = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        let screen = (u32::from(W), u32::from(H));
        let source: Vec<u8> = (0..usize::from(W) * usize::from(H) * 4)
            .map(|i| (i / 3) as u8)
            .collect();
        let rect = Rect::new(0, 0, W, H);
        let px = f64::from(W) * f64::from(H);

        let time = |general: bool| {
            let mut out = Vec::new();
            // One warm-up round, excluded: the first call is what pays for the
            // allocation and for the branch predictor learning nothing.
            let mut run = || {
                let started = Instant::now();
                for _ in 0..ROUNDS {
                    let converted = if general {
                        convert_pixels_rect_general(&source, screen, &format, rect, &mut out)
                    } else {
                        convert_pixels_rect(&source, screen, &format, rect, &mut out)
                    };
                    assert_eq!(converted, Some(px as usize));
                }
                started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0
            };
            run();
            run()
        };

        let slow = time(true);
        let fast = time(false);

        println!(
            "\n{W}x{H} ({px:.0} px), BGRX red_shift=0:\n               per pixel (reference) {slow:>6.3} ms  {:>5.2} ns/px\n               per row (fast)        {fast:>6.3} ms  {:>5.2} ns/px\n               saved                 {:>6.3} ms  {:>5.2} ns/px               = {:.1}% of the log's {LOG_ENCODE_MS:.2} ms encode",
            slow * 1e6 / px,
            fast * 1e6 / px,
            slow - fast,
            (slow - fast) * 1e6 / px,
            100.0 * (slow - fast) / LOG_ENCODE_MS,
        );

        assert!(
            fast < slow,
            "the per-row loop cost {fast:.3} ms and the per-pixel loop {slow:.3} ms, so \
             reorganising the iteration made it *slower*. Either the win is not there \
             or this measurement is not measuring it, and both are worth knowing."
        );
        // Half, as the bar for "worth a second implementation to keep correct".
        //
        // This assertion was written backwards the first time — it fired when the
        // saving was *large* — which is the same mistake as the u16 overflow in
        // the sweep above: a comparison written from the shape of the sentence
        // rather than from the direction of the inequality. It is worth checking
        // every assertion in this file for the same.
        assert!(
            (slow - fast) * 1e6 / px >= slow * 1e6 / px * 0.5,
            "the fast path saved only {:.1} ns a pixel out of {:.1}, which is not worth a \
             second implementation to keep correct. Measured {:.1} against {:.1} ns/px.",
            (slow - fast) * 1e6 / px,
            slow * 1e6 / px,
            fast * 1e6 / px,
            slow * 1e6 / px
        );
    }

    /// How many ZRLE tiles take the raw path, on content like production's.
    ///
    /// A tile with more than 16 colours goes out as sub-encoding 0: three bytes
    /// a pixel, unpacked, straight into the deflate stream. That is the most
    /// expensive thing the ZRLE encoder does and it is the path a video surface
    /// lives on — a decoded frame has thousands of colours in every 64x64 block.
    ///
    /// So the question is not whether the path exists but **how much of the
    /// workload is on it**, and nothing in this file could answer that: the
    /// encoder does not report which sub-encoding it chose. So this counts it
    /// from the frame, which is exact and needs no cooperation from the encoder.
    ///
    /// It is the same census the compressibility sweep needs. A frame where
    /// every tile is raw and a frame where every tile is a sixteen-colour
    /// palette compress to similar sizes — one is 3 bytes a pixel before
    /// deflate, the other 1 + palette + 1 index — and cost wildly different
    /// amounts, which is why "bytes a pixel" and "nanoseconds a pixel" are not
    /// the same measurement.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn how_much_of_a_video_frame_takes_the_raw_path() {
        const W: u16 = 1280;
        const H: u16 = 308;
        /// ZRLE's tile, and the palette limit that sends a tile the raw way.
        const TILE: usize = 64;
        const PALETTE: usize = 16;

        // Distinct colours a tile holds, sorted and deduped rather than marked
        // in a 2^24 table: that table is 16 MB and putting it on the stack
        // overflows the thread, which is what the first version of this did.
        // A census is not a hot loop and clarity is worth more than the
        // microseconds.
        let distinct = |frame: &[u8], tx: usize, ty: usize| -> usize {
            let mut colours = Vec::with_capacity(TILE * TILE);
            for y in ty..(ty + TILE).min(usize::from(H)) {
                for x in tx..(tx + TILE).min(usize::from(W)) {
                    let o = (y * usize::from(W) + x) * 4;
                    // The three colour bytes, which is what the palette is
                    // keyed on, and not the fourth.
                    colours.push(
                        ((frame[o] as u32) << 16)
                            | ((frame[o + 1] as u32) << 8)
                            | frame[o + 2] as u32,
                    );
                }
            }
            colours.sort_unstable();
            colours.dedup();
            colours.len()
        };

        let census = |frame: &[u8]| {
            let (mut raw, mut palette_tiles, mut solid) = (0usize, 0usize, 0usize);
            for ty in (0..usize::from(H)).step_by(TILE) {
                for tx in (0..usize::from(W)).step_by(TILE) {
                    match distinct(frame, tx, ty) {
                        0 => {}
                        1 => solid += 1,
                        used if used > PALETTE => raw += 1,
                        _ => palette_tiles += 1,
                    }
                }
            }
            (raw, palette_tiles, solid)
        };

        println!("\n{W}x{H}, tiles of {TILE}x{TILE}, palette limit {PALETTE}:");
        for grain in [2i32, 8, 20, 48, 127] {
            let frame = video_frame_with_grain(W, H, 7, grain);
            let (raw, pal, sol) = census(&frame);
            let total = raw + pal + sol;
            println!(
                "  grain {grain:>3}  {:>5.1}% raw  {:>5.1}% palette  {:>5.1}% solid                   ({raw}/{pal}/{sol} of {total} tiles)",
                100.0 * raw as f64 / total as f64,
                100.0 * pal as f64 / total as f64,
                100.0 * sol as f64 / total as f64,
            );
        }
        println!(
            "\n  production compresses to 1.888 bytes/px, which is above what a \
             sixteen-colour palette reaches and so cannot be entirely on that path. \
             The raw path is where the remaining nanoseconds are, and the census \
             says how much of it."
        );
    }

    /// What the raw ZRLE sub-encoding costs a pixel, isolated.
    ///
    /// `how_much_of_a_video_frame_takes_the_raw_path` says a video frame puts
    /// **every** tile on sub-encoding 0, so this is not a branch that is rarely
    /// taken — it is the one the workload lives on. It writes three bytes a
    /// pixel straight into the deflate stream, and it is the only part of the
    /// ZRLE encoder whose cost does not fall out of the palette machinery.
    ///
    /// Three frames of the same size differing only in how many colours each
    /// tile holds, so the sub-encoding is the only variable: one colour a tile
    /// is sub-encoding 1, sixteen is a palette and an index, more than sixteen
    /// is three bytes a pixel.
    ///
    /// They do not compress alike, and that is the point: the third is both the
    /// slowest and, on hard content, the largest. The first two bracket what the
    /// palette path costs and the third says what the raw path adds on top of
    /// the deflate that follows it.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_the_raw_zrle_subencoding_costs() {
        use std::time::Instant;

        const W: u16 = 1280;
        const H: u16 = 308;
        const LEVEL: u32 = 2;
        const ROUNDS: u32 = 15;

        let bgrx = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        let rect = Rect::new(0, 0, W, H);
        let offered = HashSet::from([Encoding::Zrle]);
        let px = f64::from(W) * f64::from(H);

        // A frame where every 64x64 tile holds exactly `colours` distinct values.
        let tiled = |colours: u32| {
            let mut data = vec![0u8; usize::from(W) * usize::from(H) * 4];
            for y in 0..usize::from(H) {
                for x in 0..usize::from(W) {
                    let v = (((y % 64) * 64 + (x % 64)) as u32) % colours.max(1);
                    let o = (y * usize::from(W) + x) * 4;
                    data[o] = (v * 7) as u8;
                    data[o + 1] = (v * 13) as u8;
                    data[o + 2] = (v * 29) as u8;
                    data[o + 3] = 0;
                }
            }
            data
        };

        println!("\n{W}x{H} ({px:.0} px), ZRLE level {LEVEL}:");
        let mut raw_ns = 0.0;
        for (label, colours) in [
            ("solid, 1 colour a tile ", 1u32),
            ("palette, 16 a tile     ", 16),
            ("raw, 4096 a tile      ", 4096),
        ] {
            let frame = tiled(colours);
            let source = pixels_in(&frame, W, H, &bgrx);
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(LEVEL);
            let (_, warm) = encoders
                .encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect)
                .expect("zrle");
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ =
                    encoders.encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect);
            }
            let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            let ns = ms * 1e6 / px;
            if colours > 16 {
                raw_ns = ns;
            }
            println!(
                "  {label}  {ms:>6.2} ms  {ns:>5.1} ns/px  {:>6.3} bytes/px",
                warm.len() as f64 / px
            );
        }
        println!(
            "  the raw path costs {raw_ns:.1} ns/px; the log's whole encode is 46.7 ns/px, \
             so this is {:.0}% of it",
            100.0 * raw_ns / 46.7
        );

        // **Deflate alone, on the bytes ZRLE actually hands it.** Three bytes a
        // pixel for a raw tile, so the input is exactly the tile stream.
        //
        // This is where the rest of the log's 46.7 ns/pixel has to be. The raw
        // path above writes 3 bytes a pixel and costs 6.3 ns/pixel; production
        // compresses to 1.888 bytes a pixel, which means deflate is working on
        // data it cannot compress — the opposite of the fixture above, which
        // deflate crushes to 0.059 and which is therefore flattering the raw
        // path by measuring almost none of deflate's real work.
        //
        // Three inputs, same size, three compressibilities: the tiled fixture
        // above, a video-shaped frame, and the same frame with its grain turned
        // up until it reaches the log's 1.888 bytes/px. If deflate on the last
        // of those is most of 46.7, then the residual is the compressor and
        // there is nothing left in this crate's code to win.
        let mut deflate_share = Vec::new();
        println!("\n  deflate alone, on three bytes a pixel of:\n");
        for (label, frame) in [
            ("the tiled fixture   ", tiled(4096)),
            ("video, grain 8      ", video_frame_with_grain(W, H, 7, 8)),
            ("video, grain 127    ", video_frame_with_grain(W, H, 7, 127)),
        ] {
            // Exactly what sub-encoding 0 writes: three bytes a pixel.
            let packed: Vec<u8> = frame
                .as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[0], p[1], p[2]])
                .collect();
            let mut zlib = Zlib::with_level(LEVEL);
            let out = zlib.compress(&packed);
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = zlib.compress(&packed);
            }
            let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            let ns = ms * 1e6 / px;
            deflate_share.push(ns);
            println!(
                "    {label} {:>5.3} bytes/px out  {:>6.2} ms  {:>5.1} ns/px  \
                 ({:>4.0} MB/s)",
                out.len() as f64 / px,
                ms,
                ns,
                packed.len() as f64 / 1e6 / (ms / 1000.0)
            );
        }
        println!(
            "\n  the log's whole encode is 46.7 ns/px. Deflate alone on the hardest of \
             these is {:.1} ns/px, which is {:.0}% of it, and the raw tiling adds \
             {:.1}. The rest is the palette machinery, which a video frame barely \
             touches.",
            deflate_share[2],
            100.0 * deflate_share[2] / 46.7,
            raw_ns,
        );

        assert!(
            raw_ns > 1.0,
            "the raw sub-encoding measured {raw_ns:.2} ns/px, too fast to be the path a \
             video frame spends its time on. The fixture is probably not producing \
             many-coloured tiles and every number here would be wrong."
        );
    }

    /// What coalescing the per-row damage runs is worth, and what it is not.
    ///
    /// `Coalescer` in `display.rs` was added for a reason that turned out to be
    /// false — that without it 800 rows of ten runs would blow past
    /// `MAX_DAMAGE_RECTS` and degrade to the whole framebuffer. They would not:
    /// `Damage` merges each rectangle in as it arrives, so the list holds ten
    /// entries however many rows go by. A mutation that deletes `Coalescer`
    /// outright survives every wire test, which is how the false reason was
    /// caught.
    ///
    /// So this measures what is actually left. Both arms produce the same
    /// rectangles and the same wire bytes; the difference is the number of
    /// `part` calls and how much merging each one does. The coalesced arm is
    /// twenty calls on a growing list; the per-row arm is sixteen thousand,
    /// each restarting an O(n) scan with a restart-on-contact rule.
    ///
    /// Run in release: at these sizes a debug build says nothing.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_coalescing_the_rows_is_worth() {
        use std::time::Instant;

        const W: u16 = 1280;
        const H: u16 = 800;
        /// How many of the screen's 64-pixel bands changed, every row.
        const BANDS: u16 = 10;

        // Every *other* 64-pixel band, so the ten rectangles stay ten. Bands
        // that touch are one band: a first run of this measurement used twenty
        // adjacent ones, `Damage` merged them into a single 1280-wide
        // rectangle, and the fixture was measuring one run where it claimed to
        // measure twenty. The assertion at the end is what noticed.
        let spans: Vec<(u16, u16)> = (0..BANDS).map(|i| (i * 128, 64)).collect();
        let rows: Vec<Vec<(u16, u16)>> = vec![spans.clone(); H as usize];

        // Arm one: the rows as they come off the comparison.
        let started = Instant::now();
        let mut per_row = Damage::None;
        for (y, row) in rows.iter().enumerate() {
            for &(left, width) in row {
                per_row.part(Rect::new(left, y as u16, width, 1));
            }
        }
        let per_row_ns = started.elapsed().as_nanos();
        let per_row_rects = per_row.rects(W, H).len();

        // Arm two: the same rows, coalesced first.
        let started = Instant::now();
        let mut coalescer = Coalescer::default();
        for (y, row) in rows.iter().enumerate() {
            coalescer.row(y as u32, row.clone());
        }
        let coalesced = coalescer.finish();
        let coalesce_ns = started.elapsed().as_nanos();
        let mut coalesced_damage = Damage::None;
        for rect in &coalesced {
            coalesced_damage.part(*rect);
        }
        let merged_ns = started.elapsed().as_nanos() - coalesce_ns;
        let coalesced_rects = coalesced_damage.rects(W, H).len();

        println!(
            "{W}x{H}, {BANDS} bands:\n  \
             per row:     {} calls on Damage::part, {per_row_ns} ns ({:.1} ns/call)\n  \
             coalesced:   {} rects, {coalesce_ns} ns coalescing ({:.1} ns/row) \
             + {merged_ns} ns merging ({:.1} ns/rect)\n  \
             end to end:  {} ns vs {} ns",
            H as usize * BANDS as usize,
            per_row_ns as f64 / (H as f64 * BANDS as f64),
            coalesced.len(),
            coalesce_ns as f64 / H as f64,
            merged_ns as f64 / coalesced.len().max(1) as f64,
            per_row_ns,
            coalesce_ns + merged_ns,
        );

        assert_eq!(
            per_row_rects, coalesced_rects,
            "the two arms disagree on the shape of the damage, so this is \
             comparing two different things and the timings mean nothing"
        );
        assert_eq!(
            per_row_rects, BANDS as usize,
            "a frame with {BANDS} changed bands every row ended up as \
             {per_row_rects} rectangles, so the fixture is not the shape it \
             claims to be"
        );
    }

    /// What production actually costs, on production's shape, and where it goes.
    ///
    /// The production log says **46.6 ns a pixel**: `encode_ms_per_interval=1121`
    /// over 91 updates and `damage_per_interval=23995456`. The release benchmark
    /// in this file says 18-22 ns a pixel on `photographic` content. Those two
    /// numbers are 2 to 2.6 apart and the gap is the largest single thing left
    /// in the profile, so this measures the same encode under the conditions the
    /// log actually records:
    ///
    /// - **the shape**: 1280x308, which is 135 of the 191 updates in the log.
    ///   Not 1280x800 — the frame is a band, and a full-screen figure would be
    ///   measuring something the log does not contain.
    /// - **the codec and level**: ZRLE at deflate level 2, which is what the
    ///   `sending framebuffer update encoding=16 level=2` line says.
    /// - **the pixel format**: the viewer's `red_shift: 0, green_shift: 8,
    ///   blue_shift: 16`, which is BGRX and is *not* the framebuffer's own
    ///   layout. That makes `convert_pixels_rect` run on every update, and every
    ///   other measurement in this file is on the fast path that skips it.
    /// - **the content**: decoded video, which is neither the smooth gradient
    ///   nor the high-entropy middle band that `photographic` is built from.
    ///
    /// **And the content is checked rather than assumed.** Compression depends
    /// on the pixels, so a synthetic frame that compresses to 0.4 bytes a pixel
    /// would time a different codec than the one in production. The log gives
    /// the number to check against: `bytes_per_interval=45308189` over
    /// `damage_per_interval=23995456` is **1.889 bytes a pixel**. If this frame
    /// does not land near that, its timings do not describe the workload and the
    /// honest reading is that the content is still unknown, not that the encoder
    /// is slow.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_production_costs_and_where_it_goes() {
        use std::time::Instant;

        /// The log's own numbers, so this test cannot be read without them.
        const LOG_NS_PER_PIXEL: f64 = 1121.0 / 91.0 * 1e6 / 263_686.0;
        const LOG_BYTES_PER_PIXEL: f64 = 45_308_189.0 / 23_995_456.0;
        const LOG_ENCODE_MS: f64 = 1121.0 / 91.0;

        const W: u16 = 1280;
        const H: u16 = 308;
        const LEVEL: u32 = 2;
        const ROUNDS: u32 = 15;

        let native = pixman_xrgb();
        let bgrx = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..native
        };
        let rect = Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };
        let pixels = video_frame(W, H, 7);
        let offered = HashSet::from([Encoding::Zrle]);
        // Widened *before* the multiply, not after. `1280 * 308` is 394,240,
        // which does not fit in a `u16`, and the first version of this line
        // wrapped to 1,024 — so every nanoseconds-per-pixel figure below was
        // 385 times too large and the bytes-per-pixel check, which is what
        // validates the content, was reading 280 instead of 0.71.
        let px = f64::from(W) * f64::from(H);

        // The encode, in each pixel format, with the bytes it produced.
        //
        // `Encoders::encode` is handed pixels already in the client's layout,
        // so the conversion is *outside* it — measured separately below rather
        // than folded in, because folding it in is what made the gap
        // unmeasurable in the first place.
        let mut measured = Vec::new();
        for (label, format) in [("native x8r8g8b8", native), ("BGRX red_shift=0", bgrx)] {
            let mut source = pixels.clone();
            if format.red_shift == 0 {
                // Put the source in the layout the client asked for, which is
                // exactly what `convert_pixels_rect` does and nothing else.
                source = pixels_in(&pixels, W, H, &bgrx);
            }
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(LEVEL);
            let (_, warm) = encoders
                .encode(
                    Codec::Zrle,
                    &offered,
                    &source,
                    &format,
                    W as usize * 4,
                    rect,
                )
                .expect("zrle");
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = encoders.encode(
                    Codec::Zrle,
                    &offered,
                    &source,
                    &format,
                    W as usize * 4,
                    rect,
                );
            }
            let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            measured.push((label, ms, warm.len()));
        }

        // The conversion on its own, over the same rectangle.
        //
        // This is the cost production pays and every other number in this file
        // does not: the viewer asked for `red_shift: 0`, so `convert_pixels_rect`
        // runs on every update and on nothing else in these tests.
        let convert_ms = {
            let mut out = Vec::new();
            let started = Instant::now();
            for _ in 0..ROUNDS {
                convert_pixels_rect(&pixels, (W as u32, H as u32), &bgrx, rect, &mut out);
            }
            started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0
        };

        println!(
            "\nproduction: {W}x{H} ZRLE level {LEVEL}, {px:.0} px, \
             from the log: {LOG_NS_PER_PIXEL:.1} ns/px, {LOG_ENCODE_MS:.2} ms/update, \
             {LOG_BYTES_PER_PIXEL:.3} bytes/px",
        );
        for (label, ms, bytes) in &measured {
            println!(
                "  encode {label:<20} {:>7.2} ms  {:>5.1} ns/px  {:>7.3} bytes/px",
                ms,
                ms * 1e6 / px,
                *bytes as f64 / px
            );
        }
        println!(
            "  convert_pixels_rect     {:>7.2} ms  {:>5.1} ns/px   (production pays this \
             on every update; nothing else here does)",
            convert_ms,
            convert_ms * 1e6 / px
        );
        let bgrx_ms = measured[1].1 + convert_ms;
        println!(
            "\n  production's total, native->BGRX convert + ZRLE: {bgrx_ms:.2} ms \
             ({:.1} ns/px) against the log's {LOG_ENCODE_MS:.2} ms \
             ({LOG_NS_PER_PIXEL:.1} ns/px)\n",
            bgrx_ms * 1e6 / px
        );

        // **Calibrate the content, then read the clock.**
        //
        // The frame above compresses to 0.71 bytes a pixel where production
        // compresses to 1.888, so its 17 ns/pixel is a measurement of *easier*
        // pixels and says nothing about the encoder on real ones. Compression
        // cost is most of ZRLE's cost, so the two numbers cannot be compared
        // until they agree on compressibility.
        //
        // So: raise the grain until the bytes a pixel match the log's, and take
        // the nanoseconds from there. If they land on the log's number, the
        // encoder is not slow and the content was the whole of the apparent 2x.
        // If they land well under it, there is a real gap in this code and this
        // is where to look for it.
        println!("  calibrating the content against the log's compressibility:");
        let mut sweep: Vec<(f64, f64)> = Vec::new(); // (bytes a pixel, ns a pixel)
        // Past about 24 the palette in a 64x64 tile passes 256 colours and ZRLE
        // leaves the indexed sub-encoding for the plain-RGB one, so the curve
        // has a knee rather than a slope. That knee is why production can reach
        // 1.888 bytes/px when everything below 24 saturates around 1.29.
        for grain in [2i32, 4, 6, 8, 12, 16, 20, 24, 32, 48, 64, 96, 127] {
            let frame = video_frame_with_grain(W, H, 7, grain);
            let source = pixels_in(&frame, W, H, &bgrx);
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(LEVEL);
            let (_, bytes) = encoders
                .encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect)
                .expect("zrle");
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ =
                    encoders.encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect);
            }
            let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            let bpp = bytes.len() as f64 / px;
            println!(
                "    grain {grain:>3}  {bpp:>6.3} bytes/px  {ms:>6.2} ms  {:>5.1} ns/px",
                ms * 1e6 / px
            );
            sweep.push((bpp, ms * 1e6 / px));
        }
        // The line through the sweep, read off rather than guessed.
        //
        // Least squares over every point, because the curve has a knee — past
        // about 24 a tile's palette passes 256 colours and ZRLE leaves the
        // indexed sub-encoding for plain RGB — so no single pair of points
        // describes it and the honest thing is a fit and an explicit note that
        // the log sits beyond the measured range.
        let n = sweep.len() as f64;
        let mean_x = sweep.iter().map(|p| p.0).sum::<f64>() / n;
        let mean_y = sweep.iter().map(|p| p.1).sum::<f64>() / n;
        let (cov, var) = sweep.iter().fold((0.0, 0.0), |(cov, var), p| {
            (
                cov + (p.0 - mean_x) * (p.1 - mean_y),
                var + (p.0 - mean_x) * (p.0 - mean_x),
            )
        });
        let slope = cov / var;
        let intercept = mean_y - slope * mean_x;
        let fitted = intercept + slope * LOG_BYTES_PER_PIXEL;
        let highest = sweep.last().copied().unwrap();
        println!(
            "    fit: {intercept:.1} + {slope:.1} x bytes/px  ->  at the log's \
             {LOG_BYTES_PER_PIXEL:.3} bytes/px that is **{fitted:.1} ns/px** against the \
             log's {LOG_NS_PER_PIXEL:.1}",
        );
        let (last, before) = (highest, sweep[sweep.len() - 2]);
        let near_slope = (last.1 - before.1) / (last.0 - before.0);
        let extrapolated = last.1 + (LOG_BYTES_PER_PIXEL - last.0) * near_slope;
        println!(
            "    the measured range stops at {:.3} bytes/px, {:.0}% short of the log's, so \
             that point is an extrapolation. The segment nearest it ({:.3} -> {:.3}) runs \
             at {near_slope:.0} ns/px per byte/px against the fit's {slope:.0}, so the \
             truth is between {fitted:.0} and {extrapolated:.0} ns/px -- the curve \
             steepens where ZRLE changes sub-encoding and a straight line through a \
             knee understates it.",
            last.0,
            100.0 * (LOG_BYTES_PER_PIXEL - last.0) / last.0,
            before.0,
            last.0,
        );

        // What is established, asserted rather than printed.
        // **Endpoints, not every step.** The curve rises monotonically in
        // principle and does not in practice on a machine with anything else
        // running: adjacent points here wobble by 10% and reverse twice, because
        // 11 ms of deflate is not a long enough interval to average over seven
        // rounds. So the assertion is that the hardest content costs appreciably
        // more than the easiest, which is the claim the reading rests on, and
        // not that it does so without a hiccup -- a stricter version of this
        // assertion was the first thing to fail, and it was measuring the other
        // tenants on the host.
        let (easiest, hardest) = (sweep.first().copied().unwrap(), highest);
        assert!(
            hardest.1 > easiest.1 * 1.4,
            "the hardest content cost {:.1} ns/px and the easiest {:.1} ns/px. ZRLE's cost \
             tracks compressibility, and if it did not the whole reading here is void.",
            hardest.1,
            easiest.1
        );

        // The two claims this can be wrong about, asserted rather than printed.
        assert!(
            convert_ms * 1e6 / px < LOG_NS_PER_PIXEL * 0.5,
            "the conversion alone is {convert_ms:.2} ms, which is more than half the log's \
             whole encode of {LOG_ENCODE_MS:.2} ms. That is a real cost and it is not the \
             gap, so the gap is elsewhere -- but a cost that size is worth its own line."
        );
        assert!(
            fitted > LOG_NS_PER_PIXEL * 0.6,
            "even extrapolated to the log's compressibility the fit is {fitted:.1} ns/px \
             against the log's {LOG_NS_PER_PIXEL:.1}, which is a third of the gap still \
             unexplained. That would mean a real inefficiency in this code rather than \
             in the workload, and it is not what the measurement says."
        );
    }

    /// A frame that looks like decoded video rather than a test pattern.
    ///
    /// Four regions, because a codec's cost is decided by what it finds in a
    /// 64x64 tile and one region only exercises one answer: a slow sky gradient,
    /// a flat wall, textured foliage, and a moving object with an edge. Plus a
    /// little grain, because the residue a real decoder leaves is part of why
    /// video is expensive and a perfectly smooth frame would flatter it.
    ///
    /// `photographic` is deliberately not used here and must not be substituted:
    /// it is a smooth gradient with a high-entropy middle band, and every
    /// measurement in this file that quotes its numbers is measuring that and
    /// not a video frame.
    fn video_frame(width: u16, height: u16, seed: u32) -> Vec<u8> {
        video_frame_with_grain(width, height, seed, 2)
    }

    /// The encode end to end, on a video-shaped frame, **and the same frame with
    /// deflate taken out of it** — which is the one subtraction that says where
    /// the encode's time actually goes.
    ///
    /// The production log's encode is 41.5 ns/pixel, and the parts measured
    /// elsewhere in this file add to far less than that: deflate alone on the
    /// three-bytes-a-pixel stream is 19.1, and the raw tiling that produces that
    /// stream is 4.8. `set_update` is not the rest either — `tests/update_cost.rs`
    /// measures the whole apply path at 3.7 ns/pixel on the production band. So
    /// something in the encoder is spending about 14 ns/pixel that no measurement
    /// so far has accounted for, and guessing at it has already produced one wrong
    /// answer in this file.
    ///
    /// This measures the encoder whole, and then the same encode with the zlib
    /// stream bypassed, so the difference is deflate and the remainder is
    /// everything this crate does. Both arms are the same function on the same
    /// bytes, so the only difference is whether the compressor runs.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_the_whole_encode_costs_against_its_compressor() {
        use std::time::Instant;

        /// The production band and the production level: the client's `-254`
        /// selected 2, and matching it is the whole point of a parity argument.
        const W: u16 = 1280;
        const H: u16 = 308;
        const LEVEL: u32 = 2;
        const ROUNDS: u32 = 10;
        const LOG_NS_PER_PX: f64 = 41.5;
        const SET_UPDATE_NS_PER_PX: f64 = 3.7;

        // The production viewer's format, spelled out because there is no local
        // called `format` to shadow the macro of that name.
        let bgrx = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        let offered = HashSet::from([Encoding::Zrle]);
        let rect = Rect::new(0, 0, W, H);
        let frame = video_frame_with_grain(W, H, 7, 96);
        let source = pixels_in(&frame, W, H, &bgrx);
        let px = f64::from(u32::from(W) * u32::from(H));

        let mut encoders = Encoders::new(None);
        encoders.set_deflate_level(LEVEL);
        // One untimed pass first: the first call on a fresh `Encoders` builds
        // the zlib stream and allocates, and measuring that as the steady-state
        // cost is how a measurement ends up flattering itself.
        let _ = encoders
            .encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect)
            .expect("zrle");
        let started = Instant::now();
        let mut bytes = 0usize;
        for _ in 0..ROUNDS {
            // The byte count is the `Vec` in the returned pair, not the pair
            // itself: `.0` is the codec, which is a `Codec`, not a length.
            bytes = encoders
                .encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect)
                .expect("zrle")
                .1
                .len();
        }
        let each = started.elapsed().as_secs_f64() / f64::from(ROUNDS);
        let ns = each * 1e9 / px;

        // The same stream at level 0, which zlib treats as store: the block
        // structure is still built and the bytes still travel, but no matching
        // happens. That isolates the search from the copying.
        let mut cheap = Encoders::new(None);
        cheap.set_deflate_level(0);
        let _ = cheap.encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect);
        let started = Instant::now();
        for _ in 0..ROUNDS {
            let _ = cheap.encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect);
        }
        let store = started.elapsed().as_secs_f64() / f64::from(ROUNDS);
        let store_ns = store * 1e9 / px;

        println!(
            "\n  one {W}x{H} video-shaped band, ZRLE level {LEVEL}, release\n\n  \
             the whole encode          {ns:>6.1} ns/px   {each_ms:.2} ms   {bpp:.2} bytes/px out\n  \
             the same at zlib level 0  {store_ns:>6.1} ns/px   {store_ms:.2} ms   (store, no matching)\n  \
             the difference            {:>6.1} ns/px   <- the compressor's search\n\n  \
             the production log's encode is {LOG_NS_PER_PX} ns/px and `set_update` is \
             {SET_UPDATE_NS_PER_PX} of\n  it, so this encoder should be about \
             {expected:.1} ns/px. Measured {ns:.1}.\n  \
             If those agree then the log's figure is this encoder and the encode is \
             what it\n  costs. If the measurement is far below, then the log's \
             encode is not this code and the\n  difference is in what is being \
             encoded rather than in how it is encoded.\n  \
             The frame produced {bytes} bytes out.\n",
            ns - store_ns,
            each_ms = each * 1000.0,
            store_ms = store * 1000.0,
            bpp = bytes as f64 / px,
            expected = LOG_NS_PER_PX - SET_UPDATE_NS_PER_PX,
        );

        assert!(
            ns > 1.0,
            "the whole encode measured {ns:.2} ns/px, too fast to be an encode. \
             The frame is probably not producing many-coloured tiles, and every \
             figure here would be flattering the wrong code."
        );
        assert!(
            store_ns <= ns,
            "storing cost {store_ns:.1} ns/px against compressing at {ns:.1}. \
             Store does strictly less work than level {LEVEL}, so this is \
             impossible and the level is not reaching the compressor."
        );
    }

    /// What deflate costs and what it buys, on the production band, across the
    /// levels that are actually reachable.
    ///
    /// The encode is 24.3 ns/pixel on this shape and 19.6 of that is the
    /// compressor's search. What the compressor returns is 1.888 bytes a pixel
    /// from the three a pixel ZRLE feeds it — a factor of 1.57. **So four
    /// fifths of the encode buys the removal of 37% of the bytes**, and whether
    /// that is a good trade depends entirely on what the link can carry, which
    /// is not a property of the encoder.
    ///
    /// The levels here are 0 through 9, all of them reachable by a client, so
    /// the table shows the whole curve rather than a point on it. The default is
    /// QEMU's: `Z_DEFAULT_COMPRESSION` at `vnc-enc-zrle.c:339`, which zlib reads
    /// as 6, and which a client's `-254` does not change for ZRLE. Level 6 is
    /// marked, because that is what this port and QEMU both serve regardless of
    /// what the client asks.
    #[test]
    #[ignore = "a measurement, not a gate; run with --release"]
    fn what_deflate_costs_and_what_it_buys() {
        use std::time::Instant;

        /// The production band, and the client's level.
        const W: u16 = 1280;
        const H: u16 = 308;
        const ROUNDS: u32 = 10;
        /// QEMU's level for ZRLE: `Z_DEFAULT_COMPRESSION`, which zlib reads as 6.
        const QEMU_LEVEL: u32 = 6;
        /// What production actually gets out of it, from the log.
        const LOG_BYTES_PER_PX: f64 = 1.888;
        /// Production's measured update rate, from the log's `updates_per_interval`.
        const UPDATES_PER_SECOND: f64 = 18.0;

        let bgrx = PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        };
        let offered = HashSet::from([Encoding::Zrle]);
        let rect = Rect::new(0, 0, W, H);
        let frame = video_frame_with_grain(W, H, 7, 96);
        let source = pixels_in(&frame, W, H, &bgrx);
        let px = f64::from(u32::from(W) * u32::from(H));

        // Build the table: every level a client can ask for, so this is the
        // whole curve rather than a point on it.
        let mut rows: Vec<(u32, f64, usize)> = Vec::new();
        for level in 0..=9u32 {
            // **Not `set_deflate_level`, which cannot reach ZRLE any more -- on
            // purpose, because QEMU's cannot either.** The test-only constructor
            // is how the curve gets walked now; calling the public path here
            // produced ten identical rows and said nothing about the compressor.
            let mut encoders = Encoders::with_zrle_level_for_measurement(level);
            // One untimed pass, so the zlib stream exists before it is timed: the
            // first call builds it, and timing that as steady state is how a
            // measurement ends up flattering itself.
            let _ = encoders.encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect);
            let started = Instant::now();
            let mut bytes = 0usize;
            for _ in 0..ROUNDS {
                bytes = encoders
                    .encode(Codec::Zrle, &offered, &source, &bgrx, W as usize * 4, rect)
                    .expect("zrle")
                    .1
                    .len();
            }
            let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            rows.push((level, ms * 1e6 / px, bytes));
        }

        let six_bytes = rows
            .iter()
            .find(|(level, _, _)| *level == QEMU_LEVEL)
            .map(|(_, _, bytes)| *bytes)
            .expect("level 6 is in the table");
        let six_ns = rows
            .iter()
            .find(|(level, _, _)| *level == QEMU_LEVEL)
            .map(|(_, ns, _)| *ns)
            .expect("level 6 is in the table");
        let six_bpp = six_bytes as f64 / px;

        println!("\n  one {W}x{H} band, video-shaped, zlib level against cost");
        println!(
            "\n  {:>5}  {:>7}  {:>9}  {:>11}\n  {:>5}  {:>7}  {:>9}  {:>11}",
            "level",
            "ns/px",
            "bytes/px",
            "vs level 6",
            "-".repeat(5),
            "-".repeat(7),
            "-".repeat(9),
            "-".repeat(11),
        );
        for (level, ns, bytes) in &rows {
            let mark = if *level == QEMU_LEVEL {
                "  <- QEMU's, and ours"
            } else {
                ""
            };
            let bpp = *bytes as f64 / px;
            println!(
                "  {level:>5}  {ns:>7.1}  {bpp:>9.3}  {:>9.2}x{mark}",
                *bytes as f64 / six_bytes as f64
            );
        }

        println!(
            "\n  QEMU's level {QEMU_LEVEL} gives {six_bpp:.3} bytes/px here against \
             the log's\n  {LOG_BYTES_PER_PX:.3}, so this fixture is {} than \
             production.\n  \
             At {UPDATES_PER_SECOND} updates a second this band is {:.1} MB/s at level \
             {QEMU_LEVEL} and\n  {:.1} MB/s at level 0, which any LAN carries and \
             which a viewer on the far side of a slow link\n  might not. That is a\n  deployment question \
             rather than a codec one, and this port's answer to it is QEMU's:\n  serve \
             level {QEMU_LEVEL}, and let a client that wants another ask for one.",
            if six_bpp > LOG_BYTES_PER_PX {
                "harder to compress"
            } else {
                "easier to compress"
            },
            six_bpp * f64::from(u32::from(W) * u32::from(H)) * UPDATES_PER_SECOND / 1e6,
            rows[0].2 as f64 / px * f64::from(u32::from(W) * u32::from(H)) * UPDATES_PER_SECOND
                / 1e6,
        );

        // Level 0 must be the cheapest, or the level is not reaching the
        // compressor and the whole table is one number repeated ten times.
        let cheapest_ns = rows.iter().map(|(_, ns, _)| *ns).fold(f64::MAX, f64::min);
        assert!(
            rows[0].1 <= cheapest_ns,
            "level 0 cost {:.1} ns/px, which is not the cheapest in the table. \
             Store does strictly less work than any search, so the level is not \
             reaching the compressor and this table measures nothing.",
            rows[0].1
        );
        // And a deeper search must cost more than a weaker one.
        let nine_ns = rows
            .iter()
            .find(|(level, _, _)| *level == 9)
            .map(|(_, ns, _)| *ns)
            .expect("level 9 is in the table");
        assert!(
            nine_ns > six_ns,
            "level 9 cost {nine_ns:.1} ns/px against level 6's {six_ns:.1}. A deeper \
             search cannot be free; if it is, the levels are not reaching the \
             compressor."
        );
    }

    fn video_frame_with_grain(width: u16, height: u16, seed: u32, grain: i32) -> Vec<u8> {
        let (w, h) = (usize::from(width), usize::from(height));
        let mut data = vec![0u8; w * h * 4];
        let seed = seed as usize;
        for y in 0..h {
            for x in 0..w {
                let (r, g, b) = match y * 4 / h.max(1) {
                    // Sky: a slow vertical gradient, the easiest thing there is.
                    0 => ((90 + y / 3) as u8, (140 + y / 2) as u8, (210 - y / 4) as u8),
                    // Foliage: no two pixels alike within a tile, which is the
                    // sub-encoding ZRLE handles least cheaply.
                    1 | 2 => {
                        let n = ((x * 2654435761) >> 13 ^ (y * 40503) >> 7) as u8;
                        (n / 3 + 20, n / 2 + 60, n / 4 + 10)
                    }
                    // Wall: flat, with a moving object crossing it.
                    _ => {
                        let (ox, oy) = ((x + seed * 37) % 300, h / 2);
                        let inside = x >= ox && x < ox + 90 && (y as i32 - oy as i32).abs() < 25;
                        if inside {
                            // A soft-edged object, so its border is a gradient
                            // rather than a step: video edges are never steps.
                            let dx = (x - ox) as f32 / 90.0;
                            let dy = (y as f32 - oy as f32) / 25.0;
                            let inside = (1.0 - dx * dx * dx) * (1.0 - dy * dy * dy);
                            (
                                (200.0 * inside) as u8,
                                (120.0 * inside) as u8,
                                (60.0 * inside) as u8,
                            )
                        } else {
                            (150u8, 148, 145)
                        }
                    }
                };
                let o = (y * w + x) * 4;
                // Grain. Small, everywhere, and incompressible.
                let jitter = ((x * 7 + y * 13 + seed) as i32 % (2 * grain + 1)) - grain;
                data[o] = (b as i32 + jitter).clamp(0, 255) as u8;
                data[o + 1] = (g as i32 + jitter).clamp(0, 255) as u8;
                data[o + 2] = (r as i32 + jitter).clamp(0, 255) as u8;
                data[o + 3] = 0;
            }
        }
        data
    }

    /// The source pixels in the layout `format` asks for.
    ///
    /// The same arithmetic `convert_pixels_rect` does, without the counting and
    /// the rectangle walking, so that the encode can be timed on the bytes the
    /// client would actually receive.
    fn pixels_in(src: &[u8], width: u16, height: u16, format: &PixelFormat) -> Vec<u8> {
        let stride = usize::from(width) * 4;
        let mut out = vec![0u8; stride * usize::from(height)];
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                let i = y * stride + x * 4;
                let (red, green, blue) = (src[i + 2], src[i + 1], src[i]);
                // No `as u8`: `blue` is a `u8` and so is the result of a
                // `u8 << u32`, which wraps rather than saturating. The casts
                // said "this might be wider" about three values that cannot be.
                out[i] = blue << (format.blue_shift / 8);
                out[i + 1] = green << (format.green_shift / 8);
                out[i + 2] = red << (format.red_shift / 8);
                out[i + 3] = 0;
            }
        }
        out
    }
}

#[cfg(test)]
mod convert_tests {
    use super::{convert_pixels, convert_pixels_rect, convert_pixels_rect_general, pixman_xrgb};
    use crate::rfb::{PixelFormat, Rect};

    /// A converted rectangle is byte-for-byte what a whole-frame conversion
    /// would have put there — and only the rectangle is converted.
    ///
    /// Two claims, and the second is the one that cannot be checked by
    /// comparing output. Converting only the rectangle is an *optimisation*, and
    /// an optimisation is invisible in its results: converting the whole screen
    /// produces the same bytes in the rectangle and this test would pass either
    /// way, which is the same failure as the dead corpus in §8 and the same
    /// failure as the mutation that removed a merge rule nothing exercised.
    ///
    /// So `convert_pixels_rect` reports how many pixels it converted, and that
    /// number is asserted. A 64x64 rectangle is 4096 pixels whatever the screen
    /// is, so a version that quietly converted the framebuffer fails here even
    /// though every byte it produced was right.
    ///
    /// The first claim is the one that keeps the optimisation honest: the
    /// rectangle's bytes must match the whole-frame conversion exactly, at a
    /// screen stride, for a rectangle that is not at the origin — because
    /// `RectPixels` offsets by the rectangle and reads nothing outside it, so
    /// the rest of the screen-sized buffer is stale and must never be read.
    #[test]
    fn a_converted_rectangle_matches_a_whole_frame_conversion() {
        const W: u16 = 1280;
        const H: u16 = 800;
        let source: Vec<u8> = (0..usize::from(W) * usize::from(H) * 4)
            .map(|i| match i % 4 {
                0 => (i / 4) as u8,
                1 => ((i / 4) % 251) as u8,
                2 => ((i / 4) / 251) as u8,
                _ => 0,
            })
            .collect();

        // The format the production viewer asks for, which is not the
        // framebuffer's own, and a 16-bit one for the other byte order.
        for format in [
            PixelFormat {
                red_shift: 0,
                green_shift: 8,
                blue_shift: 16,
                ..pixman_xrgb()
            },
            PixelFormat {
                bits_per_pixel: 16,
                red_shift: 11,
                green_shift: 5,
                blue_shift: 0,
                ..pixman_xrgb()
            },
        ] {
            let bpp = if format.bits_per_pixel == 16 { 2 } else { 4 };
            let stride = usize::from(W) * bpp;

            let screen = (u32::from(W), u32::from(H));
            let mut whole = Vec::new();
            assert!(convert_pixels(&source, screen, &format, &mut whole));

            for rect in [
                Rect::new(0, 0, 64, 64),
                // Not at the origin, and against the right-hand and bottom
                // edges, where an off-by-one in the stride would show.
                Rect::new(1200, 700, 64, 64),
                Rect::new(1216, 736, 64, 64),
                Rect::new(0, 0, W, H),
            ] {
                let mut part = Vec::new();
                let converted = convert_pixels_rect(&source, screen, &format, rect, &mut part)
                    .expect("the format is supported");
                assert_eq!(
                    converted,
                    usize::from(rect.width) * usize::from(rect.height),
                    "{rect:?} converted {converted} pixels, which is not its area. A whole \\
                     framebuffer is {} pixels, so this is the whole point: the conversion is \\
                     sized by the damage and not by the screen",
                    usize::from(W) * usize::from(H)
                );
                assert_eq!(
                    part.len(),
                    stride * usize::from(H),
                    "{rect:?}: the buffer must stay screen-strided, because RectPixels is \\
                     handed it with the screen stride and offsets by the rectangle"
                );
                for y in rect.top..rect.top + rect.height {
                    for x in rect.left..rect.left + rect.width {
                        let o = usize::from(y) * stride + usize::from(x) * bpp;
                        assert_eq!(
                            &part[o..o + bpp],
                            &whole[o..o + bpp],
                            "{rect:?}: the pixel at {x},{y} differs from a whole-frame \\
                             conversion"
                        );
                    }
                }
            }
        }
    }

    /// The fast conversion is the slow one, byte for byte, everywhere.
    ///
    /// `convert_rows_32` is a second implementation of `convert_pixels_rect_general`
    /// and the only thing that makes it a fast path rather than a second source
    /// of truth is this test. It has to be exhaustive over the *axes* rather than
    /// reassuring on one case: every channel shift arrangement that a client can
    /// ask for, the reduced-range formats that take the slow path anyway, and
    /// rectangles at the origin, mid-screen and against both edges.
    ///
    /// The formats are generated rather than listed because the interesting one
    /// was not in the list: the production viewer asks for
    /// `red_shift: 0, green_shift: 8, blue_shift: 16`, the reverse of ours, and
    /// the hand-written list had it in third place behind the two that were
    /// already covered by other tests.
    #[test]
    fn the_fast_conversion_is_the_slow_one_byte_for_byte() {
        const W: u16 = 1280;
        const H: u16 = 800;
        let source: Vec<u8> = (0..usize::from(W) * usize::from(H) * 4)
            .map(|i| match i % 4 {
                0 => (i / 4) as u8,
                1 => ((i / 4) % 251) as u8,
                2 => ((i / 4) / 251) as u8,
                _ => (i / 7) as u8,
            })
            .collect();
        let screen = (u32::from(W), u32::from(H));

        let mut checked = 0usize;
        for format in channel_formats() {
            for rect in [
                Rect::new(0, 0, 64, 64),
                Rect::new(640, 0, 64, 308),
                Rect::new(1216, 736, 64, 64),
                Rect::new(0, 162, 1280, 13),
                Rect::new(0, 0, W, H),
            ] {
                let mut fast = Vec::new();
                let converted = convert_pixels_rect(&source, screen, &format, rect, &mut fast)
                    .expect("a supported format");
                let mut slow = Vec::new();
                let reference =
                    convert_pixels_rect_general(&source, screen, &format, rect, &mut slow)
                        .expect("a supported format");

                assert_eq!(
                    converted, reference,
                    "{format:?} {rect:?}: the fast path converted {converted} pixels and \
                     the reference {reference}"
                );
                assert_eq!(
                    fast.len(),
                    slow.len(),
                    "{format:?} {rect:?}: the buffers differ in length"
                );
                assert!(
                    fast == slow,
                    "{format:?} {rect:?}: the fast path and the reference disagree. \
                     Shifts {}/{}/{}, max {}/{}/{}",
                    format.red_shift,
                    format.green_shift,
                    format.blue_shift,
                    format.red_max,
                    format.green_max,
                    format.blue_max
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 40,
            "only {checked} format-and-rectangle combinations were checked, so this is \
             not the exhaustive comparison it claims to be"
        );
    }

    /// Every channel arrangement a client can legitimately ask for.
    ///
    /// Generated over all three shifts and a reduced range, and *not* over
    /// arbitrary ones: a format with `red_shift: 3` is not expressible, and
    /// including it would make this test assert on nonsense.
    fn channel_formats() -> Vec<PixelFormat> {
        let mut formats = Vec::new();
        for red_shift in [0u8, 8, 16] {
            for green_shift in [0u8, 8, 16] {
                for blue_shift in [0u8, 8, 16] {
                    let shifts = [red_shift, green_shift, blue_shift];
                    if shifts.iter().any(|s| *s != 0 && *s != 8 && *s != 16) || shifts == [0, 0, 0]
                    {
                        continue;
                    }
                    // A permutation: each channel in a different byte.
                    let mut seen = [false; 3];
                    let mut ok = true;
                    for s in shifts {
                        let i = (s / 8) as usize;
                        if i > 2 || seen[i] {
                            ok = false;
                        }
                        seen[i] = true;
                    }
                    if !ok {
                        continue;
                    }
                    formats.push(PixelFormat {
                        red_shift,
                        green_shift,
                        blue_shift,
                        ..pixman_xrgb()
                    });
                    // And the reduced-range version, which is a real request and
                    // which the fast path must decline rather than get wrong.
                    formats.push(PixelFormat {
                        red_max: 31,
                        green_max: 63,
                        blue_max: 31,
                        red_shift,
                        green_shift,
                        blue_shift,
                        ..pixman_xrgb()
                    });
                }
            }
        }
        // The production viewer's, spelled out so that deleting it is a visible
        // edit rather than a silent loss of the case that found the cost.
        formats.push(PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..pixman_xrgb()
        });
        formats
    }

    /// A rectangle clipped away entirely converts nothing and says so.
    ///
    /// Damage recorded before a resize can name a rectangle that no longer
    /// exists, and `encode` clips it before asking. This is the boundary where
    /// that has to not turn into a read outside the buffer.
    #[test]
    fn a_rectangle_off_the_surface_converts_nothing() {
        let source = vec![0u8; 4 * 4 * 4];
        let format = pixman_xrgb();
        let mut out = Vec::new();
        assert_eq!(
            convert_pixels_rect(&source, (4, 4), &format, Rect::new(10, 10, 8, 8), &mut out),
            Some(0),
            "a rectangle entirely outside a 4x4 surface converted something"
        );
        // Partly outside: the part that is on the surface is what is converted.
        assert_eq!(
            convert_pixels_rect(&source, (4, 4), &format, Rect::new(2, 2, 8, 8), &mut out),
            Some(4),
            "a rectangle hanging off the edge converted the wrong number of pixels"
        );
    }
}
