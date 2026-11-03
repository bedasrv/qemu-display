# qemu-vnc

A standalone VNC server, serving the display of a QEMU instance started with
`-display dbus` (`org.qemu.Display1`).

It is a Rust port of QEMU's `tools/qemu-vnc`. The D-Bus side is implemented
with the [`qemu-display`](../qemu-display) crate, the RFB (VNC) side with the
[`vnc`](https://github.com/elmarco/rust-vnc) crate, and the text consoles with
[`vt100`](https://crates.io/crates/vt100) and
[`font8x8`](https://crates.io/crates/font8x8).

## Usage

```sh
$ cargo run -p qemu-vnc -- --help
$ cargo run -p qemu-vnc -- --vnc-addr localhost:5900
```

The C program options are supported: `--dbus-address`, `--dbus-p2p-fd`,
`--bus-name`, `--wait`, `--vnc-addr`, `--share`, `--vt-chardev`, `--no-vt`,
`--keyboard-layout` and `--trace`. Use `--trace qemu_vnc=debug` (or `RUST_LOG`)
to get the tracing output, the equivalent of the QEMU trace events.

`--lossy` and `--jpeg-quality=<n>` are the C options of the same name: they
allow the clients that ask for it to be served lossy JPEG instead of the
lossless encodings. The lossy encoder is behind the `lossy` cargo feature, as
in QEMU where it is a build option:

```sh
$ cargo run -p qemu-vnc --features lossy -- --lossy --jpeg-quality 40
```

`--websocket`/`-w` opens a second listener serving RFB over WebSocket, which
is what a browser based viewer uses. It is behind the `websockets` cargo
feature, like the option is a build option in QEMU:

```sh
$ cargo run -p qemu-vnc --features websockets -- --websocket 5700
```

A viewer connects to `ws://host:5700/websockify` and the stream is RFB. A client
that offers the `binary` sub-protocol has it selected; one that offers no
sub-protocol -- noVNC 1.7.0 does not -- is accepted without one, and one that
offers only other sub-protocols is refused before a single RFB byte is sent.
Both listeners are reported by the `Listeners` D-Bus property, each with its own
`WebSocket` flag, and a client carries the one of the listener it came in on.

### Serving noVNC

`--web DIR` serves a directory over HTTP on the WebSocket listener's port, as
`websockify --web=DIR` does, so noVNC needs no second process:

```sh
$ qemu-vnc -w 127.0.0.1:6080 --web /path/to/noVNC-1.7.0 \
      -a unix:path=/var/run/qvm/windows-dbus.sock
```

`http://127.0.0.1:6080/vnc.html` is then the viewer, and its WebSocket goes to
`ws://127.0.0.1:6080/websockify` on the same port. An upgrade is accepted on
any path, as websockify accepts it, so a viewer written to ask for `/` keeps
working; a request without `Upgrade: websocket` is answered from `DIR` and the
connection is closed.

Only the tree under `DIR` is served. `..` is refused rather than normalised,
and a symbolic link that resolves outside the root is refused with it, so a
link planted in the directory cannot reach the rest of the machine. A directory
without an `index.html` is listed, which is what makes `/` a page rather than a
404 in a viewer directory.

## Encodings

The clients are served the best encoding they announced that we can produce:
ZRLE, Tight or hextile, with raw pixels as the floor. Only the part of a
console the guest damaged is sent, and the choice adapts to how fast a client
reads, so that a slow one gets cheaper updates rather than a server that
spends all its time in zlib. See
[`src/rfb/encodings.rs`](src/rfb/encodings.rs).

## Transports

One task serves a client, polling the connection and the events of the server
together. A plain socket is driven through `async_io`; a WebSocket is the same
byte stream in binary messages, and `src/rfb/websocket.rs` is the only place
that knows it. The RFB parsing above them is unchanged and synchronous: a
message is only parsed once all of its bytes are in the buffer.


## SASL

`-vnc ...,sasl=on` is `--sasl`, and it is behind the `sasl` cargo feature, as
QEMU's `--enable-vnc-sasl` is a configure option. The RFB security type 20 is
implemented in [`src/rfb/sasl.rs`](src/rfb/sasl.rs), including `ANONYMOUS`,
which needs no library at all; the Cyrus mechanisms (`GSSAPI`, `PLAIN`,
`DIGEST-MD5`) are in [`src/rfb/sasl_cyrus.rs`](src/rfb/sasl_cyrus.rs) and are
only built with the feature, which uses `sasl2-sys`'s `vendored` feature so
that no `libsasl2-dev` is needed:

```sh
$ cargo run -p qemu-vnc --features sasl -- --sasl --sasl-authz alice,bob
```

`--sasl-authz` takes the comma separated list of SASL usernames allowed to
connect. QEMU puts a QAuthZ object there, which has no equivalent in Rust;
this is the allow/deny policy that replaces it, and every client is allowed
when it is not given.

## Audio

The audio of the guest is sent to the clients that ask for it: the `Audio`
pseudo-encoding, then QEMU's own extended messages. RFB has no audio of its
own, so both halves of this are QEMU extensions -- `-259` for the
acknowledgement, which is a frame buffer update carrying the encoding and no
pixels, and `255, 1, <op>` for the samples themselves. The wire format is raw
uncompressed PCM, which is why audio works but hardly anyone asks for it: one
44.1 kHz stereo `S16` stream is about 176 KB/s, more than the framebuffer on a
typical update.

Nothing is added to how qemu-vnc is run: the samples arrive over the same
`-display dbus` connection it already uses, on `org.qemu.Display1.Audio`, and
`--dbus-p2p-fd` carries them the same way. What the *VM* needs is an audio
device, because that is the whole gate -- `has_audio()` asks whether
`/org/qemu/Display1/Audio` is in the peer's object list, and it is only there
when the VM has one. A guest with no sound card is served no audio, and the log
says so.

**`-vnc` is not part of this, which is where the confusion starts.** QEMU's
built-in VNC server is a separate program path (`ui/vnc.c`) that binds its own
socket and takes `-vnc <display>,audiodev=<id>` to say which backend to capture
from. That option is mandatory there since 8.2: without it QEMU sends no audio
acknowledgement at all, and drops a client that sends audio control messages
anyway. qemu-vnc does not run that code, and the two arrangements are not
interchangeable -- `has_audio()` is the same policy asked over D-Bus instead.

`--audio-dump=<path>` writes the samples to a file instead of playing them,
which is how the path is checked on a machine with no sound card:

```sh
$ cargo run -p qemu-vnc --features audio -- --audio-dump /tmp/guest.pcm
```

Without the `audio` feature the samples are captured and discarded, so a build
without `libasound` still serves audio to a viewer — it just does not make any
noise. With it, the samples are played through ALSA, which needs
`libasound2-dev` and `pkg-config` at build time.

The samples are converted into the format **each** client asked for: the width,
the signedness, the channel count, and the sample rate, which is resampled. A
client that asked for nothing gets QEMU's default — S16, stereo, 44.1 kHz —
rather than whatever the guest happened to be producing, which is what QEMU
does and what its own `vs->as` defaults say. Two clients asking for two
different formats get two different conversions of the same stream.

## Ported files

| C source        | Rust module                | Notes                                             |
| --------------- | -------------------------- | ------------------------------------------------- |
| `qemu-vnc.c`    | `main.rs`                  | Command line, D-Bus setup, main loop              |
| `display.c`     | `display.rs`               | Scanout, updates, cursor, console registration    |
| `input.c`       | `input.rs`                 | Keyboard, mouse, LEDs, absolute/relative pointer   |
| `clipboard.c`   | `clipboard.rs`             | Clipboard peer, `text/plain;charset=utf-8` only   |
| `chardev.c`     | `chardev.rs`               | Chardev registration                              |
| `console.c`     | `console.rs`               | VT100 text console                                |
| `dbus.c`        | `dbus.rs`                  | `org.qemu.Vnc1.Server` and `.Client` interfaces   |
| `utils.c`       | `utils.rs`                 | Peer-to-peer D-Bus connection from a file descriptor |
| `stubs.c`       | –                          | Link time stubs, nothing to port                   |
| `audio.c`       | `audio.rs`                 | The sink, behind the `Sink` trait; the RFB half is `rfb/audio.rs` |
| `ui/vnc.c`      | `rfb/`, `server/`         | The RFB server itself, vendored from the `vnc` crate, plus the encoders and the policy in `rfb/encodings.rs`, the WebSocket transport in `rfb/websocket.rs`, the audio protocol in `rfb/audio.rs`, and the client and display glue in `server/` |

## Differences with the C implementation

The following parts of `qemu-vnc` are **not** implemented:

* TLS x509 credentials (`ReloadCredentials` returns a "not supported" error),
* the DMA-BUF and shared memory listener interfaces — which is *not* a gap: the
  original has none either. The map half is implemented
  (`display.rs::set_mapped_rect`) and the message half does not exist in the
  reference; a VGA console cannot be shared at all, so a VGA guest uses the
  scanout messages and its pixels are copied to the client.
* within the encodings: RRE/CoRRE, Tight's gradient filter, Tight PNG, ZYWRLE,
  and the `CopyRect` heuristic.

One thing to know about the `cpal` sink: it is built and tested, but it can
only be *run* on a machine with a sound card. On a machine without one —
including this project's CI — opening it fails cleanly with "there is no audio
output device", and the null sink takes over. That is the intended behaviour,
not a limitation of the build.

The RFB server itself is vendored in `src/rfb/`, from the `server` branch of
<https://github.com/elmarco/rust-vnc> (`MIT OR Apache-2.0`): the published
crate has no server support, and the entry point had to become generic over
the transport to allow authentication, TLS and WebSocket. VNC password
authentication is implemented (`--password`, `--set-password`, the
`CREDENTIALS_DIRECTORY/vnc-password` credential, and `SetPassword` /
`ExpirePassword` over D-Bus), but it is a weak scheme: use TLS for anything
crossing an untrusted network.

A client that requests a pixel format other than the native
`x8r8g8b8` one is served by converting the pixels, as long as it uses 8, 16 or
32 bits per pixel in a little endian true colour format. The compressed
encodings need to read the colours of a pixel, so an 8 bits per pixel client
gets raw pixels, as QEMU's ZRLE does.

The encoders keep a persistent zlib stream per client, as QEMU's do, and the
end-to-end suite decodes them back: ZRLE, hextile and Tight round-trip over a
real socket, and with `--features websockets` the same scripted client runs
over a WebSocket, so the framing is covered by the same assertions.

## Testing

`cargo test -p qemu-vnc` runs the unit tests and the end-to-end suite. No real
QEMU is needed.

The end-to-end suite lives in `tests/`. `tests/mock.rs` runs the actual
`Server` against a stand-in for QEMU — `tests/mock/qemu.rs`, a D-Bus object
server exporting `org.qemu.Display1.VM`, `.Console`, `.Keyboard`, `.Mouse` and
`.Clipboard` with two consoles. The two ends talk over a peer-to-peer socket pair, the same shape
`--dbus-p2p-fd` gives the real program, so nothing has to own the `org.qemu`
well-known name and the tests run in parallel. There is no bus involved at all,
so no test skips on a machine without one.

That covers what a viewer would see, end to end: a scanout pushed over the
console's listener connection and coming back out of a socket as pixels; a
damaged rectangle arriving as one rectangle and not the whole console; an
`r5g6b5` or `a8r8g8b8` console expanded to the client's format; a scanout the
server cannot read, or an update outside the surface, leaving the console
alone; a cursor arriving as a mask and a shape; a key arriving as a keycode;
a mouse move arriving as a position because the console has an absolute
pointer; Ctrl+Alt-N moving a client between two consoles that show different
things; the clipboard in both directions; a resize reaching the console; and
the audio acknowledgement, which a server without audio must not send.

The other two test files do not need the mock: `tests/session.rs` drives
the RFB protocol with a scripted client over a socket, and
`tests/websocket.rs` drives the same one over a WebSocket.

Two tests in `tests/mock.rs` check Tight and ZRLE at 1280x800 with a decoder
that shares no code with this crate: `tests/witness/`, a `vnc-rs` client. Build
it with `cargo build -p witness` and point the suite at it:

```sh
QEMU_VNC_VNCRS_WITNESS=$PWD/target/debug/witness \
  dbus-run-session -- cargo test -p qemu-vnc --all-features
```

Without that variable those two tests return early and still report `ok`, so a
green suite does not by itself prove they ran. Run with `-- --nocapture` and
expect no `skipped:` line and a `VERDICT: ok` from each.

