//! Tests for the RFB session: the handshake, the VNC authentication, and the
//! pixel encodings.
//!
//! These drive [`qemu_vnc::rfb::TcpSession`] directly over a loopback socket,
//! so they need neither QEMU nor a VNC viewer.

mod common;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use common::rfb_client::{self, Decoders};
use qemu_vnc::rfb::{
    ClientTransport, Codec, Encoders, Event, FramebufferUpdate, Password, PixelFormat, Rect,
    SaslMechanism, SaslMechanisms, ServerOptions, TcpSession,
};

/// Drive a future to completion, in a test.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    async_io::block_on(future)
}

/// The size of the frame buffer the test server serves.
///
/// Big enough for Tight to be worth it, which the policy only considers from
/// 64x64 up.
const WIDTH: u16 = 96;
const HEIGHT: u16 = 64;

/// A synthetic frame, in the x8r8g8b8 format: a red pixel pattern.
fn frame(width: u16, height: u16) -> Vec<u8> {
    (0..width as usize * height as usize)
        .flat_map(|i| {
            if i % 4 == 0 {
                [0x7f, 0x00, 0x00, 0x00]
            } else {
                [0x00; 4]
            }
        })
        .collect()
}

/// The pixel format the tests use.
fn pixel_format() -> PixelFormat {
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

/// Serve one client in a background thread, and hand the connection back to
/// the test. `password` is the password the server requires, if any.
fn serve(password: Option<&str>) -> (TcpStream, thread::JoinHandle<()>) {
    serve_with(password, None)
}

/// Serve a client that sends more than one message before asking for the
/// picture.
///
/// [`serve`] answers the first event it reads and only if it is an update
/// request, which is all the handshake tests need. A test that announces its
/// encodings first has to be answered twice, and the loop is what does it.
fn serve_events() -> (TcpStream, thread::JoinHandle<()>, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let seen: Seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let name = "qemu-vnc test".to_string();
        let options = ServerOptions::anonymous(&name, pixel_format());
        block_on(async {
            let transport = ClientTransport::socket(stream).unwrap();
            let Ok((mut session, _)) =
                TcpSession::from_stream(transport, WIDTH, HEIGHT, options).await
            else {
                return;
            };
            // Answer every event until the client hangs up, and record what
            // came in: the bare session is not the client task, so it sends no
            // acknowledgement of its own, and a test that wants to see the
            // server *read* something has to read it here.
            while let Ok(event) = session.read_event().await {
                let described = format!("{event:?}");
                if let Ok(mut seen) = record.lock() {
                    seen.push(described.clone());
                }
                if let Event::FramebufferUpdateRequest { width, height, .. } = event {
                    let mut fbu = FramebufferUpdate::new(Some(&pixel_format()));
                    let pixels = frame(width, height);
                    fbu.add_raw_pixels(Rect::new(0, 0, width, height), &pixels);
                    session.send(&fbu).await.expect("update");
                }
            }
        });
    });
    (client, handle, seen)
}

/// What the test server read from the client, shared with the test.
type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// Serve one client, with either a password or SASL mechanisms.
fn serve_with(
    password: Option<&str>,
    sasl: Option<Vec<qemu_vnc::rfb::SaslMechanism>>,
) -> (TcpStream, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let password = password.map(Password::new);
    let sasl = sasl.map(|mechanisms| std::sync::Arc::new(SaslMechanisms::new(mechanisms)));

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let name = "qemu-vnc test".to_string();
        let options = match (&password, &sasl) {
            (_, Some(mechanisms)) => ServerOptions::with_sasl(&name, pixel_format(), mechanisms),
            (Some(password), None) => ServerOptions::authenticated(&name, pixel_format(), password),
            (None, None) => ServerOptions::anonymous(&name, pixel_format()),
        };
        block_on(async {
            let transport = ClientTransport::socket(stream).unwrap();
            let Ok((mut session, _)) =
                TcpSession::from_stream(transport, WIDTH, HEIGHT, options).await
            else {
                return;
            };
            // Answer one frame buffer update, then keep the session alive
            // until the test hangs up.
            if let Ok(Event::FramebufferUpdateRequest { width, height, .. }) =
                session.read_event().await
            {
                let mut fbu = FramebufferUpdate::new(Some(&pixel_format()));
                let rect = Rect::new(0, 0, width, height);
                let pixels = frame(width, height);
                fbu.add_raw_pixels(rect, &pixels);
                session.send(&fbu).await.unwrap();
            }
            let _ = session.read_event().await;
        });
    });
    (client, handle)
}

#[test]
fn anonymous_handshake() {
    let (mut client, server) = serve(None);

    assert_eq!(rfb_client::read_server_version(&mut client), "RFB 003.008");
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");

    // The server offers no authentication, and only that.
    assert_eq!(rfb_client::read_security_types(&mut client, false), vec![1]);
    rfb_client::select_security_type(&mut client, 1);
    assert_eq!(rfb_client::read_security_result(&mut client), 0);

    rfb_client::send_client_init(&mut client, true);
    let (width, height, name) = rfb_client::read_server_init(&mut client);
    assert_eq!((width, height), (WIDTH, HEIGHT));
    assert_eq!(name, "qemu-vnc test");

    drop(client);
    let _ = server.join();
}

#[test]
fn rfb_33_is_served_without_security_result() {
    let (mut client, server) = serve(None);

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.003\n");

    // RFB 3.3 sends the chosen security type instead of a list, and expects
    // no security result.
    let mut choice = [0u8];
    client.read_exact(&mut choice).unwrap();
    assert_eq!(choice[0], 1);

    rfb_client::send_client_init(&mut client, false);
    let (_, _, name) = rfb_client::read_server_init(&mut client);
    assert_eq!(name, "qemu-vnc test");
    drop(client);
    let _ = server.join();
}

#[test]
fn a_correct_password_is_accepted() {
    let (mut client, server) = serve(Some("s3cret"));

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");

    // Only the VNC authentication is offered, as a real viewer requires.
    assert_eq!(rfb_client::read_security_types(&mut client, false), vec![2]);
    rfb_client::select_security_type(&mut client, 2);

    assert_eq!(rfb_client::authenticate(&mut client, "s3cret"), 0);
    rfb_client::send_client_init(&mut client, true);
    let (_, _, name) = rfb_client::read_server_init(&mut client);
    assert_eq!(name, "qemu-vnc test");
    drop(client);
    let _ = server.join();
}

#[test]
fn a_wrong_password_is_refused() {
    let (mut client, server) = serve(Some("s3cret"));

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    assert_eq!(rfb_client::read_security_types(&mut client, false), vec![2]);
    rfb_client::select_security_type(&mut client, 2);

    assert_eq!(rfb_client::authenticate(&mut client, "wrong"), 1);
    // RFB 3.8 explains the refusal, then the server hangs up.
    let mut reason_len = [0u8; 4];
    client.read_exact(&mut reason_len).unwrap();
    let mut reason = vec![0u8; u32::from_be_bytes(reason_len) as usize];
    client.read_exact(&mut reason).unwrap();
    assert_eq!(reason, b"Authentication failure");

    let mut end = Vec::new();
    assert_eq!(client.read_to_end(&mut end).unwrap(), 0);
    drop(client);
    let _ = server.join();
}

#[test]
fn an_unsupported_security_type_is_refused() {
    let (mut client, server) = serve(Some("s3cret"));

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    assert_eq!(rfb_client::read_security_types(&mut client, false), vec![2]);

    // The client insists on "None", which we do not offer.
    client.write_all(&[1]).unwrap();
    client.flush().unwrap();

    let mut refusal = [0u8];
    client.read_exact(&mut refusal).unwrap();
    assert_eq!(refusal[0], 0, "expected the Invalid security type");
    let mut len = [0u8; 4];
    client.read_exact(&mut len).unwrap();
    let mut reason = vec![0u8; u32::from_be_bytes(len) as usize];
    client.read_exact(&mut reason).unwrap();
    assert!(!reason.is_empty());

    let mut end = Vec::new();
    assert_eq!(client.read_to_end(&mut end).unwrap(), 0);
    drop(client);
    let _ = server.join();
}

#[test]
fn a_client_can_request_and_read_an_update() {
    let (mut client, server) = serve(None);

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    rfb_client::read_security_types(&mut client, false);
    rfb_client::select_security_type(&mut client, 1);
    rfb_client::read_security_result(&mut client);
    rfb_client::send_client_init(&mut client, true);
    let (width, height, _) = rfb_client::read_server_init(&mut client);

    rfb_client::request_update(&mut client, 0, 0, width, height);
    let pixels = rfb_client::read_update(&mut client);
    assert_eq!(pixels.len(), width as usize * height as usize * 4);

    drop(client);
    let _ = server.join();
}

/// A frame with a few solid bands, a two-colour pattern, and a gradient:
/// something every encoding has to cope with.
///
/// `steps` is how many colours the gradient band has per axis. Sixteen fits
/// in a ZRLE palette and in a Tight one, and a hundred is more than a 256
/// colour palette can hold, which is how the two encoders are pushed onto
/// their different code paths.
fn colourful_frame(width: u16, height: u16, steps: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    let clamp = |value: u32, steps: u32| ((value.min(255) * (steps - 1)) / 255) as u8;
    for y in 0..height as u32 {
        for x in 0..width as u32 {
            let (r, g, b) = if y < height as u32 / 4 {
                // A solid band.
                (0, 0, 0x40)
            } else if y < height as u32 / 2 {
                // A checkerboard of two colours.
                if (x + y) % 2 == 0 {
                    (0xff, 0xff, 0xff)
                } else {
                    (0, 0, 0)
                }
            } else if y < (height as u32 * 3) / 4 {
                // A gradient.
                (
                    clamp(x * 255 / width as u32, steps),
                    clamp(y * 255 / height as u32, steps),
                    0x80,
                )
            } else {
                (0x12, 0x34, 0x56)
            };
            // x8r8g8b8 is B, G, R, X in memory.
            data.extend_from_slice(&[b, g, r, 0]);
        }
    }
    data
}

/// The rows of a rectangle of a strided frame buffer, as the raw encoding
/// needs them.
fn gather(pixels: &[u8], rect: Rect, stride: usize) -> Vec<u8> {
    let mut rows = Vec::new();
    for y in 0..rect.height as usize {
        let start = (rect.top as usize + y) * stride + rect.left as usize * 4;
        rows.extend_from_slice(&pixels[start..start + rect.width as usize * 4]);
    }
    rows
}

/// A connection to a server that answers one update per rectangle, with the
/// encoders it was built with.
struct Encoded {
    client: TcpStream,
    server: thread::JoinHandle<()>,
}

impl Encoded {
    /// Connect, handshake, and announce `encodings`. The server serves
    /// `frames`, in order, one per update request.
    fn connect(encodings: &[i32], frames: Vec<(Rect, Vec<u8>)>, jpeg: Option<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let encodings = encodings.to_vec();
        let (width, height) = frames
            .first()
            .map(|(rect, _)| (rect.width, rect.height))
            .unwrap_or((WIDTH, HEIGHT));
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let name = "qemu-vnc test".to_string();
            let options = ServerOptions::anonymous(&name, pixel_format());
            let (mut session, _) = block_on(async {
                let transport = ClientTransport::socket(stream).unwrap();
                TcpSession::from_stream(transport, width, height, options)
                    .await
                    .expect("a session")
            });
            let mut encoders = Encoders::new(jpeg);
            let mut offered = HashSet::new();
            // The client announces its encodings, then asks for updates.
            let mut event = block_on(session.read_event()).expect("an event");
            while let Event::SetEncodings(list) = event {
                offered = list.into_iter().collect();
                event = block_on(session.read_event()).expect("an event");
            }
            for (rect, pixels) in &frames {
                assert!(
                    matches!(event, Event::FramebufferUpdateRequest { .. }),
                    "expected an update request"
                );
                let wanted = encoders.choose(&offered, &pixel_format(), *rect);
                let mut fbu = FramebufferUpdate::new(Some(&pixel_format()));
                let compressed = encoders.encode(
                    wanted,
                    &offered,
                    pixels,
                    &pixel_format(),
                    width as usize * 4,
                    *rect,
                );
                let rows = gather(pixels, *rect, width as usize * 4);
                if let Some((codec, data)) = &compressed {
                    match codec {
                        Codec::Zrle => fbu.add_compressed_pixels(*rect, data),
                        Codec::Zlib => fbu.add_zlib_pixels(*rect, data),
                        // Tight, and the JPEG that rides on it.
                        _ => fbu.add_tight_pixels(*rect, data),
                    };
                } else {
                    // A rectangle that can not be compressed goes out raw.
                    fbu.add_raw_pixels(*rect, &rows);
                }
                block_on(session.send(&fbu)).expect("update");
                event = block_on(session.read_event()).expect("an event");
            }
        });

        let mut client = client;
        let encodings: &[i32] = &encodings;
        rfb_client::read_server_version(&mut client);
        rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
        rfb_client::read_security_types(&mut client, false);
        rfb_client::select_security_type(&mut client, 1);
        rfb_client::read_security_result(&mut client);
        rfb_client::send_client_init(&mut client, true);
        let (w, h, _) = rfb_client::read_server_init(&mut client);
        assert_eq!((w, h), (width, height));
        rfb_client::send_set_encodings(&mut client, encodings);
        Self { client, server }
    }

    /// Ask for `rect` and read the rectangle that comes back, decoded.
    fn update(&mut self, rect: Rect, decoders: &mut Decoders) -> rfb_client::Rect {
        rfb_client::request_update(
            &mut self.client,
            rect.left,
            rect.top,
            rect.width,
            rect.height,
        );
        let rects = rfb_client::read_update_rects(&mut self.client, decoders);
        assert_eq!(rects.len(), 1, "expected a single rectangle");
        rects.into_iter().next().unwrap()
    }
}

/// The frames every encoding test sends: a whole screen, a small rectangle of
/// a different screen (so the encoders see a stride rather than a full
/// screen), and the first screen again. Every entry is a rectangle of a full
/// screen, as a real update is.
///
/// `steps` is the number of colours per gradient axis, see
/// [`colourful_frame`].
fn frames(steps: u32) -> Vec<(Rect, Vec<u8>)> {
    frames_of(colourful_frame(WIDTH, HEIGHT, steps))
}

/// The same three rectangles, over a screen of the caller's choosing.
fn frames_of(screen: Vec<u8>) -> Vec<(Rect, Vec<u8>)> {
    // The same shapes with the red and blue channels swapped. The unused byte
    // of a pixel stays zero, as it is in a real framebuffer: the palette and
    // solid encodings only carry the three colour bytes, so anything else
    // would not survive the round trip.
    let other = invert(&screen);
    vec![
        (Rect::new(0, 0, WIDTH, HEIGHT), screen.clone()),
        // A rectangle in the middle of the screen: big enough for the policy
        // to consider Tight, and offset so the encoders see a stride rather
        // than the whole screen.
        (Rect::new(16, 0, WIDTH - 32, 64), other),
        (Rect::new(0, 0, WIDTH, HEIGHT), screen),
    ]
}

/// The same pixels with the red and blue channels swapped.
fn invert(pixels: &[u8]) -> Vec<u8> {
    let (chunks, _) = pixels.as_chunks::<4>();
    chunks
        .iter()
        .flat_map(|pixel| [pixel[2], pixel[1], pixel[0], pixel[3]])
        .collect()
}

/// A compressed rectangle decodes back to the frame it was made of, over a
/// connection that sends several of them: the zlib stream has to survive
/// from one rectangle to the next.
fn round_trip(encoding: i32) {
    // Twelve colours per gradient axis: 144 plus the four bands is 148, which
    // fits in the 256 colour Tight palette.
    round_trip_of(encoding, frames(12));
}

/// The same, over a given set of rectangles.
fn round_trip_of(encoding: i32, frames: Vec<(Rect, Vec<u8>)>) {
    let mut connection = Encoded::connect(&[encoding], frames.clone(), None);
    let mut decoders = Decoders::new();
    for (rect, screen) in &frames {
        let got = connection.update(*rect, &mut decoders);
        assert_eq!(got.encoding, encoding, "the server used another encoding");
        assert_eq!(
            (got.x, got.y, got.width, got.height),
            (rect.left, rect.top, rect.width, rect.height),
            "wrong rectangle"
        );
        let expected = gather(screen, *rect, WIDTH as usize * 4);
        if got.pixels != expected {
            let at = got
                .pixels
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            let pixel = at / 4;
            let got_pixel = got.pixels.get(at..at + 4).unwrap_or(&[]).to_vec();
            let want_pixel = expected.get(at..at + 4).unwrap_or(&[]).to_vec();
            panic!(
                "the pixels do not round trip: first difference at pixel ({}, {}) of {}x{}: got {got_pixel:?} expected {want_pixel:?}",
                pixel % rect.width as usize,
                pixel / rect.width as usize,
                rect.width,
                rect.height,
            );
        }
    }
    drop(connection.client);
    let _ = connection.server.join();
}

/// A screen of two colours in a checkerboard.
///
/// The gradient screen the encoding tests use holds more than sixteen colours
/// in *every* 64x64 tile, so the encoders only ever take their raw path there
/// and a palette tile was untested from end to end. A checkerboard puts
/// exactly two colours in each tile, which is the palette path.
fn checkerboard(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height as u32 {
        for x in 0..width as u32 {
            let white = (x + y) % 2 == 0;
            // x8r8g8b8 is B, G, R, X in memory.
            data.extend_from_slice(&[0, 0, if white { 0xff } else { 0 }, 0]);
        }
    }
    data
}

/// A screen of a single colour, so every tile is solid.
fn solid(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    for _ in 0..width as usize * height as usize {
        // x8r8g8b8 is B, G, R, X in memory.
        data.extend_from_slice(&[0x56, 0x34, 0x12, 0]);
    }
    data
}

#[test]
fn zrle_round_trips() {
    round_trip(rfb_client::encoding::ZRLE);
}

#[test]
fn zrle_round_trips_a_palette_screen() {
    // Two colours to a tile: the sub-encoding is the count, the entries are
    // three bytes each, and the indices are one bit apiece, packed most
    // significant bit first and restarted on every row. All of that is pinned
    // byte for byte in `rfb::encodings::zrle_layout`; this is the same layout
    // travelling the whole way through the server.
    round_trip_of(
        rfb_client::encoding::ZRLE,
        frames_of(checkerboard(WIDTH, HEIGHT)),
    );
}

#[test]
fn zrle_round_trips_a_solid_screen() {
    round_trip_of(rfb_client::encoding::ZRLE, frames_of(solid(WIDTH, HEIGHT)));
}

#[test]
fn tight_round_trips_a_palette_screen() {
    round_trip_of(
        rfb_client::encoding::TIGHT,
        frames_of(checkerboard(WIDTH, HEIGHT)),
    );
}

#[test]
fn hextile_round_trips() {
    round_trip(rfb_client::encoding::ZLIB);
}

#[test]
fn tight_round_trips() {
    round_trip(rfb_client::encoding::TIGHT);
}

/// The same content at production's size, through this crate's own decoder.
///
/// **The control that says whose fault the size-dependent failure is.** The
/// independent witness reads a 1280x800 Tight rectangle and reports `deflate
/// decompression error`; a real viewer reports `zlib inflate failed`. Two
/// independent decoders agreeing is good evidence the bytes are wrong, and it is
/// not proof -- both could share a misreading of the format.
///
/// What settles it is our own decoder, written from the same reading, at the same
/// size. If it also fails, the bytes are wrong and nothing about the witness
/// matters. If it passes, the bytes inflate and the fault is in the witness.
///
/// It must be a different size from the fixture everywhere else: the harness sizes
/// the console from the first frame, so a 1280x800 frame makes a 1280x800 console
/// and a 1280x800 rectangle, which is the shape that fails.
#[test]
fn tight_at_productions_size_round_trips_through_our_own_decoder() {
    let (w, h) = (1280u16, 800u16);
    let rect = Rect::new(0, 0, w, h);
    // More than 256 colours, which is what forces the full-colour sub-encoding.
    let screen = colourful_frame(w, h, 100);
    let frames = vec![(rect, screen.clone())];
    let mut connection =
        Encoded::connect(&[rfb_client::encoding::TIGHT], frames.clone(), None);
    let mut decoders = Decoders::new();
    let got = connection.update(rect, &mut decoders);
    assert_eq!(
        got.encoding,
        rfb_client::encoding::TIGHT,
        "the frame went out as something else, so nothing below is about Tight"
    );
    assert_eq!(
        got.pixels.len(),
        usize::from(w) * usize::from(h) * 4,
        "the rectangle decoded to {} bytes rather than {}",
        got.pixels.len(),
        usize::from(w) * usize::from(h) * 4
    );
    assert_eq!(
        got.pixels,
        gather(&screen, rect, w as usize * 4),
        "the full-colour rectangle inflated to the wrong pixels at 1280x800, so the \
         failure at this size is in our bytes and the independent witnesses are \
         right about them"
    );
    drop(connection.client);
    let _ = connection.server.join();
}

#[test]
fn a_palette_that_is_too_small_becomes_a_full_colour_rectangle() {
    // **This test asserted the opposite for as long as the encoder had the gap.**
    //
    // It read: "a frame with more than 256 colours can not be a Tight palette, so
    // a client offered only Tight and raw gets the raw rectangle rather than a
    // mangled one." And that is exactly what happened -- because Tight here
    // implemented only the fill and palette sub-encodings, and *declined* the
    // rest. Which meant Tight could not encode a photograph or a video band, the
    // client was served an encoding it had not asked for first, and the
    // `send_full_color_rect` that QEMU uses for exactly this case
    // (`ui/vnc-enc-tight.c:922`) was simply absent.
    //
    // Now it is implemented, so this content goes out as Tight -- which is what
    // QEMU does, and what the client listed first. The pixels are still checked,
    // because "the right encoding" is not the same claim as "the right picture",
    // and a full-colour rectangle that inflates to the wrong bytes would satisfy
    // the first and fail the second.
    let rect = Rect::new(0, 0, WIDTH, HEIGHT);
    let screen = colourful_frame(WIDTH, HEIGHT, 100);
    let frames = vec![(rect, screen)];
    let mut connection = Encoded::connect(
        &[rfb_client::encoding::TIGHT, rfb_client::encoding::RAW],
        frames.clone(),
        None,
    );
    let mut decoders = Decoders::new();
    let got = connection.update(rect, &mut decoders);
    assert_eq!(
        got.encoding,
        rfb_client::encoding::TIGHT,
        "more than 256 colours still declines Tight, so the sub-encoding is \
         missing again. This is the state the test was written against."
    );
    assert_eq!(
        got.pixels,
        gather(&frames[0].1, rect, WIDTH as usize * 4),
        "the full-colour rectangle inflated to the wrong pixels, so the encoding \
         number is right and the content is not"
    );
    drop(connection.client);
    let _ = connection.server.join();
}

#[test]
fn a_palette_that_is_too_small_falls_back_to_zrle() {
    // The same frame, for a client that also understands ZRLE, whose palette
    // is per tile and therefore has no such limit.
    let rect = Rect::new(0, 0, WIDTH, HEIGHT);
    let screen = colourful_frame(WIDTH, HEIGHT, 100);
    let frames = vec![(rect, screen.clone())];
    let mut connection = Encoded::connect(
        &[rfb_client::encoding::TIGHT, rfb_client::encoding::ZRLE],
        frames.clone(),
        None,
    );
    let mut decoders = Decoders::new();
    let got = connection.update(rect, &mut decoders);
    assert_eq!(got.encoding, rfb_client::encoding::ZRLE);
    assert_eq!(got.pixels, gather(&screen, rect, WIDTH as usize * 4));
    drop(connection.client);
    let _ = connection.server.join();
}

#[test]
fn compression_actually_shrinks_the_update() {
    // The point of the encodings: the same frame has to take fewer bytes than
    // the pixels it stands for.
    //
    // **ZRLE no longer does, and that is the trade `ZRLE_DEFLATE_LEVEL` makes.**
    // It runs at zlib level 0 -- deflate's store mode -- because on the
    // production video band level 0 is seven times cheaper than level 6 for
    // 2.24x the bytes, which buys 8 points of a core on a LAN that carries both.
    // The old assertion, `compressed < raw / 2`, was true at level 6 and is
    // false at level 0, and it was right to fire: it is the same claim this port
    // would otherwise be making by omission.
    //
    // So the assertion is now the one that is actually true and actually
    // matters: **the update must not exceed the pixels it stands for**, and for
    // ZRLE at level 0 it will not, because deflate's stored blocks carry three
    // bytes a pixel where the framebuffer holds four. Hextile and Tight are
    // unchanged and must still compress properly, so they keep the old bar --
    // asserted separately, because a test that loosened its threshold for
    // everything would stop noticing if hextile quietly stopped compressing too.
    let frames = frames(12);

    // ZRLE: no worse than the pixels, which is the floor at level 0.
    let mut connection = Encoded::connect(&[rfb_client::encoding::ZRLE], frames.clone(), None);
    let mut decoders = Decoders::new();
    let (mut stored, mut raw) = (0usize, 0usize);
    for (rect, _screen) in &frames {
        let rect = *rect;
        let got = connection.update(rect, &mut decoders);
        assert_eq!(
            got.encoding, rfb_client::encoding::ZRLE,
            "ZRLE could not handle the frame and fell back"
        );
        stored += got.bytes;
        raw += rect.width as usize * rect.height as usize * 4;
    }
    drop(connection.client);
    let _ = connection.server.join();
    assert!(
        stored <= raw,
        "ZRLE at level 0 produced {stored} bytes for {raw} of pixels, so deflate's \
         store mode is carrying more than the pixels did. That is not a slower \
         level, it is a broken one."
    );

    // The other two compress, and still have to.
    for (encoding, name) in [
        (rfb_client::encoding::ZLIB, "hextile"),
        (rfb_client::encoding::TIGHT, "Tight"),
    ] {
        let mut connection = Encoded::connect(&[encoding], frames.clone(), None);
        let mut decoders = Decoders::new();
        let mut compressed = 0;
        let mut pixels = 0;
        for (rect, _screen) in &frames {
            let rect = *rect;
            let got = connection.update(rect, &mut decoders);
            assert_eq!(
                got.encoding, encoding,
                "{name} could not handle the frame and fell back"
            );
            compressed += got.bytes;
            pixels += rect.width as usize * rect.height as usize * 4;
        }
        drop(connection.client);
        let _ = connection.server.join();
        assert!(
            compressed < pixels / 2,
            "{name} did not compress: {compressed} bytes for {pixels} of pixels. \
             Its level is still the client's, and this is the assertion that \
             notices if it stops being."
        );
    }
}

#[test]
fn a_client_that_asks_for_nothing_gets_raw_pixels() {
    // No encoding but raw: the frame arrives untouched.
    let frames = frames(12);
    let mut connection = Encoded::connect(&[rfb_client::encoding::RAW], frames.clone(), None);
    let mut decoders = Decoders::new();
    for (rect, screen) in &frames {
        let got = connection.update(*rect, &mut decoders);
        assert_eq!(got.encoding, rfb_client::encoding::RAW);
        assert_eq!(got.pixels, gather(screen, *rect, WIDTH as usize * 4));
    }
    drop(connection.client);
    let _ = connection.server.join();
}

#[cfg(feature = "lossy")]
#[test]
fn the_lossy_encoding_is_a_jpeg_image() {
    let rect = Rect::new(0, 0, WIDTH, HEIGHT);
    let pixels = colourful_frame(WIDTH, HEIGHT, 16);
    let frames = vec![(rect, pixels)];
    let mut connection = Encoded::connect(
        // The client announces it can take JPEG, as QEMU's `-vnc lossy`
        // clients do.
        &[rfb_client::encoding::TIGHT, -32 - 30],
        frames,
        Some(30),
    );
    let mut decoders = Decoders::new();
    let got = connection.update(rect, &mut decoders);
    // The JPEG is lossy, so the pixels only have to be close, but the
    // rectangle and the encoding have to be right.
    assert_eq!(got.encoding, rfb_client::encoding::TIGHT);
    assert_eq!(got.pixels.len(), WIDTH as usize * HEIGHT as usize * 4);
    drop(connection.client);
    let _ = connection.server.join();
}

// --- SASL, the RFB security type 20 -----------------------------------------
//
// The protocol is the one `ui/vnc-auth-sasl.c` speaks, and the exchange is
// driven here by hand so that the framing is what is under test rather than a
// library that happens to agree with it.

/// A mechanism that always accepts, so a test can check the loop without
/// needing a SASL library.
struct Accepting {
    rounds: u32,
}

impl qemu_vnc::rfb::Mechanism for Accepting {
    fn name(&self) -> &str {
        "ACCEPT"
    }

    fn start(
        &mut self,
        client_data: Option<&[u8]>,
    ) -> Result<qemu_vnc::rfb::SaslStep, qemu_vnc::rfb::SaslError> {
        // The first round has to come from the client's initial response.
        assert_eq!(client_data, Some(&b"hello"[..]));
        self.rounds = 1;
        Ok(qemu_vnc::rfb::SaslStep {
            output: Some(b"who?".to_vec()),
            complete: false,
        })
    }

    fn step(
        &mut self,
        client_data: Option<&[u8]>,
    ) -> Result<qemu_vnc::rfb::SaslStep, qemu_vnc::rfb::SaslError> {
        self.rounds += 1;
        // The second round is an empty string, which is not the same as the
        // client sending nothing: that distinction is the reason the length
        // is read before the bytes.
        assert_eq!(client_data, Some(&[][..]), "an empty string, not no data");
        Ok(qemu_vnc::rfb::SaslStep {
            output: None,
            complete: true,
        })
    }

    fn describe(&self) -> Option<String> {
        Some(format!("ACCEPT rounds={}", self.rounds))
    }
}

#[test]
fn a_sasl_client_completes_the_exchange() {
    let (_client, server) = serve_with(
        None,
        Some(vec![SaslMechanism::new("ACCEPT", |_| {
            Box::new(Accepting { rounds: 0 })
        })]),
    );
    let mut client = _client;

    assert_eq!(rfb_client::read_server_version(&mut client), "RFB 003.008");
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    // SASL is the only thing on offer, so it is the only thing a client may
    // pick.
    assert_eq!(
        rfb_client::read_security_types(&mut client, false),
        vec![rfb_client::SASL]
    );
    rfb_client::select_security_type(&mut client, rfb_client::SASL);

    // The list of mechanisms, then the one the client wants.
    assert_eq!(
        rfb_client::read_sasl_mechanisms(&mut client),
        vec!["ACCEPT"]
    );
    rfb_client::select_sasl_mechanism(&mut client, "ACCEPT");

    // The initial response, and the first round of the mechanism.
    rfb_client::send_sasl_data(&mut client, Some(b"hello"));
    let (output, complete) = rfb_client::read_sasl_data(&mut client);
    assert_eq!(output.as_deref(), Some(&b"who?"[..]));
    assert!(!complete, "the mechanism asks for another round");

    // An empty string this time, which is a different thing from nothing.
    rfb_client::send_sasl_data(&mut client, Some(b""));
    let (output, complete) = rfb_client::read_sasl_data(&mut client);
    assert_eq!(output, None, "no data is not an empty string");
    assert!(complete);

    // The RFB security result, and then the handshake goes on as usual.
    assert_eq!(rfb_client::read_security_result(&mut client), 0);
    rfb_client::send_client_init(&mut client, true);
    let (width, height, name) = rfb_client::read_server_init(&mut client);
    assert_eq!((width, height), (WIDTH, HEIGHT));
    assert_eq!(name, "qemu-vnc test");

    drop(client);
    let _ = server.join();
}

#[test]
fn an_anonymous_client_is_accepted() {
    // The mechanism QEMU allows, and the one that needs no library.
    let (mut client, server) = serve_with(None, Some(qemu_vnc::rfb::default_mechanisms()));

    assert_eq!(rfb_client::read_server_version(&mut client), "RFB 003.008");
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    assert_eq!(
        rfb_client::read_security_types(&mut client, false),
        vec![rfb_client::SASL]
    );
    rfb_client::select_security_type(&mut client, rfb_client::SASL);

    // The list on the wire is the list the build offers, which is not the same
    // in every build: without the `sasl` feature there is no Cyrus to ask, so
    // `ANONYMOUS` — the mechanism that needs no library — is all there is, and
    // with it the mechanisms Cyrus knows come first. Asserting one fixed list
    // would only be right for half the builds, so this ties the wire to the API
    // and then says what each build is expected to contain.
    let offered = rfb_client::read_sasl_mechanisms(&mut client);
    assert_eq!(
        offered,
        qemu_vnc::rfb::default_mechanisms()
            .iter()
            .map(|mechanism| mechanism.name().to_owned())
            .collect::<Vec<_>>(),
        "the mechanisms on the wire should be the ones the build offers"
    );
    assert!(
        offered.contains(&"ANONYMOUS".to_owned()),
        "ANONYMOUS is offered in every build, being the one that needs no library: \
         {offered:?}"
    );
    #[cfg(not(feature = "sasl"))]
    assert_eq!(
        offered,
        vec!["ANONYMOUS"],
        "and it is the only one there is"
    );
    #[cfg(feature = "sasl")]
    assert!(
        offered.len() > 1,
        "and with Cyrus the rest come from the library: {offered:?}"
    );

    rfb_client::select_sasl_mechanism(&mut client, "ANONYMOUS");

    // No initial response at all, which ANONYMOUS is happy with.
    rfb_client::send_sasl_data(&mut client, None);
    let (output, complete) = rfb_client::read_sasl_data(&mut client);
    assert_eq!(output, None);
    assert!(complete, "ANONYMOUS completes at once");

    assert_eq!(rfb_client::read_security_result(&mut client), 0);
    rfb_client::send_client_init(&mut client, true);
    let _ = rfb_client::read_server_init(&mut client);

    drop(client);
    let _ = server.join();
}

#[test]
fn a_mechanism_we_do_not_offer_is_refused() {
    let (mut client, server) = serve_with(
        None,
        Some(vec![SaslMechanism::new("ACCEPT", |_| {
            Box::new(Accepting { rounds: 0 })
        })]),
    );

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    rfb_client::read_security_types(&mut client, false);
    rfb_client::select_security_type(&mut client, rfb_client::SASL);
    assert_eq!(
        rfb_client::read_sasl_mechanisms(&mut client),
        vec!["ACCEPT"]
    );
    // A client that names something else is told so, rather than being made to
    // talk for a mechanism that does not exist.
    rfb_client::select_sasl_mechanism(&mut client, "GSSAPI");

    // The security result, then the reason, as every refusal does.
    assert_eq!(rfb_client::read_security_result(&mut client), 1);
    let reason = rfb_client::read_utf8(&mut client);
    assert!(
        reason.contains("unsupported SASL mechanism"),
        "unexpected reason: {reason}"
    );

    let _ = server.join();
}

#[test]
fn a_mechanism_that_refuses_ends_the_handshake() {
    // A mechanism that says no, which is what a wrong password looks like to
    // the server side of a real exchange.
    struct Refusing;
    impl qemu_vnc::rfb::Mechanism for Refusing {
        fn name(&self) -> &str {
            "REFUSE"
        }

        fn start(
            &mut self,
            _client_data: Option<&[u8]>,
        ) -> Result<qemu_vnc::rfb::SaslStep, qemu_vnc::rfb::SaslError> {
            Err(qemu_vnc::rfb::SaslError::Refused("bad password".into()))
        }

        fn step(
            &mut self,
            _client_data: Option<&[u8]>,
        ) -> Result<qemu_vnc::rfb::SaslStep, qemu_vnc::rfb::SaslError> {
            Err(qemu_vnc::rfb::SaslError::Failed)
        }
    }

    let (mut client, server) = serve_with(
        None,
        Some(vec![SaslMechanism::new("REFUSE", |_| Box::new(Refusing))]),
    );

    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    rfb_client::read_security_types(&mut client, false);
    rfb_client::select_security_type(&mut client, rfb_client::SASL);
    rfb_client::read_sasl_mechanisms(&mut client);
    rfb_client::select_sasl_mechanism(&mut client, "REFUSE");
    rfb_client::send_sasl_data(&mut client, None);

    assert_eq!(rfb_client::read_security_result(&mut client), 1);
    let reason = rfb_client::read_utf8(&mut client);
    assert!(
        reason.contains("bad password"),
        "the mechanism's own reason should reach the client: {reason}"
    );

    let _ = server.join();
}

// --- Audio, the pseudo-encoding QEMU serves it as ---------------------------

#[test]
fn the_audio_messages_the_server_reads_are_the_ones_qemu_frames() {
    // The client half, driven by hand: the bytes a viewer sends, read by the
    // server's own parser. This is the exchange that a socket test can check,
    // because the acknowledgement is the *client task's* business and the bare
    // session this harness uses is not the client task.
    let (mut client, server, seen) = serve_events();
    rfb_client::read_server_version(&mut client);
    rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    rfb_client::read_security_types(&mut client, false);
    rfb_client::select_security_type(&mut client, 1);
    rfb_client::read_security_result(&mut client);
    rfb_client::send_client_init(&mut client, true);
    let _ = rfb_client::read_server_init(&mut client);

    // The format it wants: S16, stereo, 44100 Hz.
    client
        .write_all(&[255, 1, 0, 2, 3, 2, 0, 0, 0xAC, 0x44])
        .unwrap();
    // Then enable, and disable again: `255, 1, 0` and `255, 1, 1`.
    client.write_all(&[255, 1, 0, 0]).unwrap();
    client.write_all(&[255, 1, 0, 1]).unwrap();
    client.flush().unwrap();
    // Something the server can answer, so the test knows it has read them all.
    rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
    assert_eq!(rfb_client::read_update(&mut client), frame(WIDTH, HEIGHT));

    let read = seen.lock().unwrap().clone();
    assert!(
        read.iter()
            .any(|e| e.contains("SetFormat") && e.contains("44100") && e.contains("channels: 2")),
        "the format should have been read as S16 stereo at 44100: {read:?}"
    );
    assert!(
        read.iter().any(|e| e == "QemuAudio { command: Enable }"),
        "the enable should have been read: {read:?}"
    );
    assert!(
        read.iter().any(|e| e == "QemuAudio { command: Disable }"),
        "the disable should have been read: {read:?}"
    );

    drop(client);
    let _ = server.join();
}

#[test]
fn an_audio_acknowledgement_is_one_rectangle_and_no_pixels() {
    // What the acknowledgement is made of. It goes through the session rather
    // than the client, so the bytes are checked here rather than over a socket:
    // whether a server *has* audio is the server's business, and the only
    // thing this crate decides is what the acknowledgement looks like.
    use qemu_vnc::rfb::{Encoding, FramebufferUpdate, ServerMessage};

    let mut fbu = FramebufferUpdate::new(None);
    fbu.add_pseudo_encoding(Encoding::Audio, WIDTH, HEIGHT);
    let mut bytes = Vec::new();
    fbu.write_to(&mut bytes).expect("serialised");

    // 4 bytes of update header, then 8 of rectangle and 4 of encoding, and
    // nothing else: the acknowledgement is the encoding, not a picture. The
    // rectangle carries the frame buffer's size, as QEMU's acknowledgements
    // do, rather than the empty one the vendored code wrote.
    assert_eq!(bytes.len(), 16, "the bytes are: {bytes:02x?}");
    assert_eq!(bytes[0], 0, "a FramebufferUpdate");
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 1, "one rectangle");
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 0, "at the origin");
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0, "at the origin");
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), WIDTH);
    assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), HEIGHT);
    assert_eq!(i32::from_be_bytes(bytes[12..16].try_into().unwrap()), -259);
}
