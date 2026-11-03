//! An independent decoder for what this port puts on the wire.
//!
//! Takes `host port encoding`, where `encoding` is `tight` or `zrle`, and prints
//! what it decoded. It is a *witness*, not a test: it shares no code with
//! `qemu-vnc`, so when it agrees with us there are two implementations of the
//! format involved rather than one reading itself back.
//!
//! # Why it exists, and why it is a separate program
//!
//! Three separate faults in this port were invisible to the in-tree tests because
//! the encoder and the test client had been written from one reading and agreed:
//!
//! - Tight's compact length was a byte too wide, so a third-party inflater was fed
//!   the wrong first byte. `vnc-rs` reported `deflate decompression error` where a
//!   real viewer reported `zlib inflate failed`.
//! - The test client had the identical four-byte fault, so the pair *could not*
//!   disagree.
//! - The framebuffer conversion was four times slower than the same code measured
//!   in isolation, and nothing that read a number could see it.
//!
//! A client written beside the server is evidence about the client. This one is
//! not.
//!
//! # What it prints
//!
//! ```text
//! VERDICT: ok | error
//! ```
//!
//! and a `SUMMARY` line with the pixel count and how many were non-black, so a
//! decode that "succeeds" into an empty framebuffer is visibly wrong rather than
//! silently fine.
//!
//! # Two things it has to get right about itself
//!
//! **A panic hook.** `poll_event` reports "the client isn't started" when the
//! connection task has gone, and a task that panics goes without saying so: the
//! channel closes, the error propagates as that, and the real cause is nowhere.
//! That happened at 1280x800 and cost a round, because the output read as a verdict
//! about the *server*.
//!
//! **`VncEvent::Error` is handled.** The library reports a decoding failure by
//! sending `VncEvent::Error` on the same channel as the images. A catch-all arm
//! drops it, and then this tool says "the client isn't started" for what was
//! always a decoder error.

use std::process::exit;
use std::time::Duration;

use vnc::{PixelFormat, VncEncoding};

/// How long to wait for the whole picture.
///
/// Generous, because the frame may not arrive until the server is asked for it,
/// and asking is the witness's job rather than the server's.
const TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("PANIC in the witness: {info}");
    }));

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: witness <host> <port> <tight|zrle>");
        exit(2);
    }
    let (host, port) = (args[1].clone(), args[2].clone());
    let encoding = match args[3].as_str() {
        "tight" => VncEncoding::Tight,
        "zrle" => VncEncoding::Zrle,
        other => {
            eprintln!("unknown encoding {other}");
            exit(2);
        }
    };

    let addr = format!("{host}:{port}");
    let tcp = match tokio::net::TcpStream::connect(&addr).await {
        Ok(t) => t,
        Err(e) => {
            println!("CONNECT ERROR: {e}");
            println!("VERDICT: error");
            exit(1);
        }
    };
    let _ = tcp.set_nodelay(true);

    // The auth callback's *type* has to be named: `VncConnector<S, F>` carries it,
    // and it is never called because this port serves `None`. Left to inference
    // the builder cannot be built at all, which is the library's ergonomics and
    // not anything to do with the wire.
    let auth = async { Err(vnc::VncError::NoPassword) };
    let client = match vnc::VncConnector::new(tcp)
        .set_auth_method(auth)
        .allow_shared(true)
        .set_pixel_format(PixelFormat::bgra())
        .add_encoding(encoding)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            println!("CONNECT ERROR: {e}");
            println!("VERDICT: error");
            exit(1);
        }
    };
    let client = match client.try_start().await {
        Ok(c) => c,
        Err(e) => {
            println!("CONNECT ERROR: {e}");
            println!("VERDICT: error");
            exit(1);
        }
    };
    let client = match client.finish() {
        Ok(c) => c,
        Err(e) => {
            println!("CONNECT ERROR: {e}");
            println!("VERDICT: error");
            exit(1);
        }
    };

    // Whatever the server announced, which is worth printing: a witness that
    // silently negotiated a different size than asked for is not a witness.
    if let Some(layout) = client.desktop_layout() {
        println!(
            "CONNECTED: {addr}, server announced {}x{}",
            layout.width, layout.height
        );
    }

    // One full refresh, so the server sends the whole screen rather than only
    // what it thinks changed. An incremental request against a client that has
    // just connected can legitimately return nothing at all.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut pixels: u32 = 0;
    let mut non_black: u32 = 0;
    let mut first_bytes: Vec<u8> = Vec::new();
    let mut done = false;

    while tokio::time::Instant::now() < deadline && !done {
        let remaining = deadline - tokio::time::Instant::now();
        let event = match tokio::time::timeout(remaining, client.poll_event()).await {
            Ok(Ok(Some(e))) => e,
            Ok(Ok(None)) => continue,
            Ok(Err(e)) => {
                println!("DECODE ERROR: {e}");
                println!("VERDICT: error");
                exit(1);
            }
            Err(_) => {
                println!("TIMEOUT: nothing decoded in {TIMEOUT:?}");
                println!("VERDICT: error");
                exit(1);
            }
        };
        match event {
            vnc::VncEvent::RawImage(_rect, data) => {
                if first_bytes.is_empty() {
                    first_bytes = data.iter().copied().take(8).collect();
                }
                // Counted in the pixel format the decoder handed us: `bgra`, so
                // every fourth byte is the alpha and a pixel is black when all
                // three colour channels are.
                for px in data.chunks_exact(4) {
                    pixels += 1;
                    if px[0] != 0 || px[1] != 0 || px[2] != 0 {
                        non_black += 1;
                    }
                }
            }
            vnc::VncEvent::Copy(..) => {}
            // **The one that carries the reason.** The library's decoding task
            // reports a failure by sending this on the same channel as the images;
            // a catch-all drops it and the tool then reports "the client isn't
            // started", which is what the channel closing looks like from outside.
            vnc::VncEvent::Error(e) => {
                println!("DECODER ERROR: {e}");
                println!("VERDICT: error");
                exit(1);
            }
            vnc::VncEvent::SetResolution(_) => {
                // Ask for the whole screen, non-incrementally, once a layout is
                // known. Doing it here rather than up front is what makes the
                // request use the size the server actually announced.
                use vnc::X11Event;
                if client
                    .input(X11Event::FullRefresh)
                    .await
                    .is_err()
                {
                    println!("could not ask for a full refresh");
                    println!("VERDICT: error");
                    exit(1);
                }
            }
            _ => {}
        }
        if pixels > 0 && first_bytes.len() >= 8 {
            done = true;
        }
    }

    if pixels == 0 {
        println!("no pixels decoded");
        println!("VERDICT: error");
        exit(1);
    }
    println!(
        "SUMMARY: {pixels} pixels, {non_black} non-black, first bytes {}",
        first_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("VERDICT: ok");
}
