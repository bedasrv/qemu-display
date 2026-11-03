# The independent decoder

`main.rs` is a VNC client built on [`vnc-rs`](https://crates.io/crates/vnc-rs).
It shares no code with `qemu-vnc`, so when it agrees with us there are two
independent implementations of the format involved rather than one reading itself
back. That distinction has caught three faults the in-tree tests could not:

- **Tight's compact length was a byte too wide.** `vnc-rs` reported
  `deflate decompression error` where a real viewer reported `zlib inflate
  failed`, and the in-tree test client had the *identical* fault, so the pair
  could not have disagreed.
- **The test client's length reader was wrong the same way.** Fixing the writer
  alone left the reader masking the third byte to seven bits, which made a
  1280x800 Tight rectangle read as 614,647 bytes instead of 3,072,247 and hang
  waiting for bytes that never came.
- **The framebuffer conversion was four times slower than the same code measured
  in isolation**, and nothing that read a number could see it.

## Building and running it

    cargo build -p witness     # from the repository root
    ./target/debug/witness 127.0.0.1 <port> tight
    ./target/debug/witness 127.0.0.1 <port> zrle

It prints `VERDICT: ok` or `VERDICT: error`, and a `SUMMARY` line with the pixel
count and how many were non-black -- so a decode that "succeeds" into an empty
framebuffer is visibly wrong rather than silently fine.

## Driving it from the suite

    QEMU_VNC_VNCRS_WITNESS=$PWD/target/debug/witness \
      dbus-run-session -- cargo test -p qemu-vnc --all-features

Without that variable the witness tests **skip**, and say so on stdout, rather
than failing -- which means a green suite can quietly have stopped checking the
only thing that can contradict the encoder. That has happened: `/tmp` was wiped
once and every witness test skipped for several rounds while the suite still
reported `ok`. Grep the output of `cargo test ... -- --nocapture` for
`skipped:` and expect none; the witness prints `VERDICT: ok` when it ran.

## Why it lives in the repository and not in /tmp

Because it was in `/tmp` and `/tmp` was emptied.
