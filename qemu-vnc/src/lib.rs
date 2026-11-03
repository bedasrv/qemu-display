//! A standalone VNC server, connecting to a QEMU instance through its
//! D-Bus display interface (`org.qemu.Display1`).
//!
//! This crate is a Rust port of QEMU's `tools/qemu-vnc`. The D-Bus side is
//! implemented with the [`qemu_display`] crate, and the RFB (VNC) side with
//! the vendored [`rfb`] module.

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod audio;
pub mod chardev;
pub mod clipboard;
mod console;
pub mod counters;
pub mod dbus;
pub mod display;
pub mod input;
pub mod rfb;
pub mod server;
pub mod utils;
#[cfg(feature = "websockets")]
pub mod web;

pub use console::{TEXT_COLS, TEXT_FONT_HEIGHT, TEXT_FONT_WIDTH, TEXT_ROWS, TextConsole};
pub use dbus::{BUS_NAME, CLIENT_PATH_PREFIX, SERVER_PATH};
pub use server::{ClientId, ClientInfo, ListenerInfo, PasswordStore, Server, ServerEvent, Share};
