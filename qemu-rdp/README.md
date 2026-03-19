# org.qemu.Display1 D-Bus RDP server

[![Crates.io](https://img.shields.io/crates/v/qemu-rdp.svg)](https://crates.io/crates/qemu-rdp)
[![Documentation](https://docs.rs/qemu-display/badge.svg)](https://docs.rs/qemu-rdp)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

RDP server for
[org.qemu.Display1](https://www.qemu.org/docs/master/interop/dbus-display.html)
interface (as exposed by `qemu -display dbus`).

The project was originally designed to work with QEMU, but it can be used with
other displays/UI that implement the D-Bus interface.

## Features

- RDP server in Rust thanks to IronRDP
- using TLS/CredSSP for secure connections
- text clipboard sharing
- audio playback
- monitor resize
- remotefx image codec
- Opus audio codec (works with some clients, like FreeRDP)

## Installation & usage

```
cargo install qemu-rdp
```

To run the server against qemu, the simplest way is to use `qemu -display dbus` and
run the server: (requires certificate and key)
```bash
qemu-rdp serve --bind-address YOUR_IP:3389 --cert=CERT.PEM --key=KEY.PEM
```

Although for a complete setup (with audio devices, clipboard and such), you may
want to wait for libvirt to support it.

## TODO

Some ideas to improve the project:

- [ ] some video/image codec (AV1/AVC/HEVC)
- [ ] USB redirection
- [ ] audio recording
- [ ] more types clipboard redirection
- [ ] file system redirection
- [ ] multimonitor
- [ ] more efficient bitmap sharing with the dmabuf & mmap interfaces
- [ ] VM status / simple management or communication
- [ ] make it work on Win32 (untested, shouldn't be too hard)
- tons of other stuff from RDP features, and a lot of bug fixes🐛

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major
changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

### Development Setup

1. Clone the repository:
```bash
git clone https://gitlab.com/marcandre.lureau/qemu-display
cd qemu-display/qemu-rdp
```

2. Build the project:
```bash
cargo build
```

Since credentials are not managed properly right now, you will need to manually set the credentials
when connecting through smth like [IronRDP/ironrdp/client](https://github.com/Devolutions/IronRDP/tree/master/crates/ironrdp-client)
```bash
busctl --user call \
  org.QemuDisplay.RDP \
  /org/qemu_display/rdp \
  org.QemuDisplay.RDP \
  SetCredentials sss "user" "pass" "" #the default credentials
```

## Changelog

### [0.1.0] - 2025-01-29
- Initial release

## License

This project is licensed under the MIT License - see the [LICENSE](https://opensource.org/licenses/MIT) file for details.

## Acknowledgments

- Thanks to contributors, especially [Mihnea
Buzatu](https://github.com/mihneabuz) who did the initial work during GSoC
2023
- Credits to [IronRDP](https://github.com/Devolutions/IronRDP)
- Red Hat!

## Contact

- Email: marcandre.lureau@gmail.com

---
Built with ❤️ using Rust
