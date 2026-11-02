use futures::prelude::*;
use glib::{clone, MainContext};
use gtk::{gio, glib};
use qemu_display::{Chardev, Display};
use std::os::unix::{io::AsRawFd, net::UnixStream};
use vte::{gtk, prelude::*};
use zbus::Connection;

fn main() {
    pretty_env_logger::init();
    let chardev_id = std::env::args().nth(1);

    let app = gtk::Application::new(Some("org.qemu.vte-example"), Default::default());
    app.add_main_option(
        glib::OPTION_REMAINING,
        glib::Char(0),
        glib::OptionFlags::NONE,
        glib::OptionArg::StringArray,
        "ID",
        Some("chardev-name/id"),
    );
    app.connect_handle_local_options(|_, _| std::ops::ControlFlow::Continue(()));
    app.connect_activate(move |app| {
        let window = gtk::ApplicationWindow::new(app);
        window.set_title(Some("D-Bus serial example"));
        let term = vte::Terminal::new();
        window.set_child(Some(&term));

        let id = chardev_id.clone();
        MainContext::default().spawn_local(clone!(async move {
            let conn = Connection::session()
                .await
                .expect("Failed to connect to session D-Bus");

            let c = if let Some(id) = id {
                Chardev::new(&conn, &id).await.unwrap()
            } else {
                let display = Display::new(&conn, Option::<&str>::None).await.unwrap();
                let mut found = None;
                for c in display.chardevs().await {
                    if c.proxy.name().await.ok() == Some("org.qemu.console.serial.0".to_string()) {
                        found = Some(c);
                        break;
                    }
                }
                found.expect("No chardev with name 'org.qemu.console.serial.0' found")
            };
            c.proxy.name().await.expect("Chardev not found");

            let (p0, p1) = UnixStream::pair().unwrap();
            if c.proxy.register((&p1).into()).await.is_ok() {
                let ostream = unsafe { gio_unix::OutputStream::with_fd(p0.as_raw_fd()) };
                let istream = gio_unix::InputStream::take_fd(p0.into())
                    .dynamic_cast::<gio::PollableInputStream>()
                    .unwrap();

                let mut read = istream.into_async_read().unwrap();
                term.connect_commit(move |_, text, _| {
                    let _res = ostream.write(text.as_bytes(), gio::Cancellable::NONE);
                    // TODO cancellable and error
                });

                loop {
                    let mut buffer = [0u8; 8192];
                    match read.read(&mut buffer[..]).await {
                        Ok(0) => break,
                        Ok(len) => {
                            term.feed(&buffer[..len]);
                        }
                        Err(e) => {
                            log::warn!("{}", e);
                            break;
                        }
                    }
                }
            }
        }));

        window.set_visible(true);
    });

    app.run();
}
