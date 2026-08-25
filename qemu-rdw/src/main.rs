use gio::ApplicationFlags;
use glib::MainContext;
use gtk::{gio, glib, prelude::*};
#[cfg(unix)]
use qemu_display::UsbRedir;
use qemu_display::{util, Chardev, Display};
use rdw::gtk::{self, glib::ExitCode};
use std::{cell::RefCell, convert::TryFrom, ops::ControlFlow, rc::Rc};
use zbus::names::BusName;

struct Inner {
    app: gtk::Application,
    #[cfg(unix)]
    usbredir: RefCell<Option<rdw_qemu::UsbRedirHandler>>,
}

#[derive(Clone)]
struct App {
    inner: Rc<Inner>,
}

#[derive(Debug, Default)]
struct AppOptions {
    vm_name: Option<String>,
    address: Option<String>,
    #[cfg(feature = "qmp")]
    qmp: Option<String>,
    list: bool,
    wait: bool,
}

async fn display_from_opt(opt: Rc<RefCell<AppOptions>>) -> Option<Display<'static>> {
    #[cfg(feature = "qmp")]
    if let Some(qmp_addr) = &opt.borrow().qmp {
        return Some(Display::new_qmp(qmp_addr).await.unwrap());
    }
    let builder = if let Some(addr) = &opt.borrow().address {
        zbus::connection::Builder::address(addr.as_str())
    } else {
        zbus::connection::Builder::session()
    };
    let conn = match builder.unwrap().internal_executor(false).build().await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("Failed to connect to DBus: {err}");
            return None;
        }
    };
    let conn_clone = conn.clone();
    MainContext::default().spawn_local(async move {
        loop {
            conn_clone.executor().tick().await;
        }
    });

    if opt.borrow().list {
        let list = Display::list_by_name(&conn).await.unwrap();
        for (name, dest) in list {
            println!("{} (at {})", name, dest);
        }
        return None;
    }
    let dest = if opt.borrow().vm_name.is_some() {
        let name = opt.borrow().vm_name.clone();
        let wait = opt.borrow().wait;

        Display::lookup(&conn, wait, name.as_deref())
            .await
            .unwrap()
            .map(Into::into)
    } else {
        if opt.borrow().wait {
            Display::lookup(&conn, true, None).await.unwrap();
        }
        BusName::try_from("org.qemu").ok()
    };

    Display::new(
        &conn,
        dest,
        #[cfg(windows)]
        unimplemented!(),
    )
    .await
    .ok()
}

impl App {
    fn new() -> Self {
        let app = gtk::Application::new(Some("org.qemu.rdw.demo"), ApplicationFlags::NON_UNIQUE);
        app.add_main_option(
            glib::OPTION_REMAINING,
            glib::Char(0),
            glib::OptionFlags::NONE,
            glib::OptionArg::StringArray,
            "VM name",
            Some("VM-NAME"),
        );
        app.add_main_option(
            "address",
            glib::Char(b'a' as _),
            glib::OptionFlags::NONE,
            glib::OptionArg::String,
            "D-Bus bus address",
            None,
        );
        #[cfg(feature = "qmp")]
        app.add_main_option(
            "qmp",
            glib::Char(b'q' as _),
            glib::OptionFlags::NONE,
            glib::OptionArg::String,
            "QMP monitor address",
            None,
        );
        app.add_main_option(
            "list",
            glib::Char(0),
            glib::OptionFlags::NONE,
            glib::OptionArg::None,
            "List available VM names",
            None,
        );
        app.add_main_option(
            "wait",
            glib::Char(0),
            glib::OptionFlags::NONE,
            glib::OptionArg::None,
            "Wait for display to be available",
            None,
        );
        app.add_main_option(
            "version",
            glib::Char(0),
            glib::OptionFlags::NONE,
            glib::OptionArg::None,
            "Show program version",
            None,
        );

        let opt: Rc<RefCell<AppOptions>> = Default::default();
        let opt_clone = opt.clone();
        app.connect_handle_local_options(move |_, opt| {
            let mut app_opt = opt_clone.borrow_mut();
            if opt.lookup_value("version", None).is_some() {
                println!("Version: {}", env!("CARGO_PKG_VERSION"));
                return ControlFlow::Break(ExitCode::new(0));
            }
            if let Some(arg) = opt.lookup_value("address", None) {
                app_opt.address = arg.get::<String>();
            }
            #[cfg(feature = "qmp")]
            if let Some(arg) = opt.lookup_value("qmp", None) {
                app_opt.qmp = arg.get::<String>();
            }
            if opt.lookup_value("list", None).is_some() {
                app_opt.list = true;
            }
            if opt.lookup_value("wait", None).is_some() {
                app_opt.wait = true;
            }
            app_opt.vm_name = opt
                .lookup_value(glib::OPTION_REMAINING, None)
                .and_then(|args| args.child_value(0).get::<String>());
            ControlFlow::Continue(())
        });

        let app = App {
            inner: Rc::new(Inner {
                app,
                #[cfg(unix)]
                usbredir: Default::default(),
            }),
        };

        let app_clone = app.clone();
        app.inner.app.connect_activate(move |app| {
            let ui_src = include_str!("main.ui");
            let builder = gtk::Builder::new();
            builder
                .add_from_string(ui_src)
                .expect("Couldn't add from string");
            let window: gtk::ApplicationWindow =
                builder.object("window").expect("Couldn't get window");
            window.set_application(Some(app));

            let app_clone = app_clone.clone();
            let opt_clone = opt.clone();
            MainContext::default().spawn_local(async move {
                let display = match display_from_opt(opt_clone).await {
                    Some(d) => d,
                    None => {
                        app_clone.inner.app.quit();
                        return;
                    }
                };
                let disp = display.clone();
                let app = app_clone.clone();
                let rdw = rdw_qemu::Display::new_with_qemu_display(
                    &disp,
                    Some(move |_| app.inner.app.quit()),
                )
                .await
                .expect("Failed to initialize the rdw_qemu::Display");
                app_clone
                    .inner
                    .app
                    .active_window()
                    .unwrap()
                    .set_child(Some(&rdw));

                #[cfg(unix)]
                {
                    let chardevs = display.usbredir_chardevs().await;
                    let usbredir = UsbRedir::new(chardevs, rdw_qemu::RusbBackend);
                    app_clone.set_usbredir(rdw_qemu::UsbRedirHandler::new(usbredir));
                }

                if let Ok(c) = Chardev::new(display.connection(), "qmp").await {
                    use std::io::{prelude::*, BufReader};
                    #[cfg(unix)]
                    use std::os::unix::net::UnixStream;
                    #[cfg(windows)]
                    use uds_windows::UnixStream;

                    let (p0, p1) = UnixStream::pair().unwrap();
                    let fd = util::prepare_uds_pass(
                        #[cfg(windows)]
                        display.peer_pid(),
                        &p1,
                    )
                    .unwrap();
                    if c.proxy.register(fd).await.is_ok() {
                        let mut reader = BufReader::new(p0.try_clone().unwrap());
                        let mut line = String::new();
                        std::thread::spawn(move || loop {
                            if reader.read_line(&mut line).unwrap() > 0 {
                                println!("{}", line);
                            }
                        });
                    }
                }

                window.present();
            });
        });

        #[cfg(unix)]
        {
            let action_usb = gio::SimpleAction::new("usb", None);
            let app_clone = app.clone();
            action_usb.connect_activate(move |_, _| {
                let usbredir = app_clone.inner.usbredir.borrow();
                if let Some(usbredir) = usbredir.as_ref() {
                    let dialog = gtk::Window::new();
                    dialog.set_transient_for(app_clone.inner.app.active_window().as_ref());
                    dialog.set_child(Some(&usbredir.widget()));
                    dialog.present();
                }
            });
            app.inner.app.add_action(&action_usb);
        }

        app
    }

    #[cfg(unix)]
    fn set_usbredir(&self, usbredir: rdw_qemu::UsbRedirHandler) {
        self.inner.usbredir.replace(Some(usbredir));
    }

    fn run(&self) -> ExitCode {
        self.inner.app.run()
    }
}

fn main() {
    pretty_env_logger::init();
    tracing_subscriber::fmt::init();
    // TODO: This always fails? We have already set up a logger above.
    rdw::setup_logger(log::logger(), log::max_level()).ok();

    let app = App::new();
    app.run();
}
