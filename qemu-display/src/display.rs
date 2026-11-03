use futures::stream::{self, StreamExt};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    rc::Rc,
};
use zbus::{
    fdo,
    fdo::ManagedObjects,
    names::{BusName, OwnedUniqueName, UniqueName, WellKnownName},
    proxy::OwnerChangedStream,
    Connection, OwnedObjectPath,
};

use crate::{Audio, Chardev, Clipboard, Error, Result, VMProxy};

#[cfg(all(unix, feature = "qmp"))]
use std::os::unix::net::UnixStream;
#[cfg(all(windows, feature = "qmp"))]
use uds_windows::UnixStream;

struct Inner<'d> {
    proxy: fdo::ObjectManagerProxy<'d>,
    conn: Connection,
    objects: ManagedObjects,
    #[cfg(windows)]
    peer_pid: u32,
}

#[derive(Clone)]
pub struct Display<'d> {
    inner: Rc<Inner<'d>>,
}

impl<'d> Display<'d> {
    pub async fn lookup(
        conn: &Connection,
        wait: bool,
        name: Option<&str>,
    ) -> Result<Option<OwnedUniqueName>> {
        let mut changed = fdo::DBusProxy::new(conn)
            .await?
            .receive_name_owner_changed()
            .await?;
        loop {
            let list = Display::list_by_name(conn).await?;
            if let Some(name) = name {
                let res = list.get(name);
                if res.is_some() {
                    return Ok(res.cloned());
                }
            } else if !list.is_empty() {
                return Ok(None);
            }
            if !wait {
                return Err(Error::Failed("Can't find VM".into()));
            };
            let _ = changed.next().await;
        }
    }

    pub async fn list_by_name(conn: &Connection) -> Result<HashMap<String, OwnedUniqueName>> {
        let mut hm = HashMap::new();
        let list = match fdo::DBusProxy::new(conn)
            .await?
            .list_queued_owners(WellKnownName::from_str_unchecked("org.qemu"))
            .await
        {
            Ok(list) => list,
            Err(zbus::fdo::Error::NameHasNoOwner(_)) => vec![],
            Err(e) => return Err(e.into()),
        };
        for dest in list.into_iter() {
            let name = VMProxy::builder(conn)
                .destination(UniqueName::from(&dest))
                .build()
                .await?
                .name()
                .await?;
            hm.insert(name, dest);
        }
        Ok(hm)
    }

    pub async fn new<D>(
        conn: &Connection,
        dest: Option<D>,
        #[cfg(windows)] peer_pid: u32,
    ) -> Result<Display<'d>>
    where
        D: TryInto<BusName<'d>>,
        D::Error: Into<Error>,
    {
        let builder = fdo::ObjectManagerProxy::builder(conn).destination("org.qemu");
        let builder = if let Some(dest) = dest {
            let dest = dest.try_into().map_err(Into::into)?;
            builder.destination(dest)
        } else {
            builder
        };
        let proxy = builder.path("/org/qemu/Display1").build().await?;
        let objects = proxy
            .get_managed_objects()
            .await
            .map_err(|e| Error::Failed(format!("Unreachable QEMU display ({e})")))?;

        // TODO: listen for changes
        let inner = Inner {
            // owner_changed,
            proxy,
            conn: conn.clone(),
            objects,
            #[cfg(windows)]
            peer_pid,
        };

        Ok(Self {
            inner: Rc::new(inner),
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.inner.conn
    }

    pub fn destination(&self) -> &BusName<'_> {
        self.inner.proxy.inner().destination()
    }

    #[cfg(windows)]
    pub fn peer_pid(&self) -> u32 {
        self.inner.peer_pid
    }

    #[cfg(feature = "qmp")]
    pub async fn new_qmp<P: AsRef<std::path::Path>>(path: P) -> Result<Display<'d>> {
        use qapi::{qmp, Qmp};

        let stream = UnixStream::connect(path)?;
        let mut qmp = Qmp::from_stream(&stream);
        let _info = qmp.handshake()?;

        let (p0, p1) = UnixStream::pair()?;

        #[cfg(unix)]
        {
            // FIXME: no ancillary fd API at this point
            // https://github.com/rust-lang/rust/issues/76915
            let _ = p0;
            qmp.execute(&qmp::getfd {
                fdname: "fdname".into(),
            })?;
        }
        #[cfg(windows)]
        let pid = {
            use crate::win32::{duplicate_socket, unix_stream_get_peer_pid};
            use serde::{Deserialize, Serialize};
            use std::os::windows::io::AsRawSocket;
            use windows::Win32::Networking::WinSock::SOCKET;

            #[allow(non_camel_case_types)]
            #[derive(Debug, Clone, Serialize, Deserialize)]
            pub struct get_win32_socket {
                #[serde(rename = "info")]
                pub info: ::std::string::String,
                #[serde(rename = "fdname")]
                pub fdname: ::std::string::String,
            }

            impl qmp::QmpCommand for get_win32_socket {}
            impl qapi::Command for get_win32_socket {
                const NAME: &'static str = "get-win32-socket";
                const ALLOW_OOB: bool = false;

                type Ok = qapi::Empty;
            }

            let pid = unix_stream_get_peer_pid(&stream)?;
            let info = duplicate_socket(pid, SOCKET(p0.as_raw_socket() as _))?;
            use base64::prelude::*;
            let info = BASE64_STANDARD.encode(info);
            qmp.execute(&get_win32_socket {
                info,
                fdname: "fdname".into(),
            })?;
            pid
        };

        qmp.execute(&qmp::add_client {
            skipauth: None,
            tls: None,
            protocol: "@dbus-display".into(),
            fdname: "fdname".into(),
        })?;

        let conn = zbus::connection::Builder::async_io_unix_stream(p1).p2p();
        #[cfg(windows)]
        let conn = conn.auth_mechanism(zbus::conn::AuthMechanism::Anonymous);
        let conn = conn.build().await?;

        Self::new(
            &conn,
            Option::<String>::None,
            #[cfg(windows)]
            pid,
        )
        .await
    }

    pub fn inner_proxy(&self) -> &zbus::Proxy<'d> {
        self.inner.proxy.inner()
    }

    pub async fn receive_owner_changed(&self) -> Result<OwnerChangedStream<'_>> {
        Ok(self.inner.proxy.inner().receive_owner_changed().await?)
    }

    pub async fn audio(&self) -> Result<Option<Audio>> {
        if !self
            .inner
            .objects
            .contains_key(&OwnedObjectPath::try_from("/org/qemu/Display1/Audio").unwrap())
        {
            return Ok(None);
        }

        Ok(Some(
            Audio::new(
                &self.inner.conn,
                Some(self.inner.proxy.inner().destination().to_owned()),
                #[cfg(windows)]
                self.peer_pid(),
            )
            .await?,
        ))
    }

    pub async fn clipboard(&self) -> Result<Option<Clipboard>> {
        if !self
            .inner
            .objects
            .contains_key(&OwnedObjectPath::try_from("/org/qemu/Display1/Clipboard").unwrap())
        {
            return Ok(None);
        }

        Ok(Some(Clipboard::new(&self.inner.conn).await?))
    }

    /// Whether the peer has an audio interface to register a listener with.
    ///
    /// QEMU only exports `/org/qemu/Display1/Audio` when the VM has an audio
    /// device, and its own client asks before it registers rather than after:
    ///
    /// ```c
    /// iface = g_dbus_object_manager_get_interface(manager,
    ///          DBUS_DISPLAY1_ROOT "/Audio", "org.qemu.Display1.Audio");
    /// if (!iface) {
    ///     return;
    /// }
    /// ```
    ///
    /// Asking afterwards looks equivalent and is not. `RegisterOutListener`
    /// takes a file descriptor, so the difference between not sending it and
    /// sending it to an object that does not exist is a descriptor handed to
    /// the peer for nothing — and the answer, `UnknownMethod`, only arrives
    /// once it is too late. The object manager already listed the peer's
    /// objects, so the question can be answered before anything is sent.
    pub fn has_audio(&self) -> bool {
        const AUDIO_PATH: &str = "/org/qemu/Display1/Audio";
        const AUDIO: &str = "org.qemu.Display1.Audio";
        self.inner.objects.iter().any(|(path, interfaces)| {
            path.as_str() == AUDIO_PATH
                && interfaces.keys().any(|name| name.as_str() == AUDIO)
        })
    }

    /// The chardevs the peer exports, in the order it lists them.
    ///
    /// The path alone does not make an object a chardev, and QEMU's own client
    /// checks the interface as well as the prefix:
    ///
    /// ```c
    /// iface = g_dbus_object_get_interface(obj, "org.qemu.Display1.Chardev");
    /// if (!iface) {
    ///     continue;
    /// }
    /// ```
    ///
    /// Skipping that is not a crash on its own — a `Get` at an object without
    /// the interface comes back as an error and the caller moves on — but it
    /// does mean sending methods to objects that are not chardevs, on a
    /// connection where the peer is a fixed piece of software rather than a bus
    /// that can shrug it off.
    pub async fn chardevs(&self) -> Vec<Chardev> {
        const CHARDEV: &str = "org.qemu.Display1.Chardev";
        stream::iter(&self.inner.objects)
            .filter_map(|(p, interfaces)| async move {
                if !interfaces.keys().any(|name| name.as_str() == CHARDEV) {
                    return None;
                }
                match p.strip_prefix("/org/qemu/Display1/Chardev_") {
                    Some(id) => Chardev::new(&self.inner.conn, id).await.ok(),
                    _ => None,
                }
            })
            .collect()
            .await
    }

    #[cfg(unix)]
    pub async fn usbredir_chardevs(&self) -> Vec<Chardev> {
        stream::iter(self.chardevs().await)
            .filter_map(|c| async move {
                if c.proxy.name().await.ok().as_deref() == Some("org.qemu.usbredir") {
                    Some(c)
                } else {
                    None
                }
            })
            .collect()
            .await
    }
}
