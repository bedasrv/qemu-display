use futures_util::StreamExt;
use glib::{clone, subclass::prelude::*, MainContext};
use gtk::glib;
use once_cell::sync::OnceCell;
use qemu_display::{Console, ConsoleListenerHandler};
#[cfg(windows)]
use qemu_display::{ConsoleListenerD3d11Handler, ConsoleListenerMapHandler};
use rdw::{gtk, DisplayExt};
use std::cell::Cell;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;

mod imp {
    use super::*;
    use gtk::subclass::prelude::*;
    #[cfg(windows)]
    use std::cell::RefCell;
    #[cfg(windows)]
    use std::ffi::c_void;
    #[cfg(windows)]
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    #[repr(C)]
    pub struct RdwDisplayQemuClass {
        pub parent_class: rdw::RdwDisplayClass,
    }

    unsafe impl ClassStruct for RdwDisplayQemuClass {
        type Type = Display;
    }

    #[repr(C)]
    pub struct RdwDisplayQemu {
        parent: rdw::RdwDisplay,
    }

    impl std::fmt::Debug for RdwDisplayQemu {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("RdwDisplayQemu")
                .field("parent", &self.parent)
                .finish()
        }
    }

    unsafe impl InstanceStruct for RdwDisplayQemu {
        type Type = Display;
    }

    #[cfg(windows)]
    #[derive(Debug)]
    struct MemoryMap {
        handle: HANDLE,
        ptr: *const c_void,
        offset: isize,
        size: usize,
    }

    #[cfg(windows)]
    impl Drop for MemoryMap {
        fn drop(&mut self) {
            unsafe {
                use windows::Win32::System::Memory::UnmapViewOfFile;

                UnmapViewOfFile(self.ptr);
                CloseHandle(self.handle);
            }
        }
    }

    #[cfg(windows)]
    impl MemoryMap {
        fn as_bytes(&self) -> &[u8] {
            unsafe {
                std::slice::from_raw_parts(self.ptr.cast::<u8>().offset(self.offset), self.size)
            }
        }
    }

    #[derive(Debug, Default)]
    pub struct Display {
        pub(crate) console: OnceCell<Console>,
        keymap: Cell<Option<&'static [u16]>>,
        #[cfg(windows)]
        scanout_map: RefCell<Option<(MemoryMap, u32)>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Display {
        const NAME: &'static str = "RdwDisplayQemu";
        type Type = super::Display;
        type ParentType = rdw::Display;
        type Class = RdwDisplayQemuClass;
        type Instance = RdwDisplayQemu;
    }

    impl ObjectImpl for Display {
        fn constructed(&self) {
            self.parent_constructed();

            self.obj().set_mouse_absolute(false);

            self.obj().connect_key_event(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, keyval, keycode, event| {
                    let mapped = this
                        .keymap
                        .get()
                        .and_then(|m| m.get(keycode as usize))
                        .map(|x| *x as u32);
                    log::debug!("key-{event:?}: {keyval} {keycode} -> {mapped:?}");
                    if let Some(qnum) = mapped {
                        MainContext::default().spawn_local(clone!(
                            #[weak]
                            this,
                            async move {
                                if event.contains(rdw::KeyEvent::PRESS) {
                                    let _ = this.obj().console().keyboard.press(qnum).await;
                                }
                                if event.contains(rdw::KeyEvent::RELEASE) {
                                    let _ = this.obj().console().keyboard.release(qnum).await;
                                }
                            }
                        ));
                    }
                }
            ));

            self.obj().connect_motion(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, x, y| {
                    log::trace!("motion: {:?}", (x, y));
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            if !this
                                .obj()
                                .console()
                                .mouse
                                .is_absolute()
                                .await
                                .unwrap_or(false)
                            {
                                return;
                            }
                            if let Err(e) = this
                                .obj()
                                .console()
                                .mouse
                                .set_abs_position(x as _, y as _)
                                .await
                            {
                                log::warn!("{e}");
                            }
                        }
                    ));
                }
            ));

            self.obj().connect_motion_relative(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, dx, dy| {
                    log::trace!("motion-relative: {:?}", (dx, dy));
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            let _ = this
                                .obj()
                                .console()
                                .mouse
                                .rel_motion(dx.round() as _, dy.round() as _)
                                .await;
                        }
                    ));
                }
            ));

            self.obj().connect_mouse_press(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, button| {
                    log::debug!("mouse-press: {:?}", button);
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            let button = from_gdk_button(button);
                            let _ = this.obj().console().mouse.press(button).await;
                        }
                    ));
                }
            ));

            self.obj().connect_mouse_release(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, button| {
                    log::debug!("mouse-release: {:?}", button);
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            let button = from_gdk_button(button);
                            let _ = this.obj().console().mouse.release(button).await;
                        }
                    ));
                }
            ));

            self.obj().connect_scroll_discrete(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, scroll| {
                    use qemu_display::MouseButton;

                    log::debug!("scroll-discrete: {:?}", scroll);

                    let button = match scroll {
                        rdw::Scroll::Up => MouseButton::WheelUp,
                        rdw::Scroll::Down => MouseButton::WheelDown,
                        _ => {
                            log::warn!("not yet implemented");
                            return;
                        }
                    };
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            let _ = this.obj().console().mouse.press(button).await;
                            let _ = this.obj().console().mouse.release(button).await;
                        }
                    ));
                }
            ));

            self.obj().connect_resize_request(clone!(
                #[weak(rename_to = this)]
                self,
                move |_, width, height, wmm, hmm| {
                    log::debug!("resize-request: {:?}", (width, height, wmm, hmm));
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            let _ = this
                                .obj()
                                .console()
                                .proxy
                                .set_ui_info(wmm as _, hmm as _, 0, 0, width, height)
                                .await;
                        }
                    ));
                }
            ));
        }
    }

    impl WidgetImpl for Display {
        fn realize(&self) {
            self.parent_realize();

            self.keymap.set(rdw::keymap_qnum());

            MainContext::default().spawn_local(clone!(
                #[weak(rename_to = this)]
                self,
                async move {
                    let console = this.console.get().unwrap();
                    // we have to use a channel, because widget is not Send..
                    let (sender, mut receiver) = futures::channel::mpsc::unbounded();
                    let handler = ConsoleHandler { sender };
                    console.register_listener(handler.clone()).await.unwrap();
                    #[cfg(windows)]
                    {
                        console.set_map_listener(handler.clone()).await.unwrap();
                        console.set_d3d11_listener(handler.clone()).await.unwrap();
                    }

                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            while let Some(e) = receiver.next().await {
                                use ConsoleEvent::*;
                                match e {
                                    Scanout(s) => {
                                        if s.format != 0x20020888 {
                                            log::warn!("Format not yet supported: {:X}", s.format);
                                            continue;
                                        }
                                        this.obj()
                                            .set_display_size(Some((s.width as _, s.height as _)));
                                        this.obj().update_area(
                                            0,
                                            0,
                                            s.width as _,
                                            s.height as _,
                                            s.stride as _,
                                            Some(&s.data),
                                        );
                                    }
                                    Update(u) => {
                                        if u.format != 0x20020888 {
                                            log::warn!("Format not yet supported: {:X}", u.format);
                                            continue;
                                        }
                                        this.obj().update_area(
                                            u.x as _,
                                            u.y as _,
                                            u.w as _,
                                            u.h as _,
                                            u.stride as _,
                                            Some(&u.data),
                                        );
                                    }
                                    #[cfg(windows)]
                                    ScanoutMap(s) => {
                                        use windows::Win32::System::Memory::{
                                            MapViewOfFile, FILE_MAP_READ,
                                        };

                                        log::debug!("{s:?}");
                                        if s.format != 0x20020888 {
                                            log::warn!("Format not yet supported: {:X}", s.format);
                                            continue;
                                        }

                                        let handle = HANDLE(s.handle as _);
                                        let size = s.height as usize * s.stride as usize;
                                        let offset = s.offset as isize;
                                        let ptr = unsafe {
                                            MapViewOfFile(
                                                handle,
                                                FILE_MAP_READ,
                                                0,
                                                0,
                                                s.offset as usize + size,
                                            )
                                        };
                                        if ptr.is_null() {
                                            log::warn!("Failed to map scanout!");
                                            continue;
                                        }

                                        let map = MemoryMap {
                                            ptr,
                                            handle,
                                            offset,
                                            size,
                                        };
                                        this.obj()
                                            .set_display_size(Some((s.width as _, s.height as _)));
                                        this.obj().update_area(
                                            0,
                                            0,
                                            s.width as _,
                                            s.height as _,
                                            s.stride as _,
                                            Some(map.as_bytes()),
                                        );
                                        this.scanout_map.replace(Some((map, s.stride)));
                                    }
                                    #[cfg(windows)]
                                    UpdateMap(u) => {
                                        log::debug!("{u:?}");
                                        let scanout_map = this.scanout_map.borrow();
                                        let Some((map, stride)) = scanout_map.as_ref() else {
                                            log::warn!("No mapped scanout!");
                                            continue;
                                        };
                                        let stride = *stride;
                                        let bytes = map.as_bytes();
                                        this.obj().update_area(
                                            u.x as _,
                                            u.y as _,
                                            u.w as _,
                                            u.h as _,
                                            stride as _,
                                            Some(
                                                &bytes[u.y as usize * stride as usize
                                                    + u.x as usize * 4..],
                                            ),
                                        );
                                    }
                                    #[cfg(windows)]
                                    ScanoutD3dTexture2d(s) => {
                                        log::debug!("{s:?}");
                                        this.obj().set_display_size(Some((s.w as _, s.h as _)));
                                        this.obj().set_d3d11_texture2d_scanout(Some(
                                            rdw::RdwD3d11Texture2dScanout {
                                                handle: s.handle as _,
                                                tex_width: s.tex_width,
                                                tex_height: s.tex_height,
                                                y0_top: s.y0_top,
                                                x: s.x,
                                                y: s.y,
                                                w: s.w,
                                                h: s.h,
                                            },
                                        ));
                                    }
                                    #[cfg(windows)]
                                    UpdateD3dTexture2d { wait_tx, update } => {
                                        this.obj().set_d3d11_texture2d_can_acquire(true);
                                        this.obj().update_area(
                                            update.x, update.y, update.w, update.h, 0, None,
                                        );
                                        this.obj().set_d3d11_texture2d_can_acquire(false);
                                        let _ = wait_tx.send(());
                                    }
                                    #[cfg(unix)]
                                    ScanoutDMABUF(s) => {
                                        log::trace!("{s:?}");
                                        this.obj()
                                            .set_display_size(Some((s.width as _, s.height as _)));
                                        this.obj().set_dmabuf_scanout(rdw::RdwDmabufScanout {
                                            width: s.width,
                                            height: s.height,
                                            stride: s.stride,
                                            fourcc: s.fourcc,
                                            y0_top: s.y0_top,
                                            modifier: s.modifier,
                                            fd: s.into_raw_fd(),
                                        });
                                    }
                                    #[cfg(unix)]
                                    UpdateDMABUF { wait_tx, update } => {
                                        this.obj().update_area(
                                            update.x, update.y, update.w, update.h, 0, None,
                                        );
                                        let _ = wait_tx.send(());
                                    }
                                    Disable => {
                                        log::warn!("Display disabled");
                                    }
                                    Disconnected => {
                                        log::warn!("Console disconnected");
                                    }
                                    CursorDefine(c) => {
                                        log::debug!("{c:?}");
                                        let cursor = rdw::Display::make_cursor(
                                            &c.data, c.width, c.height, c.hot_x, c.hot_y, 1,
                                        );
                                        this.obj().define_cursor(Some(cursor));
                                    }
                                    MouseSet(m) => {
                                        if m.on != 0 {
                                            this.obj()
                                                .set_cursor_position(Some((m.x as _, m.y as _)));
                                        } else {
                                            this.obj().set_cursor_position(None);
                                        }
                                    }
                                }
                            }
                        }
                    ));
                    let mut abs_changed = console.mouse.receive_is_absolute_changed().await;
                    this.obj()
                        .set_mouse_absolute(console.mouse.is_absolute().await.unwrap_or(false));
                    MainContext::default().spawn_local(clone!(
                        #[weak]
                        this,
                        async move {
                            while let Some(abs) = abs_changed.next().await {
                                if let Ok(abs) = abs.get().await {
                                    this.obj().set_mouse_absolute(abs);
                                }
                            }
                        }
                    ));
                }
            ));
        }
    }

    impl rdw::DisplayImpl for Display {}
}

glib::wrapper! {
    pub struct Display(ObjectSubclass<imp::Display>) @extends rdw::Display, gtk::Widget, @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl Display {
    pub fn new(console: Console) -> Self {
        let obj = glib::Object::builder().build();
        let self_ = imp::Display::from_obj(&obj);
        self_.console.set(console).unwrap();
        obj
    }

    pub fn console(&self) -> &Console {
        let self_ = imp::Display::from_obj(self);
        self_.console.get().unwrap()
    }
}

#[derive(Debug)]
enum ConsoleEvent {
    Scanout(qemu_display::Scanout),
    Update(qemu_display::Update),
    #[cfg(windows)]
    ScanoutMap(qemu_display::ScanoutMap),
    #[cfg(windows)]
    UpdateMap(qemu_display::UpdateMap),
    #[cfg(windows)]
    ScanoutD3dTexture2d(qemu_display::ScanoutD3dTexture2d),
    #[cfg(windows)]
    UpdateD3dTexture2d {
        update: qemu_display::UpdateD3dTexture2d,
        wait_tx: futures::channel::oneshot::Sender<()>,
    },
    #[cfg(unix)]
    ScanoutDMABUF(qemu_display::ScanoutDMABUF),
    #[cfg(unix)]
    UpdateDMABUF {
        update: qemu_display::UpdateDMABUF,
        wait_tx: futures::channel::oneshot::Sender<()>,
    },
    Disable,
    MouseSet(qemu_display::MouseSet),
    CursorDefine(qemu_display::Cursor),
    Disconnected,
}

#[derive(Clone)]
struct ConsoleHandler {
    sender: futures::channel::mpsc::UnboundedSender<ConsoleEvent>,
}

impl ConsoleHandler {
    fn send(&self, event: ConsoleEvent) {
        if let Err(e) = self.sender.unbounded_send(event) {
            log::warn!("failed to send console event: {}", e);
        }
    }
}

#[cfg(windows)]
#[async_trait::async_trait]
impl ConsoleListenerMapHandler for ConsoleHandler {
    #[cfg(windows)]
    async fn scanout_map(&mut self, scanout: qemu_display::ScanoutMap) {
        self.send(ConsoleEvent::ScanoutMap(scanout));
    }

    #[cfg(windows)]
    async fn update_map(&mut self, update: qemu_display::UpdateMap) {
        self.send(ConsoleEvent::UpdateMap(update));
    }
}

#[cfg(windows)]
#[async_trait::async_trait]
impl ConsoleListenerD3d11Handler for ConsoleHandler {
    #[cfg(windows)]
    async fn scanout_texture2d(&mut self, scanout: qemu_display::ScanoutD3dTexture2d) {
        self.send(ConsoleEvent::ScanoutD3dTexture2d(scanout));
    }

    #[cfg(windows)]
    async fn update_texture2d(&mut self, update: qemu_display::UpdateD3dTexture2d) {
        let (wait_tx, wait_rx) = futures::channel::oneshot::channel();
        self.send(ConsoleEvent::UpdateD3dTexture2d { update, wait_tx });
        if let Err(e) = wait_rx.await {
            log::warn!("wait update d3d texture2d failed: {}", e);
        }
    }
}

#[async_trait::async_trait]
impl ConsoleListenerHandler for ConsoleHandler {
    async fn scanout(&mut self, scanout: qemu_display::Scanout) {
        self.send(ConsoleEvent::Scanout(scanout));
    }

    async fn update(&mut self, update: qemu_display::Update) {
        self.send(ConsoleEvent::Update(update));
    }

    #[cfg(unix)]
    async fn scanout_dmabuf(&mut self, scanout: qemu_display::ScanoutDMABUF) {
        self.send(ConsoleEvent::ScanoutDMABUF(scanout));
    }

    #[cfg(unix)]
    async fn update_dmabuf(&mut self, update: qemu_display::UpdateDMABUF) {
        let (wait_tx, wait_rx) = futures::channel::oneshot::channel();
        self.send(ConsoleEvent::UpdateDMABUF { update, wait_tx });
        if let Err(e) = wait_rx.await {
            log::warn!("wait update dmabuf failed: {}", e);
        }
    }

    async fn disable(&mut self) {
        self.send(ConsoleEvent::Disable);
    }

    async fn mouse_set(&mut self, set: qemu_display::MouseSet) {
        self.send(ConsoleEvent::MouseSet(set));
    }

    async fn cursor_define(&mut self, cursor: qemu_display::Cursor) {
        self.send(ConsoleEvent::CursorDefine(cursor));
    }

    fn disconnected(&mut self) {
        self.send(ConsoleEvent::Disconnected);
    }

    fn interfaces(&self) -> Vec<String> {
        // todo: find a clever way to query the object server for this?
        if cfg!(windows) {
            vec![
                "org.qemu.Display1.Listener.Win32.Map".to_string(),
                "org.qemu.Display1.Listener.Win32.D3d11".to_string(),
            ]
        } else {
            vec![]
        }
    }
}

fn from_gdk_button(button: u32) -> qemu_display::MouseButton {
    use qemu_display::MouseButton::*;

    match button {
        1 => Left,
        2 => Middle,
        3 => Right,
        _ => Extra,
    }
}
