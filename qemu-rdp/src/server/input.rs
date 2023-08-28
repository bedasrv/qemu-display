use qemu_display::{zbus, Console, KeyboardProxy, MouseButton, MouseProxy};

use ironrdp::server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};

pub struct InputHandler<'a> {
    pos: (u16, u16),
    mouse: MouseProxy<'a>,
    keyboard: KeyboardProxy<'a>,
}

#[async_trait::async_trait]
impl<'a> RdpServerInputHandler for InputHandler<'a> {
    async fn keyboard(&mut self, event: KeyboardEvent) {
        let result = match event {
            KeyboardEvent::Pressed { code, .. } => self.keyboard.press(code as u32).await,
            KeyboardEvent::Released { code, .. } => self.keyboard.release(code as u32).await,
            other => {
                eprintln!("unhandled keyboard event: {:?}", other);
                Ok(())
            }
        };

        if let Err(e) = result {
            eprintln!("keyboard error: {:?}", e);
        }
    }

    async fn mouse(&mut self, event: MouseEvent) {
        let result = match event {
            MouseEvent::Move { x, y } => self.mouse_move(x, y).await,
            MouseEvent::RightPressed => self.mouse.press(MouseButton::Right).await,
            MouseEvent::RightReleased => self.mouse.release(MouseButton::Right).await,
            MouseEvent::LeftPressed => self.mouse.press(MouseButton::Left).await,
            MouseEvent::LeftReleased => self.mouse.release(MouseButton::Left).await,
            MouseEvent::VerticalScroll { value } => {
                let motion = if value > 0 {
                    MouseButton::WheelUp
                } else {
                    MouseButton::WheelDown
                };

                self.mouse.press(motion).await
            }
        };

        if let Err(e) = result {
            eprintln!("keyboard error: {:?}", e);
        }
    }
}

impl<'a> InputHandler<'a> {
    pub async fn connect(dbus: zbus::Connection) -> anyhow::Result<InputHandler<'a>> {
        let console = Console::new(&dbus, 0).await?;

        Ok(Self {
            pos: (0, 0),
            mouse: console.mouse,
            keyboard: console.keyboard,
        })
    }

    pub async fn mouse_move(&mut self, x: u16, y: u16) -> Result<(), zbus::Error> {
        if self.mouse.is_absolute().await.unwrap_or(true) {
            self.mouse.set_abs_position(x.into(), y.into()).await
        } else {
            let (dx, dy) = (x as i32 - self.pos.0 as i32, y as i32 - self.pos.1 as i32);
            let res = self.mouse.rel_motion(dx, dy).await;
            self.pos = (x, y);

            res
        }
    }
}
