use qemu_display::{Console, KeyboardProxy, MouseButton, MouseProxy};

use ironrdp_server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};

pub struct InputHandler<'a> {
    dbus: zbus::Connection,
    mouse: MouseProxy<'a>,
    keyboard: KeyboardProxy<'a>,
}

#[async_trait::async_trait]
impl<'a> RdpServerInputHandler for InputHandler<'a> {
    async fn keyboard(&mut self, event: KeyboardEvent) {
        let result = match event {
            KeyboardEvent::Pressed(code) => {
                self.keyboard.press(code as u32).await
            }

            KeyboardEvent::Released(code) => {
                self.keyboard.release(code as u32).await
            }
        };

        if let Err(e) = result {
            eprintln!("keyboard error: {:?}", e);
        }
    }

    async fn mouse(&mut self, event: MouseEvent) {
        let result = match event {
            MouseEvent::Move { x, y } => {
                self.mouse.set_abs_position(x as u32, y as u32).await
            }
            MouseEvent::RightPressed => {
                self.mouse.press(MouseButton::Right).await
            }
            MouseEvent::RightReleased => {
                self.mouse.release(MouseButton::Right).await
            }
            MouseEvent::LeftPressed => {
                self.mouse.press(MouseButton::Left).await
            }
            MouseEvent::LeftReleased => {
                self.mouse.release(MouseButton::Left).await
            }
            MouseEvent::Scroll => {
                unimplemented!()
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
            dbus,
            mouse: console.mouse,
            keyboard: console.keyboard,
        })
    }
}
