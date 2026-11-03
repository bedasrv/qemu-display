use std::{env::args, error::Error, thread::sleep, time::Duration};

use qemu_display::Display;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let qmp_path = args().nth(1).expect("argument: QMP socket path");
    // Named and not bound: the display has to stay alive for the loop below to
    // have anything to connect to, and `Display::new_qmp` is what starts it.
    let _display = Display::new_qmp(qmp_path).await?;

    loop {
        sleep(Duration::from_secs(1));
    }
}
