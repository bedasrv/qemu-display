use std::{env::args, error::Error, thread::sleep, time::Duration};

use qemu_display::Display;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let qmp_path = args().nth(1).expect("argument: QMP socket path");
    let _display = Display::new_qmp(qmp_path).await?;

    loop {
        sleep(Duration::from_secs(1));
    }
}
