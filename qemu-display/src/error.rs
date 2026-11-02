use std::{convert::Infallible, error, fmt, io};

#[cfg(feature = "qmp")]
use qapi::ExecuteError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Zbus(zbus::Error),
    Failed(String),
    #[cfg(feature = "qmp")]
    Qmp(ExecuteError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Zbus(e) => write!(f, "zbus error: {e}"),
            Error::Failed(e) => write!(f, "{e}"),
            #[cfg(feature = "qmp")]
            Error::Qmp(e) => write!(f, "qmp error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Zbus(e) => Some(e),
            Error::Failed(_) => None,
            #[cfg(feature = "qmp")]
            Error::Qmp(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Error::Zbus(e)
    }
}

impl From<zbus::fdo::Error> for Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Error::Zbus(e.into())
    }
}

#[cfg(feature = "qmp")]
impl From<ExecuteError> for Error {
    fn from(e: ExecuteError) -> Self {
        Error::Qmp(e)
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
