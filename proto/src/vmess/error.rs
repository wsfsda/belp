use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct Error {
    inner: ErrorKind,
}

impl Error {
    pub(crate) fn new_channel_close() -> Self {
        Error {
            inner: ErrorKind::ChannelClose,
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Uri(http::uri::InvalidUri),
    Uuid(uuid::Error),
    Config(super::config::ErrorKind),
    Io(std::io::Error),
    Head(super::conn::InvalidHead),
    ChannelClose,
}

impl From<http::uri::InvalidUri> for Error {
    fn from(error: http::uri::InvalidUri) -> Self {
        Error {
            inner: ErrorKind::Uri(error),
        }
    }
}

impl From<uuid::Error> for Error {
    fn from(error: uuid::Error) -> Self {
        Error {
            inner: ErrorKind::Uuid(error),
        }
    }
}

impl From<super::config::ErrorKind> for Error {
    fn from(error: super::config::ErrorKind) -> Self {
        Error {
            inner: ErrorKind::Config(error),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error {
            inner: ErrorKind::Io(error),
        }
    }
}

impl From<super::conn::InvalidHead> for Error {
    fn from(error: super::conn::InvalidHead) -> Self {
        Error {
            inner: ErrorKind::Head(error),
        }
    }
}

impl From<want::Closed> for Error {
    fn from(_: want::Closed) -> Self {
        Error {
            inner: ErrorKind::ChannelClose,
        }
    }
}

impl<T> From<mpsc::error::SendError<T>> for Error {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        Error {
            inner: ErrorKind::ChannelClose,
        }
    }
}

impl From<oneshot::error::RecvError> for Error {
    fn from(_: oneshot::error::RecvError) -> Self {
        Error {
            inner: ErrorKind::ChannelClose,
        }
    }
}
