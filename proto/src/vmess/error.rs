pub struct Error {
    inner: ErrorKind,
}

enum ErrorKind {
    Uri(http::uri::InvalidUri),
    Uuid(uuid::Error),
    Config(super::config::ErrorKind)
}

impl From<http::uri::InvalidUri> for Error {
    fn from(error: http::uri::InvalidUri) -> Self {
        Error { inner: ErrorKind::Uri(error) }
    }
}

impl From<uuid::Error> for Error {
    fn from(error: uuid::Error) -> Self {
        Error { inner: ErrorKind::Uuid(error) }
    }
}

impl From<super::config::ErrorKind> for Error {
    fn from(error: super::config::ErrorKind) -> Self {
        Error { inner: ErrorKind::Config(error) }
    }
}

