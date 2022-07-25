use std::{fmt::Display, io, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    inner: ErrorKind,
}

impl Display for Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "dsds")
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
enum ErrorKind {
    Config(config::Error),
    Vmess(proto::vmess::Error),
    Io(io::Error),
}

impl From<config::Error> for Error {
    fn from(error: config::Error) -> Self {
        Error {
            inner: ErrorKind::Config(error),
        }
    }
}

impl From<proto::vmess::Error> for Error {
    fn from(error: proto::vmess::Error) -> Self {
        Error {
            inner: ErrorKind::Vmess(error),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error {
            inner: ErrorKind::Io(error),
        }
    }
}
