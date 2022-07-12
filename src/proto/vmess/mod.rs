use std::error::Error as StdError;
use std::net::SocketAddr;

use http::Uri;

pub mod client;
pub mod conn2;
pub mod coon;
pub mod encrypt;
pub mod request;
pub mod response;

#[derive(Debug)]
pub struct Error(ErrorKind);

#[derive(Debug)]
enum ErrorKind {
    RequestBuild(request::InvalidRequest),
    Io(std::io::Error),
    InvalidHeader(coon::InvalidHeader),
    ConnError(conn2::ConnError),
}

impl From<conn2::ConnError> for Error {
    fn from(error: conn2::ConnError) -> Self {
        Error(ErrorKind::ConnError(error))
    }
}

impl From<coon::InvalidHeader> for Error {
    fn from(error: coon::InvalidHeader) -> Self {
        Error(ErrorKind::InvalidHeader(error))
    }
}

impl From<request::InvalidRequest> for Error {
    fn from(error: request::InvalidRequest) -> Self {
        Error(ErrorKind::RequestBuild(error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error(ErrorKind::Io(error))
    }
}

pub enum Version {
    V1,
}

impl Version {
    // const V1: Version = Version::V1;
}

pub enum Opt {
    S,
    M,
}

impl Opt {
    // const S: Opt = Opt::S;
    // const R: Opt = Opt::M;
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Encryption {
    Aes123Gcm,
    ChaCha20Poly1305,
    None,
}

impl Encryption {
    // const AES_123_GCM: Encryption = Encryption::Aes123Gcm;
    // const CHA_CHA20_POLY1305: Encryption = Encryption::ChaCha20Poly1305;
    // const NONE: Encryption = Encryption::None;
}

pub enum Cmd {
    Tcp,
    Udp,
}

impl Cmd {
    // const TCP: Cmd = Cmd::Tcp;
    // const UDP: Cmd = Cmd::Udp;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Addr {
    SocketAddr(SocketAddr),
    Host(Uri),
}

impl Addr {
    fn is_empty(&self) -> bool {
        match self {
            Addr::SocketAddr(_) => false,
            Addr::Host(uri) => uri == &Uri::default(),
        }
    }

    pub fn new_socket_addr<T>(addr: T) -> Self
    where
        SocketAddr: From<T>,
    {
        Addr::SocketAddr(addr.into())
    }

    pub fn new_host<T>(addr: T) -> Self
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: StdError,
    {
        let uri = addr.try_into().unwrap();

        Addr::Host(uri)
    }
}
