mod channel;
pub(crate) mod codec;
pub(crate) mod config;
mod conn;
pub(crate) mod encrypt;
mod error;
mod limit;

pub use config::{Addr, Builder, Cmd, Config, Encryption, Opt};
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
