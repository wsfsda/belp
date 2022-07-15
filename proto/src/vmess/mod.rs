pub(crate) mod config;
mod conn;
mod error;
pub(crate) mod encrypt;


pub use error::Error;
pub use config::{Config,Builder,Opt,Cmd,Addr,Encryption};

pub type Result<T> = std::result::Result<T,Error>;