use std::{fmt::Display, fs, io, path::Path};

use proto::vmess::{self, Addr, Encryption};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    services: Vec<Service>,
    rules: Vec<Rulue>,
}

impl Config {
    pub fn load() -> Result<Self, Error> {
        Self::load_path("./config.toml")
    }

    pub fn load_path<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        let buf = fs::read(path)?;
        let config = toml::from_slice(&buf)?;
        Ok(config)
    }

    pub fn match_service(&self, host: &str) -> Option<&Service> {
        for rule in self.rules.iter() {
            match rule.kind {
                Kind::Domain => {
                    if rule.payload == host {
                        if let Some(service) =
                            self.get_service(&rule.dst)
                        {
                            return Some(service);
                        }
                    }
                }
                Kind::Suffix => {
                    if host.ends_with(&rule.payload) {
                        if let Some(service) =
                            self.get_service(&rule.dst)
                        {
                            return Some(service);
                        }
                    }
                }
                Kind::Keyword => {
                    if host.contains(&rule.payload) {
                        if let Some(service) =
                            self.get_service(&rule.dst)
                        {
                            return Some(service);
                        }
                    }
                }
            }
        }

        None
    }

    fn get_service(&self, name: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.contains(name))
    }
}

#[derive(Debug)]
pub struct Error {
    inner: ErrorKind,
}

impl Display for Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match &self.inner {
            ErrorKind::Io(io) => io.fmt(f),
            ErrorKind::Toml(toml) => toml.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
enum ErrorKind {
    Io(io::Error),
    Toml(toml::de::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error {
            inner: ErrorKind::Io(error),
        }
    }
}

impl From<toml::de::Error> for Error {
    fn from(error: toml::de::Error) -> Self {
        Error {
            inner: ErrorKind::Toml(error),
        }
    }
}

type RulueTuple = (Kind, String, String);

#[derive(Debug, Deserialize)]
#[serde(from = "RulueTuple")]
struct Rulue {
    kind: Kind,
    payload: String,
    dst: String,
}

impl From<RulueTuple> for Rulue {
    fn from(value: RulueTuple) -> Self {
        Rulue {
            kind: value.0,
            payload: value.1,
            dst: value.2,
        }
    }
}

#[derive(Debug, Deserialize)]
enum Kind {
    Domain,
    Suffix,
    Keyword,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Service {
    #[serde(rename = "vmess")]
    Vmess(Vmess),
    #[serde(rename = "trojin")]
    Trojin(Trojin),
}

impl Service {
    fn contains(&self, name: &str) -> bool {
        match self {
            Service::Vmess(vmess) => vmess.part.name == name,
            Service::Trojin(trojin) => trojin.part.name == name,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Vmess {
    #[serde(flatten)]
    part: Part,
    uuid: String,
    #[serde(default)]
    cipher: Encryption,
}

impl From<&Vmess> for vmess::Builder {
    fn from(me: &Vmess) -> Self {
        let build = vmess::Config::builder()
            .uuid(me.uuid.as_ref())
            .encryption(me.cipher);

        match &me.part.server {
            ServerAddr::Host(host) => build.server_addr(
                Addr::new_host(format!(
                    "{}:{}",
                    host, me.part.port
                ))
                .expect("config file erre"),
            ),
            ServerAddr::Ipv4(v4) => build.server_addr(
                Addr::new_socket_addr((*v4, me.part.port)),
            ),
            ServerAddr::Ipv6(v6) => build.server_addr(
                Addr::new_socket_addr((*v6, me.part.port)),
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Part {
    name: String,
    server: ServerAddr,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ServerAddr {
    Host(String),
    Ipv4([u8; 4]),
    Ipv6([u16; 8]),
}

#[derive(Debug, Deserialize)]
pub struct Trojin {
    #[serde(flatten)]
    part: Part,
    _password: String,
    _sni: String,
}

#[cfg(test)]
mod test {
    use crate::Config;

    #[test]
    fn xx() {
        let str = r#"
        rules = [
    [
        "Domain",
        "www.google.com",
        "ss",
    ],
    [
        "Keyword",
        "google",
        "ss",
    ],[
        "Suffix",
        "google.com",
        "ss"
    ]
]

[[services]]
name = "ss"
type = "vmess"
server = "ss.dsds"
port = 1131
uuid = "323232323"
cipher = "aes123gcm"


[[services]]
name = "ss2"
type = "vmess"
server = [127,0,0,1]
port = 1131
uuid = "323232323"
cipher = "aes123gcm"
       "#;

        let config: Config = toml::from_str(str).unwrap();
        println!("{:?}", config);

        let service = config.match_service("www.google.com");

        println!("{:?}", service);
    }
}
