use std::{net::SocketAddr, time};
use super::{Result, encrypt::{RAND, fnv1a, vmess_kdf_1_one_shot, AES_AUTH_ID_ENCRYPTION, vmess_kdf_3_one_shot, VMESS_HEADER_AEAD_KEY_LENGTH, VMESS_HEADER_AEAD_NONCE_LENGTH, aes_123_gcm_seal, VMESS_HEADER_AEAD_KEY, VMESS_HEADER_AEAD_NONCE}};

use aes::{Aes128, cipher::{KeyInit, BlockEncrypt}};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use http::Uri;
use md5::{Md5,Digest};
use crc32fast::Hasher as Crc32;
use ring::{rand::SecureRandom, digest::{digest, SHA256}, aead::Aad};
use uuid::Uuid;

pub(crate) struct ResConfig {
    // req_key ..16
    // req_iv 16..32
    // v 32..32
    // res_key 33..49
    // res_iv 49..65
    config: Bytes,
    encrytin: Encryption,
} 

pub struct Config {
    parts: Parts
}

impl Config {
    pub fn builder() -> Builder {
        Builder::new()
    }

    pub(crate) fn seal_header(&self) -> (Bytes, ResConfig) {
        let (mut header, len, config) = self.header();

        let cmd_key = self.cmd_key();
        let mut nonce = [0; 8];
        RAND.fill(&mut nonce).unwrap();
        self.eauid(&cmd_key, &mut header);
        header.put_u16(len as u16);
        self.alength(&cmd_key, &nonce, &mut header);
        unsafe {
            header.set_len(42 + len);
        }
        self.aheader(&cmd_key, &mut header);

        (header.freeze(), config)
    }

    #[inline]
    pub(crate) fn ref_parts(&self) -> &Parts {
        &self.parts
    }

    fn header(&self) -> (BytesMut, usize, ResConfig) {
        let head = &self.parts;
        let addr_len = match &head.dst_addr {
            Addr::SocketAddr(SocketAddr::V4(_)) => 4,
            Addr::SocketAddr(SocketAddr::V6(_)) => 16,
            Addr::Host(uri) => uri.host().unwrap().len() + 1,
        };

        let mut config = BytesMut::with_capacity(66);
        config.resize(34, 0);

        RAND.fill(&mut config).unwrap();

        let p = &config[0] >> 4;
        config.advance(1);

        let header_len = 45 + addr_len + p as usize;
        let mut header =
            //BytesMut::with_capacity(45 + addr_len + p as usize);
            //                        eauid + leangth + tag + header + tag 
            BytesMut::with_capacity( 16 + 2 + 16 + 8 + header_len  + 16);
        unsafe { header.set_len(42) }
        let mut buf = header.split_off(42);

        match head.version {
            Version::V1 => buf.put_u8(0x01),
        }

        buf.put_slice(&config[16..32]);
        buf.put_slice(&config[..16]);
        buf.put_u8(config[32]);

        match &head.opt {
            Opt::S => buf.put_u8(0x01),
            Opt::M => buf.put_u8(0x04),
        }

        match &head.encryption {
            Encryption::Aes123Gcm => buf.put_u8(p << 4 | 0x03),
            Encryption::ChaCha20Poly1305 => {
                buf.put_u8(p << 4 | 0x04)
            }
            Encryption::None => buf.put_u8(p << 4 | 0x05),
        }

        buf.put_u8(0x00);

        match &head.cmd {
            Cmd::Tcp => buf.put_u8(0x01),
            Cmd::Udp => buf.put_u8(0x02),
        }

        match &head.dst_addr {
            Addr::SocketAddr(SocketAddr::V4(v4)) => {
                buf.put_u16(v4.port());
                buf.put_u8(0x01);
                buf.put(&v4.ip().octets()[..]);
            }
            Addr::SocketAddr(SocketAddr::V6(v6)) => {
                buf.put_u16(v6.port());
                buf.put_u8(0x03);
                buf.put(&v6.ip().octets()[..]);
            }
            Addr::Host(uri) => {
                let port = uri.port_u16().unwrap();
                buf.put_u16(port);
                buf.put_u8(0x02);

                let host = uri.host().unwrap();

                buf.put_u8(host.len() as u8);

                buf.put(host.as_bytes());
            }
        }

        let mut p_arr = [0; 15];
        RAND.fill(&mut p_arr).unwrap();
        buf.put_slice(&p_arr[..p as usize]);

        let hash = fnv1a!(&buf);
        buf.put_u32(hash);

        header.unsplit(buf);
        header.truncate(0);

        let res_key = digest(&SHA256, &config[..16]);
        let res_iv = digest(&SHA256, &config[16..32]);

        config.put(&res_key.as_ref()[..16]);
        config.put(&res_iv.as_ref()[..16]);

        let config = ResConfig {
            config: config.freeze(),
            encrytin: head.encryption,
        };

        (header, header_len, config)
    }

    fn cmd_key(&self) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(self.parts.uuid.as_bytes());
        hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        hasher.finalize().into()
    }

    fn eauid(&self, cmd_key: &[u8], buf: &mut BytesMut) {
        let time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_be_bytes();
        let mut rand = [0; 4];
        RAND.fill(&mut rand).unwrap();

        let mut hasher = Crc32::new();
        hasher.update(&time);
        hasher.update(&rand);

        let hash = hasher.finalize();

        buf.put_slice(&time);
        buf.put_slice(&rand);
        buf.put_u32(hash);
        let key = vmess_kdf_1_one_shot(
            cmd_key,
            AES_AUTH_ID_ENCRYPTION,
        );
        let cipher = Aes128::new(key.as_ref()[..16].into());
        cipher.encrypt_block(buf.as_mut().into());
    }

    fn alength(
        &self,
        cmd_key: &[u8],
        nonce: &[u8],
        buf: &mut BytesMut,
    ) {
        let key = vmess_kdf_3_one_shot(
            cmd_key,
            VMESS_HEADER_AEAD_KEY_LENGTH,
            &buf[..16],
            nonce,
        );

        let nonce_ = vmess_kdf_3_one_shot(
            cmd_key,
            VMESS_HEADER_AEAD_NONCE_LENGTH,
            &buf[..16],
            nonce,
        );

        let mut behind = buf.split_off(16);

        aes_123_gcm_seal(
            &key.as_ref()[..16],
            &nonce_.as_ref()[..12],
            Aad::from(&buf[..16]),
            &mut behind,
        );

        buf.unsplit(behind);
        buf.put_slice(nonce);
    }

    fn aheader(&self, cmd_key: &[u8], buf: &mut BytesMut) {
        let key = vmess_kdf_3_one_shot(
            cmd_key,
            VMESS_HEADER_AEAD_KEY,
            &buf[..16],
            &buf[34..42],
        );

        let nonce = vmess_kdf_3_one_shot(
            cmd_key,
            VMESS_HEADER_AEAD_NONCE,
            &buf[..16],
            &buf[34..42],
        );

        let mut behind = buf.split_off(42);

        aes_123_gcm_seal(
            &key.as_ref()[..16],
            &nonce.as_ref()[..12],
            Aad::from(&buf[..16]),
            &mut behind,
        );

        buf.unsplit(behind);
    }

}

pub struct Builder {
    inner: Result<Parts>,
}

impl Builder {
    fn new() -> Self {
        Builder { inner: Ok(Parts::new()) }
    }

    pub fn build(self) -> Result<Config> {
        let parts = self.inner?;

        if parts.uuid.is_nil() {
            return Err(ErrorKind::EmptyUuid.into());
        }

        if parts.dst_addr.is_empty()  {
            return Err(ErrorKind::EmptyDstAddr.into());
        }

        if parts.server_addr.is_empty() {
            return Err(ErrorKind::EmptyServerAddr.into());
        }

        Ok(Config {
            parts,
        })
    }

    pub fn uuid<T>(self, uuid: T) -> Self
    where
        Uuid: TryFrom<T>,
        <Uuid as TryFrom<T>>::Error: Into<uuid::Error>,
    {
        self.and_then(move |mut head| {
            head.uuid = uuid.try_into().map_err(Into::into)?;
            Ok(head)
        })
    }

    pub fn opt(self, opt: Opt) -> Self {
        self.and_then(move |mut head| {
            head.opt = opt;
            Ok(head)
        })
    }

    pub fn cmd(self, cmd: Cmd) -> Self {
        self.and_then(move |mut head| {
            head.cmd = cmd;
            Ok(head)
        })
    }

    pub fn encryption(self, encrypt: Encryption) -> Self {
        self.and_then(move |mut head| {
            head.encryption = encrypt;
            Ok(head)
        })
    }

    pub fn dst_addr(self, address: Addr) -> Self {
        self.and_then(move |mut head| {
            head.dst_addr = address;
            Ok(head)
        })
    }

    pub fn server_addr(self, addr: Addr) -> Self {
        self.and_then(move |mut head| {
            head.server_addr = addr;
            Ok(head)
        })
    }

    fn and_then<F>(self, func: F) -> Self
    where
        F: FnOnce(Parts) -> Result<Parts>,
    {
        Builder {
            inner: self.inner.and_then(func),
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}


pub(crate) struct Parts {
    uuid: Uuid,
    version: Version,
    opt: Opt,
    cmd: Cmd,
    encryption: Encryption,
    dst_addr: Addr,
    server_addr: Addr,
}

impl Parts {
    fn new() -> Self{
        Parts {
            uuid: Uuid::default(),
            version: Version::V1,
            opt: Opt::S,
            cmd: Cmd::Tcp,
            encryption: Encryption::None,
            dst_addr: Addr::Host(Uri::default()),
            server_addr: Addr::Host(Uri::default()),
        }
    }
}

impl Default for Parts {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) enum ErrorKind {
    EmptyUuid,
    EmptyServerAddr,
    EmptyDstAddr,
}

enum Version {
    V1,
}

pub enum Opt {
    S,
    M,
}

#[derive(Debug,Clone, Copy)]
pub enum Encryption {
    Aes123Gcm,
    ChaCha20Poly1305,
    None,
}

pub enum Cmd {
    Tcp,
    Udp,
}

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

    pub fn new_host<T>(addr: T) -> Result<Self>
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: Into<http::uri::InvalidUri>,
    {
        let uri = addr.try_into().map_err(Into::into)?;

        Ok(Addr::Host(uri))
    }
}
