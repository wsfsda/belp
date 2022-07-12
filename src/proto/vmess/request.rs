use std::{
    fmt::{self, Display},
    net::SocketAddr,
    time,
};

use aes::cipher::BlockEncrypt;
use aes::{cipher::KeyInit, Aes128};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher as Crc32;
use http::Uri;
use md5::{Digest, Md5};
use ring::{
    aead::Aad,
    digest::{digest, SHA256},
    rand::SecureRandom,
};
use uuid::Uuid;

use crate::proto::vmess::encrypt::{
    vmess_kdf_1_one_shot, AES_AUTH_ID_ENCRYPTION,
};

use super::{
    client::Key,
    encrypt::{
        aes_123_gcm_seal, fnv1a, vmess_kdf_3_one_shot, RAND,
        VMESS_HEADER_AEAD_KEY, VMESS_HEADER_AEAD_KEY_LENGTH,
        VMESS_HEADER_AEAD_NONCE, VMESS_HEADER_AEAD_NONCE_LENGTH,
    },
    response::ResponseConfig,
    Addr, Cmd, Encryption, Error, Opt, Version,
};

pub struct Request {
    head: Parts,
    // body: T,
}

pub struct Builder {
    inner: Result<Parts, Error>,
}

impl Request {
    pub fn seal_header(&self) -> (Bytes, ResponseConfig) {
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
    pub fn ref_parts(&self) -> &Parts {
        &self.head
    }

    #[inline]
    fn header(&self) -> (BytesMut, usize, ResponseConfig) {
        let head = &self.head;
        let addr_len = match &head.dst_addr {
            Addr::SocketAddr(SocketAddr::V4(_)) => 4,
            Addr::SocketAddr(SocketAddr::V6(_)) => 16,
            Addr::Host(uri) => uri.host().unwrap().len() + 1,
        };

        let mut config = BytesMut::with_capacity(66);
        config.resize(34, 0);
        // let mut req_iv = [0; 16];
        // let mut req_key = [0; 16];
        // let mut v_and_p = [0; 2];

        RAND.fill(&mut config).unwrap();
        // RAND.fill(&mut req_key).unwrap();
        // RAND.fill(&mut v_and_p).unwrap();

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

        let config = ResponseConfig {
            config: config.freeze(),
            encrytin: head.encryption,
        };

        (header, header_len, config)
    }

    #[inline]
    fn cmd_key(&self) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(self.head.uuid.as_bytes());
        hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        hasher.finalize().into()
    }

    #[inline]
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

    #[inline]
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

    #[inline]
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

impl Request {
    pub fn builder() -> Builder {
        Builder::new()
    }
}

impl Builder {
    pub fn build(self) -> Result<Request, Error> {
        let head = self.inner?;

        if head.uuid.is_nil() {
            return Err(InvalidRequest(ErrorKind::InvalidUuid(
                None,
            ))
            .into());
        }

        if head.server_addr.is_empty() {
            return Err(InvalidRequest(
                ErrorKind::InvalidServerAddr,
            )
            .into());
        }

        if head.dst_addr.is_empty() {
            return Err(InvalidRequest(
                ErrorKind::InvalidDstAddr,
            )
            .into());
        }

        Ok(Request { head })
    }

    pub fn new() -> Self {
        Builder {
            inner: Ok(Parts::new()),
        }
    }

    pub fn uuid<T>(self, uuid: T) -> Self
    where
        Uuid: TryFrom<T>,
        <Uuid as TryFrom<T>>::Error: Into<InvalidRequest>,
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
        F: FnOnce(Parts) -> Result<Parts, Error>,
    {
        Builder {
            inner: self.inner.and_then(func),
        }
    }
}

pub struct Parts {
    uuid: Uuid,
    version: Version,
    opt: Opt,
    cmd: Cmd,
    encryption: Encryption,
    dst_addr: Addr,
    server_addr: Addr,
}

#[derive(Debug)]
pub struct InvalidRequest(ErrorKind);

impl From<uuid::Error> for InvalidRequest {
    fn from(error: uuid::Error) -> Self {
        InvalidRequest(ErrorKind::InvalidUuid(Some(error)))
    }
}

impl Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ErrorKind::InvalidDstAddr => {
                "invalid dst addr".fmt(f)
            }
            ErrorKind::InvalidServerAddr => {
                "invalid server addr".fmt(f)
            }
            ErrorKind::InvalidUuid(None) => {
                "invalid uuid".fmt(f)
            }
            ErrorKind::InvalidUuid(Some(error)) => {
                error.to_string().fmt(f)
            }
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    InvalidDstAddr,
    InvalidServerAddr,
    InvalidUuid(Option<uuid::Error>),
}

impl Parts {
    pub fn new() -> Self {
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

    pub fn into_key(&self) -> Key {
        Key::new(
            self.uuid,
            self.encryption,
            self.server_addr.clone(),
            self.dst_addr.clone(),
        )
    }
}

#[cfg(test)]
mod test {

    use std::time::Duration;

    use bytes::BytesMut;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::Request;
    use crate::proto::vmess::Addr;

    #[test]
    fn cmd_key() {
        let dst_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let req = Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let cmd_key = req.cmd_key();
        println!("cmd_key: {:x?}", cmd_key);
        assert_eq!(
            [
                0x57, 0x88, 0x24, 0x08, 0x2d, 0x67, 0xc5, 0x16,
                0xb4, 0x0a, 0x76, 0x3e, 0x9d, 0xb9, 0xd4, 0xd7
            ],
            cmd_key
        );

        let mut buf = BytesMut::new();
        req.eauid(&cmd_key, &mut buf);
        println!("eauid: {:x?}", &buf[..]);
    }

    #[test]
    fn header() {
        let dst_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let req = Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let (_header, _len, _) = req.header();
    }

    #[tokio::test]
    async fn sealheader() {
        let dst_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 1234));
        let req = Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let (mut header, _config) = req.seal_header();

        let body = b"Hello world";

        let mut stream =
            TcpStream::connect("127.0.0.1:1234").await.unwrap();

        stream.write_all_buf(&mut header).await.unwrap();
        stream.write_u16(body.len() as u16).await.unwrap();
        stream.write_all(body).await.unwrap();
        //stream.write_u16(0x00).await.unwrap();

        let (mut s1, mut s2) = tokio::io::split(stream);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            s2.write_u16(0).await.unwrap();
        });
        let mut buf = [0; 1024];

        loop {
            let n = s1.read(&mut buf).await.unwrap();
            println!("{:?}", n);
        }
    }
}
