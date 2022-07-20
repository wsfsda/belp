use bytes::{Buf, Bytes, BytesMut};
use ring::aead::Aad;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use tracing::instrument;

use crate::proto::vmess::encrypt::{
    aes_123_gcm_open, vmess_kdf_1_one_shot,
    AEAD_RESP_HEADER_LEN_IV, AEAD_RESP_HEADER_LEN_KEY,
};

use super::{
    encrypt::{AEAD_RESP_HEADER_IV, AEAD_RESP_HEADER_KEY},
    response::ResponseConfig,
};

pub struct Connection<S> {
    stream: S,
    buffer: BytesMut,
    header: Option<Bytes>,
    response_config: ResponseConfig,
    is_send_header: bool,
    is_recv_header: bool,
}

impl<S> Connection<S> {
    pub fn new(
        s: S,
        header: Bytes,
        config: ResponseConfig,
    ) -> Self {
        Connection {
            stream: s,
            buffer: BytesMut::with_capacity(2048),
            header: Some(header),
            response_config: config,
            is_send_header: false,
            is_recv_header: false,
        }
    }
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[instrument(skip(self, input), err(Debug))]
    pub async fn run<T: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        mut input: T,
    ) -> Result<(), super::Error> {
        let mut in_buffer = BytesMut::with_capacity(1024);
        loop {
            tokio::select! {
                res = input.read_buf(&mut in_buffer) => {
                    println!("12345: {:?}", res);
                    res?;
                    self.send_data(&in_buffer).await?;
                    in_buffer.advance(in_buffer.len());
                }

                res = self.recv_data() => {
                    match res {
                        Ok(mut buf) => {
                            let len = buf.len();
                        loop {
                            let res = input.write(buf).await;
                            println!("678910: {:?}", res);
                            let n = res?;
                            println!("n: {}",n);
                            if n != buf.len() {
                                buf = &buf[n..];
                            }else {
                                break;
                            }
                        }
                        self.buffer.advance(len);
                        },
                        Err(e) => {
                           return Err(e)
                        }
                    }
                }
            }
        }
    }

    async fn send_data(
        &mut self,
        data: &[u8],
    ) -> Result<(), super::Error> {
        self.send_header().await?;
        let mut len = data.len();
        let max_write_len = u16::MAX as usize;
        let mut write_n = 0;
        loop {
            if len == 0 {
                break;
            }
            let mut write_len = max_write_len;
            if len < max_write_len {
                write_len = len;
            }

            self.stream.write_u16(write_len as u16).await?;

            let n = self
                .stream
                .write(&data[write_n..write_len + write_n])
                .await?;
            if n != write_len {
                return Err(InvalidHeader(
                    ErrorKind::InvalidHeader,
                )
                .into());
            }
            len -= n;
            write_n += n;
        }

        Ok(())
    }

    async fn recv_data(
        &mut self,
    ) -> Result<&[u8], super::Error> {
        self.recv_header().await?;

        loop {
            if self.buffer.len() < 2 {
                self.stream.read_buf(&mut self.buffer).await?;
            } else {
                break;
            }
        }

        let len = self.buffer.get_u16() as usize;

        loop {
            if self.buffer.len() < len {
                self.stream.read_buf(&mut self.buffer).await?;
            } else {
                break;
            }
        }
        Ok(&self.buffer[..len])
    }

    async fn send_header(&mut self) -> Result<(), super::Error> {
        if !self.is_send_header {
            let mut header = self.header.take().unwrap();

            self.stream.write_all_buf(&mut header).await?;
            self.is_send_header = true;
        }

        Ok(())
    }

    async fn recv_header(&mut self) -> Result<(), super::Error> {
        if !self.is_recv_header {
            loop {
                if self.buffer.len() < 18 {
                    self.stream
                        .read_buf(&mut self.buffer)
                        .await?;
                } else {
                    break;
                }
            }
            self.parse_header_len()?;
            let header_len = self.buffer.get_u16() as usize;
            self.buffer.advance(16);
            loop {
                if self.buffer.len() < header_len as usize + 18 {
                    self.stream
                        .read_buf(&mut self.buffer)
                        .await?;
                } else {
                    break;
                }
            }

            self.parse_header(header_len + 16)?;

            self.check_header()?;
            self.buffer.advance(header_len + 16);
            self.is_recv_header = true;
        }
        Ok(())
    }

    #[instrument(skip(self), err(Debug))]
    fn parse_header_len(&mut self) -> Result<(), InvalidHeader> {
        let key = vmess_kdf_1_one_shot(
            &self.response_config.config[33..49],
            AEAD_RESP_HEADER_LEN_KEY,
        );

        let nonce = vmess_kdf_1_one_shot(
            &self.response_config.config[49..65],
            AEAD_RESP_HEADER_LEN_IV,
        );
        aes_123_gcm_open(
            &key.as_ref()[..16],
            &nonce.as_ref()[..12],
            Aad::empty(),
            &mut self.buffer[..18],
            0..,
        )?;
        Ok(())
    }

    #[instrument(skip(self, len), err(Debug))]
    fn parse_header(
        &mut self,
        len: usize,
    ) -> Result<(), InvalidHeader> {
        let key = vmess_kdf_1_one_shot(
            &self.response_config.config[33..49],
            AEAD_RESP_HEADER_KEY,
        );

        let nonce = vmess_kdf_1_one_shot(
            &self.response_config.config[49..65],
            AEAD_RESP_HEADER_IV,
        );

        aes_123_gcm_open(
            &key.as_ref()[..16],
            &nonce.as_ref()[..12],
            Aad::empty(),
            &mut self.buffer[..len],
            0..,
        )?;

        Ok(())
    }

    #[instrument(skip(self), err(Debug))]
    fn check_header(&self) -> Result<(), InvalidHeader> {
        if self.buffer[0] != self.response_config.config[32]
            || self.buffer[1] != 0
            || self.buffer[2] != 0
        {
            Err(InvalidHeader(ErrorKind::InvalidResHeader))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct InvalidHeader(ErrorKind);

#[derive(Debug)]
enum ErrorKind {
    InvalidHeader,
    InvalidResHeader,
}

impl From<ring::error::Unspecified> for InvalidHeader {
    fn from(_error: ring::error::Unspecified) -> Self {
        InvalidHeader(ErrorKind::InvalidHeader)
    }
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use tracing_subscriber::EnvFilter;

    use crate::proto::vmess::Addr;

    #[tokio::test]
    async fn run() {
        use std::convert::Infallible;
        use std::net::SocketAddr;

        use hyper::service::{make_service_fn, service_fn};
        use hyper::upgrade::Upgraded;
        use hyper::{
            Body, Client, Method, Request, Response, Server,
        };

        use tokio::net::TcpStream;

        type HttpClient = Client<hyper::client::HttpConnector>;

        tracing_subscriber::fmt::Subscriber::builder()
            .pretty()
            .with_env_filter(EnvFilter::new("belp=trace"))
            .try_init()
            .unwrap();

        let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build_http();

        let make_service = make_service_fn(move |_| {
            let client = client.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    proxy(client.clone(), req)
                }))
            }
        });

        let server = Server::bind(&addr)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(make_service);

        println!("Listening on http://{}", addr);

        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }

        async fn proxy(
            client: HttpClient,
            req: Request<Body>,
        ) -> Result<Response<Body>, hyper::Error> {
            println!("req: {:?}", req);

            if Method::CONNECT == req.method() {
                // Received an HTTP request like:
                // ```
                // CONNECT www.domain.com:443 HTTP/1.1
                // Host: www.domain.com:443
                // Proxy-Connection: Keep-Alive
                // ```
                //
                // When HTTP method is CONNECT we should return an empty body
                // then we can eventually upgrade the connection and talk a new protocol.
                //
                // Note: only after client received an empty body with STATUS_OK can the
                // connection be upgraded, so we can't return a response inside
                // `on_upgrade` future.
                if let Some(addr) = host_addr(req.uri()) {
                    tokio::task::spawn(async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                if let Err(e) =
                                    tunnel(upgraded, addr).await
                                {
                                    eprintln!(
                                        "server io error: {}",
                                        e
                                    );
                                };
                            }
                            Err(e) => {
                                eprintln!("upgrade error: {}", e)
                            }
                        }
                    });

                    Ok(Response::new(Body::empty()))
                } else {
                    eprintln!(
                        "CONNECT host is not socket addr: {:?}",
                        req.uri()
                    );
                    let mut resp = Response::new(Body::from(
                        "CONNECT must be to a socket address",
                    ));
                    *resp.status_mut() =
                        http::StatusCode::BAD_REQUEST;

                    Ok(resp)
                }
            } else {
                client.request(req).await
            }
        }

        fn host_addr(uri: &http::Uri) -> Option<String> {
            uri.authority().map(|auth| auth.to_string())
        }

        // Create a TCP connection to host:port, build a tunnel between the connection and
        // the upgraded connection
        async fn tunnel(
            upgraded: Upgraded,
            addr: String,
        ) -> std::io::Result<()> {
            let dst_addr = Addr::Host(addr.try_into().unwrap());
            let server_addr =
                Addr::new_socket_addr(([127, 0, 0, 1], 1234));
            let req = super::super::request::Request::builder()
                .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
                .dst_addr(dst_addr)
                .server_addr(server_addr)
                .build()
                .unwrap();

            let stream = TcpStream::connect("127.0.0.1:1234")
                .await
                .unwrap();

            let (header, config) = req.seal_header();

            let mut connection = super::Connection {
                is_recv_header: false,
                is_send_header: false,
                response_config: config,
                header: Some(header),
                buffer: BytesMut::with_capacity(1024),
                stream,
            };

            let res = connection.run(upgraded).await;

            println!("{:?}", res.expect("ssss"));
            println!("我要结束了");
            Ok(())
        }
    }
}
