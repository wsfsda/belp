use std::{
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::never::Never;
use ring::aead::Aad;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufStream, ReadBuf},
    sync::mpsc,
};
use tracing::instrument;

use super::{
    encrypt::{
        aes_123_gcm_open, vmess_kdf_1_one_shot,
        AEAD_RESP_HEADER_IV, AEAD_RESP_HEADER_KEY,
        AEAD_RESP_HEADER_LEN_IV, AEAD_RESP_HEADER_LEN_KEY,
    },
    response::ResponseConfig,
    Encryption,
};

pub struct Connection<T, I> {
    recv: Receiver<T>,
    sstream: SStream<I>,
    pstream: Option<PStream<T>>,
}

impl<T, I> Future for Connection<T, I>
where
    T: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), super::Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        self.poll_f(cx)
    }
}

impl<T, I> Connection<T, I>
where
    T: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn recv_new_pconn(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        // self.sstream.buffer.clear();
        let stream = crate::ready!(self.recv.poll_recv(cx))?;
        tracing::trace!("接收到新的代理流");
        self.pstream = Some(PStream::new(stream));
        Poll::Ready(Ok(()))
    }

    fn poll_f(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        // loop {
        //     match self.poll_read(cx) {
        //         Poll::Ready(Ok(_)) => {}
        //         Poll::Ready(Err(e)) => {
        //             tracing::warn!(?e, "错误");
        //             return Poll::Ready(Err(e));
        //         }
        //         Poll::Pending => match self.poll_write(cx) {
        //             Poll::Ready(Ok(_)) => {}
        //             Poll::Ready(Err(e)) => {
        //                 tracing::warn!(?e, "错误");
        //                 return Poll::Ready(Err(e));
        //             }
        //             Poll::Pending => return Poll::Pending,
        //         },
        //     }
        // }

        for _ in 0..16 {
            let _ = self.poll_read(cx)?;
            let _ = self.poll_write(cx)?;
        }

        yield_now(cx).map(|never| match never {})
    }

    fn poll_read(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        loop {
            match &mut self.pstream {
                Some(p) => match crate::ready!(p.poll_chunk(cx))
                {
                    Ok(buf) => {
                        tracing::trace!(len = ?buf.len(), "代理客户端发送");
                        crate::ready!(self
                            .sstream
                            .poll_send(cx, buf))?;
                        p.advance();
                    }
                    Err(e) => match &e.0 {
                        super::ErrorKind::ConnError(
                            ConnError(ErrorKind::ConnClose),
                        ) => {
                            tracing::trace!("等待新的代理流");
                            self.pstream = None;
                        }
                        _ => return Poll::Ready(Err(e)),
                    },
                },
                None => {
                    crate::ready!(self.recv_new_pconn(cx))?;
                }
            }
        }
    }

    fn poll_write(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        loop {
            let buf =
                crate::ready!(self.sstream.poll_chunk(cx))?;
            match &mut self.pstream {
                Some(p) => {
                    match crate::ready!(p.poll_send(cx, &buf)) {
                        Ok(_) => {
                            tracing::trace!(len = ?buf.len(), "代理客户端收到");
                        }
                        Err(e) => match &e.0 {
                            super::ErrorKind::ConnError(
                                ConnError(ErrorKind::ConnClose),
                            ) => {
                                tracing::trace!(
                                    "等待新的代理流"
                                );
                                self.pstream = None;
                            }
                            _ => return Poll::Ready(Err(e)),
                        },
                    }
                }
                None => {
                    crate::ready!(self.recv_new_pconn(cx))?;
                }
            }
        }
    }
}

impl<T, I> Connection<T, I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        rx: Receiver<T>,
        s_server: I,
        header: Bytes,
        config: ResponseConfig,
    ) -> Self {
        Connection {
            recv: rx,
            sstream: SStream::new(s_server, header, config),
            pstream: None,
        }
    }
}

pub struct SStream<I> {
    stream: BufStream<I>,
    buffer: BytesMut,
    config: ResponseConfig,
    header: Option<Bytes>,
    is_read_res_header: bool,
    is_write_req_header: bool,
    is_parse_header_len: bool,
}

struct PStream<T> {
    stream: BufStream<T>,
    buffer: BytesMut,
    advance_len: usize,
}

impl<T> PStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(t: T) -> Self {
        PStream {
            stream: BufStream::new(t),
            buffer: BytesMut::with_capacity(1024),
            advance_len: 0,
        }
    }

    pub fn poll_send(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<(), super::Error>> {
        let mut buf = buf;

        while buf.has_remaining() {
            let n = crate::ready!(self.poll_write(cx, buf))?;
            buf.advance(n);
            if n == 0 {
                return Poll::Ready(Err(ConnError(
                    ErrorKind::ConnClose,
                )
                .into()));
            }
        }

        crate::ready!(Pin::new(&mut self.stream).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    pub fn poll_chunk(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<&[u8], super::Error>> {
        let n = crate::ready!(self.poll_read(cx))?;

        if n == 0 {
            return Poll::Ready(Err(ConnError(
                ErrorKind::ConnClose,
            )
            .into()));
        }
        self.advance_len = n;
        Poll::Ready(Ok(self.buffer.chunk()))
    }

    pub fn advance(&mut self) {
        self.buffer.advance(self.advance_len);
    }

    pub fn poll_read(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.buffer.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }

        let dst = self.buffer.chunk_mut();
        let dst = unsafe {
            &mut *(dst as *mut _ as *mut [MaybeUninit<u8>])
        };
        let mut readbuf = ReadBuf::uninit(dst);
        match Pin::new(&mut self.stream)
            .poll_read(cx, &mut readbuf)
        {
            Poll::Ready(Ok(_)) => {
                let n = readbuf.filled().len();
                unsafe {
                    self.buffer.advance_mut(n);
                };
                Poll::Ready(Ok(n))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    pub fn poll_write(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let n = crate::ready!(
            Pin::new(&mut self.stream).poll_write(cx, buf)
        )?;

        Poll::Ready(Ok(n))
    }
}

impl<I> SStream<I>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    pub fn poll_send(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<(), super::Error>> {
        crate::ready!(self.send_req_header(cx))?;

        match &self.config.encrytin {
            Encryption::Aes123Gcm => todo!(),
            Encryption::ChaCha20Poly1305 => todo!(),
            Encryption::None => {
                crate::ready!(
                    self.write_encryption_none(cx, buf)
                )?;
            }
        }

        crate::ready!(Pin::new(&mut self.stream).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    fn send_req_header(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        if !self.is_write_req_header {
            let mut header = self.header.take().unwrap();

            while header.has_remaining() {
                let n =
                    crate::ready!(self.poll_write(cx, &header))?;
                header.advance(n);
                if n == 0 {
                    return Poll::Ready(Err(ConnError(
                        ErrorKind::ConnClose,
                    )
                    .into()));
                }
            }
            self.is_write_req_header = true;
        }

        Poll::Ready(Ok(()))
    }

    pub fn write_encryption_none(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<(), super::Error>> {
        let mut len = buf.len();
        let mut count = 0;

        loop {
            if len == 0 {
                break;
            }

            let mut write_len = u16::MAX as usize;
            if len < u16::MAX as usize {
                write_len = len;
            }

            let mut buf_len =
                &(write_len as u16).to_be_bytes()[..];
            tracing::warn!("写入长度: {:?}", write_len);
            while buf_len.has_remaining() {
                let n =
                    crate::ready!(self.poll_write(cx, buf_len))?;
                buf_len.advance(n);
                if n == 0 {
                    return Poll::Ready(Err(ConnError(
                        ErrorKind::ConnClose,
                    )
                    .into()));
                }
            }
            let mut buf = &buf[count..count + write_len];
            while buf.has_remaining() {
                let n = crate::ready!(self.poll_write(cx, buf))?;
                buf.advance(n);
                len -= n;
                count += n;
                if n == 0 {
                    return Poll::Ready(Err(ConnError(
                        ErrorKind::ConnClose,
                    )
                    .into()));
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    pub fn poll_write(
        &mut self,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let n = crate::ready!(
            Pin::new(&mut self.stream).poll_write(cx, buf)
        )?;

        Poll::Ready(Ok(n))
    }

    pub fn poll_chunk(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Bytes, super::Error>> {
        crate::ready!(self.poll_read_res_header(cx))?;
        loop {
            if let Some(frame) = self.parse_frame()? {
                return Poll::Ready(Ok(frame));
            }

            if let 0 = crate::ready!(self.poll_read(cx))? {
                return Poll::Ready(Err(ConnError(
                    ErrorKind::ConnClose,
                )
                .into()));
            }
        }
    }

    pub fn poll_read_res_header(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), super::Error>> {
        if !self.is_read_res_header {
            loop {
                if let Some(()) = self.parse_res_header()? {
                    return Poll::Ready(Ok(()));
                }

                if let 0 = crate::ready!(self.poll_read(cx))? {
                    return Poll::Ready(Err(ConnError(
                        ErrorKind::ConnClose,
                    )
                    .into()));
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    pub fn poll_read(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.buffer.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }

        let dst = self.buffer.chunk_mut();
        let dst = unsafe {
            &mut *(dst as *mut _ as *mut [MaybeUninit<u8>])
        };
        let mut readbuf = ReadBuf::uninit(dst);
        match Pin::new(&mut self.stream)
            .poll_read(cx, &mut readbuf)
        {
            Poll::Ready(Ok(_)) => {
                let n = readbuf.filled().len();
                unsafe {
                    self.buffer.advance_mut(n);
                };
                Poll::Ready(Ok(n))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn parse_frame(
        &mut self,
    ) -> Result<Option<Bytes>, super::Error> {
        match &self.config.encrytin {
            Encryption::Aes123Gcm => todo!(),
            Encryption::ChaCha20Poly1305 => todo!(),
            Encryption::None => {
                self.parse_encryption_none().map_err(Into::into)
            }
        }
    }

    #[instrument(skip(self), err(Debug))]
    fn parse_encryption_none(
        &mut self,
    ) -> Result<Option<Bytes>, ConnError> {
        let mut buffer: &[u8] = &self.buffer[..];
        if buffer.len() < 2 {
            return Ok(None);
        }

        let len = buffer.get_u16() as usize;
        tracing::warn!("数据长度 :{}", len);
        if len == 0 {
            return Err(ConnError(ErrorKind::ConnClose));
        }
        if buffer.len() < len {
            return Ok(None);
        }
        let buf = Bytes::copy_from_slice(&buffer[..len]);
        self.buffer.advance(2 + len);
        Ok(Some(buf))
    }

    fn parse_res_header(
        &mut self,
    ) -> Result<Option<()>, ConnError> {
        if self.buffer.len() < 2 + 16 {
            return Ok(None);
        };

        let len = self.parse_header_len()?;

        if self.buffer.len() < 2 + 16 + len + 16 {
            return Ok(None);
        };

        self.parse_header_body(len)?;
        Ok(Some(()))
    }

    #[instrument(skip(self), err(Debug))]
    fn parse_header_len(&mut self) -> Result<usize, ConnError> {
        if !self.is_parse_header_len {
            let key = vmess_kdf_1_one_shot(
                &self.config.config[33..49],
                AEAD_RESP_HEADER_LEN_KEY,
            );

            let nonce = vmess_kdf_1_one_shot(
                &self.config.config[49..65],
                AEAD_RESP_HEADER_LEN_IV,
            );
            aes_123_gcm_open(
                &key.as_ref()[..16],
                &nonce.as_ref()[..12],
                Aad::empty(),
                &mut self.buffer[..18],
                0..,
            )?;
            self.is_parse_header_len = true;
        }
        let mut buf = &self.buffer[..];
        let len = buf.get_u16() as usize;
        Ok(len)
    }

    #[instrument(skip(self), err(Debug))]
    fn parse_header_body(
        &mut self,
        len: usize,
    ) -> Result<(), ConnError> {
        let key = vmess_kdf_1_one_shot(
            &self.config.config[33..49],
            AEAD_RESP_HEADER_KEY,
        );

        let nonce = vmess_kdf_1_one_shot(
            &self.config.config[49..65],
            AEAD_RESP_HEADER_IV,
        );
        aes_123_gcm_open(
            &key.as_ref()[..16],
            &nonce.as_ref()[..12],
            Aad::empty(),
            &mut self.buffer[2 + 16..2 + 16 + len + 16],
            0..,
        )?;

        if self.buffer[18] != self.config.config[32]
            || self.buffer[19] != 0
            || self.buffer[20] != 0
        {
            return Err(ConnError(ErrorKind::InvalidHeader));
        }

        self.buffer.advance(2 + 16 + len + 16);
        self.is_read_res_header = true;
        Ok(())
    }

    fn new(
        s_server: I,
        header: Bytes,
        config: ResponseConfig,
    ) -> SStream<I> {
        SStream {
            stream: BufStream::new(s_server),
            buffer: BytesMut::with_capacity(1024),
            config,
            header: Some(header),
            is_read_res_header: false,
            is_write_req_header: false,
            is_parse_header_len: false,
        }
    }
}

#[derive(Debug)]
pub struct Sender<T> {
    inner: mpsc::UnboundedSender<T>,
    giver: want::Giver,
    buffered_once: bool,
}

impl<T> Sender<T> {
    pub fn poll_ready(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), ConnError>> {
        match self.giver.poll_want(cx) {
            Poll::Ready(res) => {
                Poll::Ready(res.map_err(Into::into))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.giver.is_wanting()
    }

    pub fn is_closed(&self) -> bool {
        self.giver.is_canceled()
    }

    pub fn can_send(&mut self) -> bool {
        if self.giver.give() || !self.buffered_once {
            self.buffered_once = true;
            true
        } else {
            false
        }
    }

    pub fn send(
        &mut self,
        val: T,
    ) -> Result<(), (T, ConnError)> {
        if !self.can_send() {
            return Ok(());
        }
        self.inner.send(val).map_err(|error| {
            (error.0, ConnError(ErrorKind::ChannelClose))
        })
    }
}

struct Receiver<T> {
    inner: mpsc::UnboundedReceiver<T>,
    taker: want::Taker,
}

impl<T> Receiver<T> {
    fn poll_recv(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<T, ConnError>> {
        match self.inner.poll_recv(cx) {
            Poll::Ready(item) => match item {
                Some(t) => Poll::Ready(Ok(t)),
                None => Poll::Ready(Err(ConnError(
                    ErrorKind::ChannelClose,
                ))),
            },
            Poll::Pending => {
                self.taker.want();
                Poll::Pending
            }
        }
    }

    pub fn close(&mut self) {
        self.taker.cancel();
        self.inner.close();
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.taker.cancel();
    }
}

impl<T> Future for Receiver<T> {
    type Output = Result<T, ConnError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        self.poll_recv(cx)
    }
}

#[derive(Debug)]
pub struct ConnError(ErrorKind);

impl From<want::Closed> for ConnError {
    fn from(_: want::Closed) -> Self {
        ConnError(ErrorKind::ChannelClose)
    }
}

impl From<ring::error::Unspecified> for ConnError {
    fn from(_: ring::error::Unspecified) -> Self {
        ConnError(ErrorKind::InvalidHeader)
    }
}

#[derive(Debug)]
enum ErrorKind {
    ChannelClose,
    ConnClose,
    InvalidHeader,
}

fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::unbounded_channel::<T>();

    let (giver, taker) = want::new();

    let send = Sender {
        inner: tx,
        giver,
        buffered_once: false,
    };
    let recv = Receiver { inner: rx, taker };
    (send, recv)
}

pub fn handshake<T, I>(
    s_server: I,
    header: Bytes,
    config: ResponseConfig,
) -> (Sender<T>, Connection<T, I>)
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (tx, rx) = channel::<T>();

    let connection =
        Connection::new(rx, s_server, header, config);

    (tx, connection)
}

pub(crate) fn yield_now(cx: &mut Context<'_>) -> Poll<Never> {
    cx.waker().wake_by_ref();
    Poll::Pending
}

#[cfg(test)]
mod test {
    use std::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::BytesMut;
    use futures::Future;
    use tokio::{
        io::{
            AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
            BufStream,
        },
        net::{TcpListener, TcpStream},
    };
    use tracing_subscriber::EnvFilter;

    use crate::proto::vmess::{request, Addr};

    use super::SStream;

    struct WarpSend<'a, I> {
        inner: &'a mut SStream<I>,
        data: &'a [u8],
    }

    impl<'a, I> Future for WarpSend<'a, I>
    where
        I: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = Result<(), super::super::Error>;

        fn poll(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            let buf = self.data;
            crate::ready!(self.inner.poll_send(cx, buf))?;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn s_stream() {
        tracing_subscriber::fmt::Subscriber::builder()
            .pretty()
            .with_env_filter(EnvFilter::new("belp=trace"))
            .try_init()
            .unwrap();

        let dst_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 6000));
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 1234));
        let req = request::Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let stream =
            TcpStream::connect("127.0.0.1:1234").await.unwrap();

        let (header, config) = req.seal_header();

        let mut s_server = SStream {
            stream: BufStream::new(stream),
            buffer: BytesMut::with_capacity(1024 * 2),
            header: Some(header),
            config,
            is_parse_header_len: false,
            is_read_res_header: false,
            is_write_req_header: false,
        };

        let send = WarpSend {
            inner: &mut s_server,
            data: b"Hello World",
        };

        send.await.unwrap();

        let _chunk = futures::future::poll_fn(|cx| {
            s_server.poll_chunk(cx)
        })
        .await;

        println!("5s end");

        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("end");
    }

    #[tokio::test]
    async fn mm() {
        //console_subscriber::init();

        tracing_subscriber::fmt::Subscriber::builder()
            .pretty()
            .with_env_filter(EnvFilter::new("belp=trace"))
            .try_init()
            .unwrap();

        let dst_addr = Addr::new_host("http://www.baidu.com:80");
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 1234));
        let req = request::Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let stream =
            TcpStream::connect("127.0.0.1:1234").await.unwrap();

        let (header, config) = req.seal_header();

        let (mut send, conn) =
            super::handshake(stream, header, config);

        let h = tokio::spawn(conn);

        let ss =
            TcpListener::bind("127.0.0.1:8100").await.unwrap();

        let x = ss.accept().await.unwrap();

        send.send(x.0).unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
        let x = h.await;

        println!("{:?}", x);
    }

    #[tokio::test]
    async fn mm2() {
        //console_subscriber::init();

        tracing_subscriber::fmt::Subscriber::builder()
            .pretty()
            .with_env_filter(EnvFilter::new("belp=trace"))
            .try_init()
            .unwrap();

        let dst_addr = Addr::new_host("127.0.0.1:6000");
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 1234));
        let req = request::Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let stream =
            TcpStream::connect("127.0.0.1:1234").await.unwrap();

        let (header, config) = req.seal_header();

        let (mut send, conn) =
            super::handshake(stream, header, config);

        let h = tokio::spawn(conn);

        let (mut x, mut y) = tokio::io::duplex(1024);
        y.write_all(b"xxxxxx").await.unwrap();
        send.send(y).unwrap();

        x.write_all(b"Hello World").await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;

        let mut buf = [0; 1024];

        let n = x.read(&mut buf).await.unwrap();
        println!("开始读");
        println!("{:?}", std::str::from_utf8(&buf[..n]));
        println!("读完成");

        let n = x.read(&mut buf).await.unwrap();
        println!("开始读");
        println!("{:?}", std::str::from_utf8(&buf[..n]));
        println!("读完成");
        tokio::time::sleep(Duration::from_secs(10)).await;
        let x = h.await;

        println!("{:?}", x);
    }
}
