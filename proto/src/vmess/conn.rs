use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{ready, Future, Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::vmess::{
    channel::Receiver, codec::bytescodec::BytesCodec,
    limit::LimitStream,
};

use super::{
    channel::Sender,
    codec::{
        aes128gcmcodec::Aes128GcmCodec, noencodec::NoEnCodec,
        Shutdown,
    },
    Config,
};

pin_project! {
    #[project = ConnectionsProj]
    pub(crate) enum Connections<T1, T2> {
        NoEN{#[pin] conn: Connection<T1, T2, NoEnCodec, BytesCodec>},
        Aes128Gcm{#[pin] conn: Connection<T1, T2, Aes128GcmCodec, BytesCodec>},
    }
}

impl<T1, T2> Connections<T1, T2>
where
    T1: AsyncWrite + AsyncRead,
    T2: AsyncRead + AsyncWrite,
{
    pub(crate) fn handshake(
        s_stream: T1,
        p_stream: T2,
        config: &Config,
    ) -> (Sender, Self, want::Giver) {
        let (tx, rx, giver) = super::channel::channel();
        let (head, resconfig) = config.seal_header();

        match resconfig.encrytin {
            super::Encryption::Aes123Gcm => todo!(),
            super::Encryption::ChaCha20Poly1305 => todo!(),
            super::Encryption::None => {
                let s_codec = Codec::new(
                    s_stream,
                    NoEnCodec::new(head, resconfig),
                );
                let p_codec = Codec::new(p_stream, BytesCodec);

                (
                    tx,
                    Self::NoEN {
                        conn: Connection::new(
                            p_codec, s_codec, rx,
                        ),
                    },
                    giver,
                )
            }
        }
    }
}

impl<T1, T2> Future for Connections<T1, T2>
where
    T1: AsyncRead + AsyncWrite,
    T2: AsyncRead + AsyncWrite,
{
    type Output = Result<(), super::Error>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match self.project() {
            ConnectionsProj::NoEN { conn } => conn.poll(cx),
            ConnectionsProj::Aes128Gcm { conn } => conn.poll(cx),
        }
    }
}

pin_project! {
    pub(crate) struct Connection<T1,T2, U1,U2> {
        #[pin]
        s_codec: Codec<T1, U1>,
        #[pin]
        p_codec: Codec<T2, U2>,
        recv: Receiver,
    }
}

impl<T1, T2, U1, U2> Connection<T1, T2, U1, U2>
where
    T1: AsyncWrite + AsyncRead,
    T2: AsyncRead + AsyncWrite,
{
    fn new(
        p_codec: Codec<T2, U2>,
        s_codec: Codec<T1, U1>,
        recv: Receiver,
    ) -> Self {
        Connection {
            s_codec,
            p_codec,
            recv,
        }
    }
}

impl<T1, T2, U1, U2> Future for Connection<T1, T2, U1, U2>
where
    T1: AsyncRead + AsyncWrite,
    T2: AsyncRead + AsyncWrite,
    U1: Encoder<BytesMut, Error = super::Error>
        + Encoder<Shutdown, Error = super::Error>
        + Decoder<Item = BytesMut, Error = super::Error>,
    U2: Encoder<BytesMut, Error = super::Error>
        + Decoder<Item = BytesMut, Error = super::Error>,
{
    type Output = Result<(), super::Error>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let mut self_ = self.project();

        let recv_mess = self_.recv.poll_mess(
            cx,
            self_.p_codec.as_ref(),
            self_.s_codec.as_ref(),
        )?;

        let p_to_s = self_
            .p_codec
            .as_mut()
            .poll_copy(cx, self_.s_codec.as_mut())?;

        let s_to_p = self_
            .s_codec
            .as_mut()
            .poll_copy2(cx, self_.p_codec.as_mut())?;

        ready!(recv_mess);
        ready!(p_to_s);
        ready!(s_to_p);

        Poll::Ready(Ok(()))
    }
}

enum State {
    Running(CopyBuffer),
    Shutingdown(Shutingdown),
    Shutdown,
}

struct Shutingdown {
    buffered: Option<Shutdown>,
}

impl Shutingdown {
    fn new() -> Self {
        Shutingdown {
            buffered: Some(Shutdown),
        }
    }

    fn poll_shutdown<W>(
        &mut self,
        cx: &mut Context<'_>,
        mut writer: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        W: Sink<Shutdown>,
        super::Error: From<W::Error>,
    {
        if let Some(buf) = self.buffered.take() {
            ready!(self.try_start_send(
                cx,
                buf,
                writer.as_mut()
            ))?;
        }

        Poll::Ready(Ok(()))
    }

    fn try_start_send<W>(
        &mut self,
        cx: &mut Context<'_>,
        item: Shutdown,
        mut writer: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        W: Sink<Shutdown>,
        super::Error: From<W::Error>,
    {
        match writer.as_mut().poll_ready(cx)? {
            Poll::Ready(()) => Poll::Ready(
                writer
                    .as_mut()
                    .start_send(item)
                    .map_err(Into::into),
            ),
            Poll::Pending => {
                self.buffered = Some(item);
                Poll::Pending
            }
        }
    }
}

struct CopyBuffer {
    buffered: Option<BytesMut>,
}

impl CopyBuffer {
    fn new() -> Self {
        CopyBuffer { buffered: None }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        R: Stream<Item = Result<BytesMut, super::Error>>,
        W: Sink<BytesMut>,
        super::Error: From<W::Error>,
    {
        if let Some(buf) = self.buffered.take() {
            ready!(self.try_start_send(
                cx,
                buf,
                writer.as_mut()
            ))?;
        }

        loop {
            match reader.as_mut().poll_next(cx)? {
                Poll::Ready(Some(buf)) => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    ready!(self.try_start_send(
                        cx,
                        buf,
                        writer.as_mut()
                    ))?
                }
                Poll::Ready(None) => {
                    ready!(writer.as_mut().poll_flush(cx))?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    ready!(writer.as_mut().poll_flush(cx))?;
                    return Poll::Pending;
                }
            }
        }
    }

    fn try_start_send<W>(
        &mut self,
        cx: &mut Context<'_>,
        item: BytesMut,
        mut writer: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        W: Sink<BytesMut>,
        super::Error: From<W::Error>,
    {
        match writer.as_mut().poll_ready(cx)? {
            Poll::Ready(()) => Poll::Ready(
                writer
                    .as_mut()
                    .start_send(item)
                    .map_err(Into::into),
            ),
            Poll::Pending => {
                self.buffered = Some(item);
                Poll::Pending
            }
        }
    }
}

pin_project! {
    pub(crate) struct Codec<T, U> {
        #[pin]
        inner: Framed<LimitStream<T>, U>,
        state: State,
    }
}

impl<T, U> Codec<T, U>
where
    T: AsyncRead + AsyncWrite,
{
    fn new(stream: T, codec: U) -> Self {
        Codec {
            inner: Framed::new(LimitStream::new(stream), codec),
            state: State::Running(CopyBuffer::new()),
        }
    }

    #[cfg(test)]
    fn _with_capacity(
        stream: T,
        codec: U,
        capacity: usize,
    ) -> Self {
        Codec {
            inner: Framed::with_capacity(
                LimitStream::new(stream),
                codec,
                capacity,
            ),
            state: State::Running(CopyBuffer::new()),
        }
    }
}

impl<T1, U1> Codec<T1, U1>
where
    T1: AsyncRead,
    U1: Decoder<Item = BytesMut, Error = super::Error>,
{
    fn poll_copy<W>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut sink: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        W: Sink<BytesMut, Error = super::Error>
            + Sink<Shutdown, Error = super::Error>,
    {
        let mut self_ = self.project();
        loop {
            match self_.state {
                State::Running(buf) => {
                    ready!(buf.poll_copy(
                        cx,
                        self_.inner.as_mut(),
                        sink.as_mut(),
                    ))?;
                    *self_.state =
                        State::Shutingdown(Shutingdown::new());
                }
                State::Shutingdown(shutingdown) => {
                    ready!(shutingdown
                        .poll_shutdown(cx, sink.as_mut()))?;
                    ready!(poll_close(cx, sink.as_mut()))?;
                    // tracing::debug!(
                    //     "代理的流主动断开连接 关闭与服务器连接"
                    // );
                    *self_.state = State::Shutdown;
                }
                State::Shutdown => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<T1, U1> Codec<T1, U1>
where
    T1: AsyncRead,
    U1: Decoder<Item = BytesMut, Error = super::Error>,
{
    fn poll_copy2<W>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut sink: Pin<&mut W>,
    ) -> Poll<Result<(), super::Error>>
    where
        W: Sink<BytesMut, Error = super::Error>,
    {
        let mut self_ = self.project();
        loop {
            match self_.state {
                State::Running(buf) => {
                    ready!(buf.poll_copy(
                        cx,
                        self_.inner.as_mut(),
                        sink.as_mut(),
                    ))?;
                    *self_.state =
                        State::Shutingdown(Shutingdown::new());
                }
                State::Shutingdown(_) => {
                    // ready!(shutingdown
                    //     .poll_shutdown(cx, sink.as_mut()))?;
                    ready!(poll_close(cx, sink.as_mut()))?;
                    // tracing::debug!(
                    //     "服务器主动断开连接 关闭与代理流的连接"
                    // );
                    *self_.state = State::Shutdown;
                }
                State::Shutdown => return Poll::Ready(Ok(())),
            }
        }
    }
}

fn poll_close<W>(
    cx: &mut Context<'_>,
    sink: Pin<&mut W>,
) -> Poll<Result<(), super::Error>>
where
    W: Sink<BytesMut, Error = super::Error>,
{
    ready!(sink.poll_close(cx))?;
    Poll::Ready(Ok(()))
}

impl<T, U> Deref for Codec<T, U>
where
    T: AsyncRead + AsyncWrite,
{
    type Target = LimitStream<T>;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<T, U> Stream for Codec<T, U>
where
    U: Decoder<Error = super::Error>,
    T: AsyncRead,
{
    type Item = Result<U::Item, super::Error>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

impl<T, U, I> Sink<I> for Codec<T, U>
where
    U: Encoder<I, Error = super::Error>,
    T: AsyncWrite,
{
    type Error = super::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: I,
    ) -> Result<(), Self::Error> {
        self.project().inner.start_send(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

#[derive(Debug)]
pub(crate) enum InvalidHead {
    NotSupport,
    DecryptionFailed,
    InvalidResponseV,
}

impl From<ring::error::Unspecified> for InvalidHead {
    fn from(_: ring::error::Unspecified) -> Self {
        InvalidHead::DecryptionFailed
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use tokio::net::{TcpListener, TcpStream};
    use tracing_subscriber::{
        prelude::__tracing_subscriber_SubscriberExt,
        util::SubscriberInitExt, EnvFilter, Layer,
    };

    use crate::vmess::{Addr, Config};

    use super::Connections;

    #[tokio::test]
    async fn conn() {
        let res = tracing_subscriber::fmt::layer()
            .with_filter(EnvFilter::new("proto=trace"));

        let console_layer = console_subscriber::spawn();

        tracing_subscriber::registry()
            .with(console_layer)
            .with(res)
            .init();

        let listener =
            TcpListener::bind("127.0.0.1:8100").await.unwrap();

        loop {
            let (p_stream, _socket) =
                listener.accept().await.unwrap();

            let config = Config::builder()
                .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
                .dst_addr(
                    Addr::new_host("http://baidu.com:80")
                        .expect("sss"),
                )
                .server_addr(Addr::new_socket_addr((
                    [127, 0, 0, 1],
                    1234,
                )))
                .build()
                .expect("ss");
            println!("{:?}", config);
            let s_stream = TcpStream::connect("127.0.0.1:1234")
                .await
                .unwrap();

            let (sender, conn, _) = Connections::handshake(
                s_stream, p_stream, &config,
            );
            // if let Err(e) = sender.set_download_speed(10.240) {
            //     println!("{:?}", e);
            // }
            tokio::spawn(conn);

            tokio::spawn(async move {
                let instant = Instant::now();
                sender.closed().await;

                let dur = instant.elapsed();
                println!("run time : {}", dur.as_secs());
            });
        }
    }
}
