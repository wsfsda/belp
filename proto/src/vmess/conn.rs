use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

pin_project! {
    struct Connection<T, U> {
        #[pin]
        codec: Codec<T, U>,
        
    }
}

pin_project! {
    struct Codec<T, U> {
        #[pin]
        inner: Framed<T, U>,
    }
}

impl<T, U> Codec<T, U>
where
    T: AsyncRead + AsyncWrite,
{
    fn new(stream: T, codec: U) -> Self {
        Codec {
            inner: Framed::new(stream, codec),
        }
    }

    fn with_capacity(
        stream: T,
        codec: U,
        capacity: usize,
    ) -> Self {
        Codec {
            inner: Framed::with_capacity(
                stream, codec, capacity,
            ),
        }
    }
}

impl<T, U> Stream for Codec<T, U>
where
    U: Decoder,
    T: AsyncRead,
{
    type Item = Result<U::Item, U::Error>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

impl<T, U, I> Sink<I> for Codec<T, U>
where
    U: Encoder<I>,
    T: AsyncWrite,
    U::Error: From<std::io::Error>,
{
    type Error = U::Error;

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
