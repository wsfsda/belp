use super::{conn::Codec, Result};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{future::Either, Future, TryFutureExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

pub struct Sender {
    inner: mpsc::UnboundedSender<Message>,
}

impl Sender {
    pub fn set_upload_speed(&self, speed: f64) -> Result<()> {
        self.inner.send(Message::SetUploadSpeed(speed))?;
        Ok(())
    }

    pub fn set_download_speed(&self, speed: f64) -> Result<()> {
        self.inner.send(Message::SetDownloadSpeed(speed))?;
        Ok(())
    }

    pub fn total_upload_bytes(
        &self,
    ) -> impl Future<Output = Result<usize>> {
        let (tx, rx) = oneshot::channel();

        if let Err(err) =
            self.inner.send(Message::TotalUploadBytes(tx))
        {
            return Either::Left(async { Err(err.into()) });
        }

        Either::Right(rx.map_err(Into::into))
    }

    pub fn total_download_bytes(
        &self,
    ) -> impl Future<Output = Result<usize>> {
        let (tx, rx) = oneshot::channel();

        if let Err(err) =
            self.inner.send(Message::TotalDownloadBytes(tx))
        {
            return Either::Left(async { Err(err.into()) });
        }

        Either::Right(rx.map_err(Into::into))
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    #[cfg(test)]
    pub(crate) async fn closed(&self) {
        self.inner.closed().await;
    }
}

pub(crate) enum Message {
    SetUploadSpeed(f64),
    SetDownloadSpeed(f64),
    TotalUploadBytes(oneshot::Sender<usize>),
    TotalDownloadBytes(oneshot::Sender<usize>),
}

pub(crate) struct Receiver {
    inner: mpsc::UnboundedReceiver<Message>,
    _taker: want::Taker,
}

impl Receiver {
    pub fn poll_recv(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<Message>> {
        match self.inner.poll_recv(cx) {
            Poll::Ready(Some(mess)) => Poll::Ready(Ok(mess)),
            Poll::Ready(None) => Poll::Ready(Err(
                super::Error::new_channel_close(),
            )),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) fn poll_mess<T1, T2, U1, U2>(
        &mut self,
        cx: &mut Context<'_>,
        p_codec: Pin<&Codec<T2, U2>>,
        s_codec: Pin<&Codec<T1, U1>>,
    ) -> Poll<Result<()>>
    where
        T1: AsyncRead + AsyncWrite,
        T2: AsyncRead + AsyncWrite,
    {
        match self.poll_recv(cx)? {
            Poll::Ready(mess) => match mess {
                super::channel::Message::SetUploadSpeed(
                    speed,
                ) => {
                    p_codec.set_speed_limit(speed);
                    Poll::Ready(Ok(()))
                }
                super::channel::Message::SetDownloadSpeed(
                    speed,
                ) => {
                    s_codec.as_ref().set_speed_limit(speed);
                    Poll::Ready(Ok(()))
                }
                super::channel::Message::TotalUploadBytes(
                    tx,
                ) => {
                    let total = p_codec.as_ref().total_bytes();
                    Poll::Ready(tx.send(total).map_err(|_| {
                        super::Error::new_channel_close()
                    }))
                }
                super::channel::Message::TotalDownloadBytes(
                    tx,
                ) => {
                    let total = s_codec.as_ref().total_bytes();
                    Poll::Ready(tx.send(total).map_err(|_| {
                        super::Error::new_channel_close()
                    }))
                }
            },
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }

    #[cfg(test)]
    fn _close(&mut self) {
        self.inner.close()
    }
}

pub(crate) fn channel() -> (Sender, Receiver, want::Giver) {
    let (tx, rx) = mpsc::unbounded_channel();

    let (giver, taker) = want::new();

    let sender = Sender { inner: tx };

    let receiver = Receiver {
        inner: rx,
        _taker: taker,
    };

    (sender, receiver, giver)
}
