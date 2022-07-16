use super::{Error, Result};
use std::task::{Context, Poll};

use futures::ready;
use tokio::sync::mpsc::{self, unbounded_channel};

pub(crate) struct Sender<T> {
    inner: mpsc::UnboundedSender<T>,
    giver: want::Giver,
    is_first_send: bool,
}

impl<T> Sender<T> {
    fn poll_ready(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<()>> {
        match self.giver.poll_want(cx)? {
            Poll::Ready(_) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_ready(&self) -> bool {
        self.giver.is_wanting()
    }

    fn is_closed(&self) -> bool {
        self.giver.is_canceled()
    }

    fn can_send(&mut self) -> bool {
        if self.giver.give() || !self.is_first_send {
            self.is_first_send = true;
            true
        } else {
            false
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context,
        val: T,
    ) -> Poll<Result<()>> {
        if !self.is_first_send {
            self.can_send();

            self.inner.send(val)?;
            return Poll::Ready(Ok(()));
        }

        ready!(self.poll_ready(cx))?;
        self.can_send();
        self.inner.send(val)?;

        Poll::Ready(Ok(()))
    }
}

pub(crate) struct Receiver<T> {
    inner: mpsc::UnboundedReceiver<T>,
    taker: want::Taker,
}

impl<T> Receiver<T> {
    fn poll_recv(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<T>> {
        match self.inner.poll_recv(cx) {
            Poll::Ready(item) => match item {
                Some(t) => Poll::Ready(Ok(t)),
                None => {
                    Poll::Ready(Err(Error::new_channel_close()))
                }
            },
            Poll::Pending => {
                self.taker.want();
                Poll::Pending
            }
        }
    }

    fn close(&mut self) {
        self.taker.cancel();
        self.inner.close();
    }
}

pub(crate) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::unbounded_channel();

    let (giver, taker) = want::new();

    let sender = Sender {
        inner: tx,
        giver,
        is_first_send: false,
    };

    let receiver = Receiver { inner: rx, taker };

    (sender, receiver)
}
