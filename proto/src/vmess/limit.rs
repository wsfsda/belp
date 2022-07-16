use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_speed_limit::{
    clock::{Clock, StandardClock},
    Limiter, Resource,
};
use futures::Future;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{
    Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt,
};

pin_project! {
    struct LimitStream<T> {
        #[pin]
        inner: Compat<Resource<Compat<T>,StandardClock>>,
        limiter: Limiter,
    }
}

impl<T> LimitStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn new(stream: T) -> Self {
        let compat = stream.compat();
        let limiter = Limiter::new(f64::INFINITY);

        let inner = limiter.clone().limit(compat);
        let inner = inner.compat();

        Self { inner, limiter }
    }
}

impl<T> LimitStream<T> {
    fn set_speed_limit(&self, speed_limit: f64) {
        self.limiter.set_speed_limit(speed_limit)
    }

    fn total_bytes(&self) -> usize {
        self.limiter.total_bytes_consumed()
    }
}

impl<T> AsyncRead for LimitStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for LimitStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[derive(Clone, Default)]
struct TokioClock;

// impl Clock for TokioClock {
//     type Instant = std::time::Instant;

//     type Delay = Delay;

//     fn now(&self) -> Self::Instant {
//         std::time::Instant::now()
//     }

//     fn sleep(&self, dur: std::time::Duration) -> Self::Delay {
//         Delay {
//             inner: tokio::time::sleep(dur),
//         }
//     }
// }

pin_project! {
    struct Delay {
        #[pin]
        inner: tokio::time::Sleep
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_read() {
        use super::LimitStream;
        use std::io::Cursor;
        use std::time::Instant;
        use tokio::io::AsyncReadExt;

        let data = "Hello World".as_bytes().to_vec();
        let cur = Cursor::new(data);

        let mut stream = LimitStream::new(cur);
        stream.set_speed_limit(1.0);
        let instant = Instant::now();
        let mut buf = [0; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            println!("{:?}", n);
            if n == 0 {
                break;
            }
        }

        println!("{:?}", instant.elapsed().as_secs());
    }
}
