use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite};

use super::Result;
use super::{channel, Config};
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};

pub struct Client {
    inner: Arc<Mutex<Vec<Proxyinfo>>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Client {
    pub fn new() -> Self {
        Client {
            inner: Arc::new(Mutex::new(Vec::with_capacity(20))),
        }
    }

    pub async fn proxy<
        T: AsyncRead + AsyncWrite + Send + 'static,
    >(
        &mut self,
        p_stream: T,
        config: Config,
    ) -> Result<()> {
        let (s_stream, local_addr) =
            super::connect::TcpConnector
                .connect(&config)
                .await?;
        tracing::debug!("{:?}", config);
        tracing::debug!("conn is local addr: {}", local_addr);

        let (sender, conn, giver) =
            super::conn::Connections::handshake(
                s_stream, p_stream, &config,
            );

        let proxy_info =
            Proxyinfo::new(sender, config, local_addr);

        tokio::spawn(conn);

        let mut inner = self.inner.lock().unwrap();

        inner.push(proxy_info);

        drop(inner);

        let weak = Arc::downgrade(&self.inner);

        let conn_close = ConnClose::new(weak, giver, local_addr);

        tokio::spawn(conn_close);

        Ok(())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

struct ConnClose {
    giver: want::Giver,
    local_addr: SocketAddr,
    weak: Weak<Mutex<Vec<Proxyinfo>>>,
}

impl ConnClose {
    fn new(
        weak: Weak<Mutex<Vec<Proxyinfo>>>,
        giver: want::Giver,
        local_addr: SocketAddr,
    ) -> Self {
        ConnClose {
            giver,
            local_addr,
            weak,
        }
    }
}

impl Future for ConnClose {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match self.giver.poll_want(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Ready(Err(_)) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for ConnClose {
    fn drop(&mut self) {
        if let Some(arc) = self.weak.upgrade() {
            let mut inner = arc.lock().unwrap();
            tracing::debug!("conn close: {}", self.local_addr);
            inner.retain(|proxyinfo| {
                proxyinfo.local_addr != self.local_addr
            });
        }
    }
}

pub struct Proxyinfo {
    sender: channel::Sender,
    config: Config,
    local_addr: SocketAddr,
}

impl Proxyinfo {
    fn new(
        sender: channel::Sender,
        config: Config,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            sender,
            config,
            local_addr,
        }
    }
}

impl Deref for Proxyinfo {
    type Target = channel::Sender;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}

#[cfg(test)]
mod test {
    use tokio::net::TcpListener;
    use tracing_subscriber::{prelude::*, EnvFilter, Layer};

    use crate::vmess::{Addr, Config};

    use super::Client;

    #[tokio::test]
    async fn client() {
        let res = tracing_subscriber::fmt::layer()
            .pretty()
            .with_filter(EnvFilter::new("proto"));

        let console_layer = console_subscriber::spawn();

        tracing_subscriber::registry()
            .with(console_layer)
            .with(res)
            .init();

        let listener =
            TcpListener::bind("127.0.0.1:8100").await.unwrap();

        let client = Client::new();

        loop {
            let mut client = client.clone();
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

            tokio::spawn(async move {
                let fut = client.proxy(p_stream, config);

                if let Err(e) = fut.await {
                    println!("{:?}", e);
                }
            });
        }
    }
}
