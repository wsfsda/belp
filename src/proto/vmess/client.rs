use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, Weak},
};

use super::{
    conn2::{self, Sender},
    request::Request,
    Addr, Encryption,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use uuid::Uuid;

pub struct Client<I> {
    pool: Pool<PoolClient<I>>,
}

impl<I> Clone for Client<I> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

impl<I> Client<I> {
    pub fn new() -> Self {
        Client { pool: Pool::new() }
    }
}

impl<I> Client<I>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn send(
        &mut self,
        req: Request,
        p_stream: I,
    ) -> Result<(), super::Error> {
        let key = req.ref_parts().into_key();

        if let Some(mut pooled) = self.pool.check_out(&key) {
            tracing::trace!("有连接");
            pooled.send(p_stream)?;
        } else {
            tracing::trace!("创建新的连接");
            let mut pooled = self.connect(key, req).await?;
            pooled.send(p_stream)?;
        }
        // self.clear_close();
        Ok(())
    }

    async fn connect(
        &self,
        key: Key,
        req: Request,
    ) -> Result<Pooled<PoolClient<I>>, super::Error> {
        let s_stream = match &key.s_addr {
            Addr::SocketAddr(addr) => {
                TcpStream::connect(addr).await?
            }
            Addr::Host(uri) => {
                TcpStream::connect(
                    uri.authority().unwrap().as_str(),
                )
                .await?
            }
        };
        let (header, config) = req.seal_header();
        let (send, conn) =
            conn2::handshake(s_stream, header, config);

        tokio::spawn(conn);

        let pclient = PoolClient::new(send);

        let weak =
            Arc::downgrade(self.pool.inner.as_ref().unwrap());

        Ok(Pooled {
            inner: weak,
            key,
            value: Some(pclient),
        })
    }

    fn clear_close(&mut self) {
        let mut inner =
            self.pool.inner.as_mut().unwrap().lock().unwrap();

        inner.clear_close();
    }
}

struct Pool<I> {
    inner: Option<Arc<Mutex<PoolInner<I>>>>,
}

impl<I> Clone for Pool<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I> Pool<I> {
    fn new() -> Self {
        Pool {
            inner: Some(Arc::new(Mutex::new(PoolInner::new()))),
        }
    }
}

impl<I> Pool<PoolClient<I>> {
    fn check_out(
        &mut self,
        key: &Key,
    ) -> Option<Pooled<PoolClient<I>>> {
        let mut inner = self.inner.as_mut()?.lock().unwrap();
        let vpclient = inner.map.get_mut(key)?;
        tracing::warn!("map: {:?}", vpclient);

        while let Some(pclient) = vpclient.pop() {
            if pclient.is_closed() {
                continue;
            }

            if pclient.is_ready() {
                tracing::warn!("map: {:?}", vpclient);

                drop(inner);

                let weak =
                    Arc::downgrade(self.inner.as_ref().unwrap());

                return Some(Pooled {
                    value: Some(pclient),
                    key: key.clone(),
                    inner: weak,
                });
            }
        }
        None
    }
}

struct Pooled<I: Poolable> {
    value: Option<I>,
    key: Key,
    inner: Weak<Mutex<PoolInner<I>>>,
}

impl<I: Poolable> Pooled<I> {
    fn as_ref(&self) -> &I {
        self.value.as_ref().expect("not dropped")
    }

    fn as_mut(&mut self) -> &mut I {
        self.value.as_mut().expect("not dropped")
    }
}

impl<I: Poolable> Deref for Pooled<I> {
    type Target = I;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<I: Poolable> DerefMut for Pooled<I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<I: Poolable> Drop for Pooled<I> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            tracing::trace!("回收发送者 {}", value.is_closed());
            if value.is_closed() {
                return;
            }
            if let Some(arc) = self.inner.upgrade() {
                if let Ok(mut mutx) = arc.lock() {
                    if let Some(vpclient) =
                        mutx.map.get_mut(&self.key)
                    {
                        tracing::trace!("回收发送者");
                        vpclient.push(value);
                    } else {
                        mutx.map.insert(
                            self.key.clone(),
                            vec![value],
                        );
                    }
                }
            }
        }
    }
}

trait Poolable {
    fn is_closed(&self) -> bool;

    fn is_ready(&self) -> bool;
}

impl<I> Poolable for PoolClient<I> {
    fn is_closed(&self) -> bool {
        self.is_closed()
    }

    fn is_ready(&self) -> bool {
        self.is_ready()
    }
}

struct PoolInner<I> {
    map: HashMap<Key, Vec<I>>,
}

impl<I> PoolInner<I> {
    fn new() -> Self {
        PoolInner {
            map: HashMap::new(),
        }
    }
}

impl<I> PoolInner<PoolClient<I>> {
    fn clear_close(&mut self) {
        tracing::warn!("map: {:?}", self.map);
        self.map.retain(|_, v| {
            v.retain(|pclient| !pclient.is_closed());

            !v.is_empty()
        });
        tracing::warn!("map: {:?}", self.map);
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct Key {
    uuid: Uuid,
    encryp: Encryption,
    s_addr: Addr,
    dst_addr: Addr,
}

impl Key {
    pub fn new(
        uuid: Uuid,
        encryp: Encryption,
        s_addr: Addr,
        dst_addr: Addr,
    ) -> Self {
        Key {
            uuid,
            encryp,
            s_addr,
            dst_addr,
        }
    }
}

struct PoolClient<I> {
    send: Sender<I>,
}

impl<I> Debug for PoolClient<I> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("PoolClient")
            .field("send_close", &self.send.is_closed())
            .field("send_ready", &self.send.is_ready())
            .finish()
    }
}

impl<I> PoolClient<I> {
    fn new(send: Sender<I>) -> Self {
        PoolClient { send }
    }

    fn is_ready(&self) -> bool {
        self.send.is_ready()
    }

    fn is_closed(&self) -> bool {
        self.send.is_closed()
    }

    fn send(
        &mut self,
        val: I,
    ) -> Result<(), super::conn2::ConnError> {
        self.send.send(val).map_err(|(_, error)| error)
    }
}

#[cfg(test)]
mod test {

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing_subscriber::EnvFilter;

    use crate::proto::vmess::{request::Request, Addr};

    use super::Client;

    #[tokio::test]
    async fn client() {
        tracing_subscriber::fmt::Subscriber::builder()
            .pretty()
            .with_env_filter(EnvFilter::new("belp=trace"))
            .try_init()
            .unwrap();

        let mut client = Client::new();

        let dst_addr = Addr::new_host("127.0.0.1:6000");
        let server_addr =
            Addr::new_socket_addr(([127, 0, 0, 1], 1234));
        let req = Request::builder()
            .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
            .dst_addr(dst_addr)
            .server_addr(server_addr)
            .build()
            .unwrap();

        let (mut s, ps) = tokio::io::duplex(1024);

        let _res = client.send(req, ps).await;

        s.write_all(b"Hello World").await.unwrap();
        let mut buf = [0; 1024];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            println!("{:?}", std::str::from_utf8(&buf[0..n]));
        }
    }
}
