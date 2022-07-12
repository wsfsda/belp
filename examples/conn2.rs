use std::time::Duration;

use belp::proto::vmess::{
    client::Client, request::Request, Addr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
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

    let (mut stream, pstream) = tokio::io::duplex(1024);

    let res = client.send(req, pstream).await;

    println!("{:?}", res);
    tokio::time::sleep(Duration::from_secs(5)).await;
    tokio::spawn(async move {
        stream.write_all(b"Hello World").await.unwrap();

        let mut buf = [0; 1024];

        stream.read_exact(&mut buf[0..22]).await.unwrap();

        println!("{:?}", std::str::from_utf8(&buf[0..22]));
    });

    let dst_addr = Addr::new_host("127.0.0.1:6000");
    let server_addr =
        Addr::new_socket_addr(([127, 0, 0, 1], 1234));
    let req = Request::builder()
        .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
        .dst_addr(dst_addr)
        .server_addr(server_addr)
        .build()
        .unwrap();

    let (mut stream, pstream) = tokio::io::duplex(1024);

    tokio::time::sleep(Duration::from_secs(5)).await;
    let _res = client.send(req, pstream).await;

    tokio::spawn(async move {
        stream.write_all(b"Hello World").await.unwrap();

        let mut buf = [0; 1024];

        stream.read_exact(&mut buf[0..22]).await.unwrap();

        println!("{:?}", std::str::from_utf8(&buf[0..22]));
    });

    tokio::time::sleep(Duration::from_secs(120)).await;
}
