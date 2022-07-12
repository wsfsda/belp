use belp::proto::vmess::{
    client::Client, request::Request, Addr,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::Subscriber::builder()
        .pretty()
        .with_env_filter(EnvFilter::new("belp=trace"))
        .try_init()
        .unwrap();

    let client = Client::new();

    let listener =
        TcpListener::bind("127.0.0.1:8100").await.unwrap();

    loop {
        let (stream, _socket) = listener.accept().await.unwrap();
        let mut client = client.clone();

        tokio::spawn(async move {
            let dst_addr = Addr::new_host("www.baidu.com:80");
            let server_addr =
                Addr::new_socket_addr(([127, 0, 0, 1], 1234));
            let req = Request::builder()
                .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
                .dst_addr(dst_addr)
                .server_addr(server_addr)
                .build()
                .unwrap();
            // let mut buf = [0; 1024];

            // let n = stream.read(&mut buf).await.unwrap();

            // println!("{:?}", std::str::from_utf8(&buf[..n]));

            // stream
            //     .write_all(b"HTTP/1.1 200 OK\r\n")
            //     .await
            //     .unwrap();
            // stream
            //     .write_all(
            //         b"Date: Sun, 10 Jul 2022 14:54:28 GMT\r\n\r\n",
            //     )
            //     .await
            //     .unwrap();

            client.send(req, stream).await.unwrap();
        });
    }
}
