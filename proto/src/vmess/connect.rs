use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::Config;

pub(crate) struct TcpConnector;

impl TcpConnector {
    pub(crate) async fn connect(
        &self,
        config: &Config,
    ) -> Result<(TcpStream, SocketAddr), super::Error> {
        let stream = match config.get_ref_server_addr() {
            super::Addr::SocketAddr(addr) => {
                TcpStream::connect(addr).await?
            }
            super::Addr::Host(uri) => {
                let host = uri.authority().unwrap().as_str();
                TcpStream::connect(host).await?
            }
        };
        let loacl_addr = stream.local_addr()?;
        Ok((stream, loacl_addr))
    }
}
