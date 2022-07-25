use std::{convert::Infallible, path::Path, result, sync::Arc};

use crate::error::Error;

use super::error::Result;
use http::{Method, Request, Response, Uri};
use hyper::{service::service_fn, Body};
use proto::vmess;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

pub struct Context {
    vmess_client: vmess::Client,
    config: InnerConfig,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            vmess_client: self.vmess_client.clone(),
            config: self.config.clone(),
        }
    }
}

type InnerConfig = Arc<config::Config>;

impl Context {
    pub fn new() -> Result<Self> {
        Context::new_path("config.toml")
    }

    pub fn new_path<P: AsRef<Path>>(p: P) -> Result<Self> {
        let config = config::Config::load_path(p)?;

        Ok(Self {
            vmess_client: vmess::Client::new(),
            config: Arc::new(config),
        })
    }

    pub async fn proxy<T>(
        &mut self,
        p_stream: T,
        uri: &Uri,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        if let Some(service) =
            self.config.match_service(uri.host().unwrap())
        {
            match service {
                config::Service::Vmess(v) => {
                    let builder: vmess::Builder = v.into();
                    let config = builder
                        .dst_addr(vmess::Addr::Host(uri.clone()))
                        .build()?;

                    self.vmess_client
                        .proxy(p_stream, config)
                        .await?;
                }
                config::Service::Trojin(t) => todo!(),
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let listener =
            TcpListener::bind("127.0.0.1:5000").await?;
        let mut http = hyper::server::conn::Http::new();
        http.http1_only(true);
        loop {
            let (stream, addr) = listener.accept().await?;
            let conn = http.serve_connection(
                stream,
                service_fn(move |req| {
                    http_service(req, self.clone())
                }),
            );
        }
    }
}

async fn http_service(
    req: Request<Body>,
    mut cx: Context,
) -> result::Result<Response<Body>, Error> {
    if req.method() == Method::CONNECT {
        let uri = req.uri();
        if let Some(host) = uri.host() {
            if let Some(service) = cx.config.match_service(host)
            {
                match service {
                    config::Service::Vmess(v) => {
                        let buidler: vmess::Builder = v.into();
                        let config = buidler
                            .dst_addr(vmess::Addr::Host(
                                uri.clone(),
                            ))
                            .build()?;

                        tokio::spawn(async move {
                            match hyper::upgrade::on(req).await {
                                Ok(upgrade) => {
                                    cx.vmess_client
                                        .proxy(upgrade, config)
                                        .await;
                                }
                                Err(_) => todo!(),
                            }
                        });

                        return Ok(Response::new(Body::empty()));
                    }
                    config::Service::Trojin(t) => todo!(),
                }
            }
        }
    }

    todo!()
}
