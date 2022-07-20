use std::{convert::Infallible, net::SocketAddr};

use belp::proto::vmess::{
    client::Client as VmClient, request::Request as VmRequest,
    Addr,
};
use http::{Method, Request, Response};
use hyper::{
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Server,
};
use tracing_subscriber::EnvFilter;

type HttpClient = Client<hyper::client::HttpConnector>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::Subscriber::builder()
        .pretty()
        .with_env_filter(EnvFilter::new(
            "belp::proto::vmess::client=warn",
        ))
        .try_init()
        .unwrap();

    let vmclient = VmClient::new();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let vmclient = vmclient.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy(client.clone(), vmclient.clone(), req)
            }))
        }
    });

    let server = Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn proxy(
    _client: HttpClient,
    vmclient: VmClient<Upgraded>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) =
                            tunnel(upgraded, vmclient, addr)
                                .await
                        {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            eprintln!(
                "CONNECT host is not socket addr: {:?}",
                req.uri()
            );
            let mut resp = Response::new(Body::from(
                "CONNECT must be to a socket address",
            ));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) =
                            tunnel(upgraded, vmclient, addr)
                                .await
                        {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });
        }

        Ok(Response::new(Body::empty()))
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    mut vmclient: VmClient<Upgraded>,
    addr: String,
) -> std::io::Result<()> {
    // Connect to remote server
    let dst_addr = Addr::new_host(addr);
    let server_addr =
        Addr::new_socket_addr(([127, 0, 0, 1], 1234));
    let req = VmRequest::builder()
        .uuid("a092e197-d7b3-3dc1-bef0-2eaa6ff34a7d")
        .dst_addr(dst_addr)
        .server_addr(server_addr)
        .build()
        .unwrap();
    if let Err(e) = vmclient.send(req, upgraded).await {
        println!("{:?}", e);
    }

    Ok(())
}
