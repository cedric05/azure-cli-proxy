#![allow(warnings)]

mod args;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use azure_core::auth::{AccessToken, TokenCredential};
use azure_identity::AzureCliCredential;
use bytes::Bytes;
use clap::Parser;
use http::response;
use http_body_util::Full;
use hyper::server::conn::http1::{self, Parts};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::tokio::TokioIo;
use hyper_util::rt::tokio::TokioTimer;
use tokio::net::{TcpListener, TcpStream};

async fn proxy_azure(
    req: Request<impl hyper::body::Body>,
    base_addr: String,
    access_token: AccessToken,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // get required params
    let uri = req.uri().path_and_query().unwrap().path();
    let query = req.uri().path_and_query().unwrap().query().unwrap();
    let method = req.method();
    println!("Requesting: {}", uri);

    // get azure access_token
    let token = access_token.token.secret();

    // create and send proxy request to azure
    let azure_request = reqwest::Client::new()
        .request(method.clone(), &format!("{base_addr}{uri}?{query}"))
        .header("Authorization", format!("Bearer {}", token));
    let resp = azure_request.send().await.unwrap();

    // create response
    let mut builder = response::Builder::new().status(resp.status());
    let header_mut = builder.headers_mut().unwrap();
    resp.headers().iter().for_each(|x| {
        header_mut.insert(x.0.clone(), x.1.clone());
    });

    // get response body
    let body = resp.bytes().await.unwrap();

    // build return response and return
    Ok(builder.body(Full::new(body)).unwrap())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = args::Args::parse();
    let base_addr = args.base_addr;
    let addr: SocketAddr = args.listen_addr.parse().unwrap();
    let credential = AzureCliCredential::default();
    let credential = Arc::new(credential);
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    loop {
        let (tcp, _) = listener.accept().await?;
        let io = TokioIo::new(tcp);
        let base_addr = base_addr.clone();
        let credential = credential.clone();
        tokio::task::spawn(async move {
            let credential = credential.clone();
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(
                    io,
                    service_fn(|req| {
                        let credential = credential.clone();
                        let base_addr = base_addr.clone();
                        async move {
                            let projected_scope = format!("{}/.default", base_addr);
                            let access_token = credential
                                .get_token(&[projected_scope.as_str()])
                                .await
                                .unwrap();
                            proxy_azure(req, base_addr, access_token).await
                        }
                    }),
                )
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
