#![allow(warnings)]

mod args;

use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use azure_core::auth::{AccessToken, TokenCredential};
use azure_identity::{create_default_credential, AzureCliCredential, DefaultAzureCredential};
use bytes::Bytes;
use clap::Parser;
use http::{response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1::{self, Parts};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::tokio::TokioIo;
use hyper_util::rt::tokio::TokioTimer;
use log::LevelFilter;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

lazy_static::lazy_static! {
    static ref HOP_HEADERS: Vec<http::HeaderName> = vec![
        http::HeaderName::from_str("Connection").unwrap(),
        http::HeaderName::from_str("Keep-Alive").unwrap(),
        http::HeaderName::from_str("Proxy-Authenticate").unwrap(),
        http::HeaderName::from_str("Proxy-Authorization").unwrap(),
        http::HeaderName::from_str("Te").unwrap(),
        http::HeaderName::from_str("Trailers").unwrap(),
        http::HeaderName::from_str("Transfer-Encoding").unwrap(),
        http::HeaderName::from_str("Upgrade").unwrap(),
        http::HeaderName::from_str("Host").unwrap(),
    ];
}

#[derive(Debug)]
enum ProxyError {
    InvalidInput,
    AccessToken,
    Other(String),
}

async fn proxy_azure(
    req: Request<hyper::body::Incoming>,
    base_addr: Arc<String>,
    azure_client: Arc<
        hyper_util::client::legacy::Client<
            hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            hyper::body::Incoming,
        >,
    >,
    credential: Arc<dyn TokenCredential>,
    scope: Arc<Vec<String>>,
) -> Result<Response<hyper::body::Incoming>, Infallible> {
    match _proxy_azure(req, base_addr, azure_client, credential, scope).await {
        Ok(resp) => Ok(resp),
        Err(error) => {
            log::error!("ran into error {:?}", error);
            todo!("handle error")
        }
    }
}
async fn _proxy_azure(
    req: Request<hyper::body::Incoming>,
    base_addr: Arc<String>,
    azure_client: Arc<
        hyper_util::client::legacy::Client<
            hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            hyper::body::Incoming,
        >,
    >,
    credential: Arc<dyn TokenCredential>,
    scope: Arc<Vec<String>>,
) -> Result<Response<hyper::body::Incoming>, ProxyError> {
    // get required params
    let path_and_query = req.uri().path_and_query().ok_or(ProxyError::InvalidInput)?;
    let request_uri = path_and_query.path();
    let request_query = path_and_query.query().ok_or(ProxyError::InvalidInput)?;
    let request_method = req.method();
    let request_headers = req.headers();

    log::info!("Requesting: {}", request_uri);

    // get azure access_token
    let scope = scope.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
    let access_token = credential.get_token(&scope).await.map_err(|x| {
        log::info!("Error: {:?}", x);
        ProxyError::AccessToken
    })?;
    let token = access_token.token.secret();

    let mut az_req_builder = Request::builder()
        .method(request_method)
        .uri(&format!("{base_addr}{request_uri}?{request_query}"))
        .header("Authorization", format!("Bearer {}", token));

    for header in request_headers {
        if !HOP_HEADERS.contains(header.0) {
            az_req_builder = az_req_builder.header(header.0, header.1);
        }
    }

    let azure_request = az_req_builder.body(req.into_body()).unwrap();

    azure_client
        .request(azure_request)
        .await
        .map_err(|_| ProxyError::Other("Hyper Error".to_string()))
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    simple_logging::log_to(io::sink(), LevelFilter::Info);
    let args = args::Args::parse();
    let addr: SocketAddr = args.listen_addr.parse()?;
    let base_addr = args.base_addr;
    let mut scope = args.scope;

    if scope.is_empty() {
        scope.push(format!("{base_addr}/.default"));
    }

    if scope.iter().any(|x| !x.contains(&base_addr)) {
        scope.push(format!("{base_addr}/.default"));
    }

    log::info!("scope is {}", scope.join(","));

    let base_addr = Arc::new(base_addr);
    let scope = Arc::new(scope);

    let credential = create_default_credential()?;

    let https = hyper_tls::HttpsConnector::new();
    let client: hyper_util::client::legacy::Client<
        hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        hyper::body::Incoming,
    > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, hyper::body::Incoming>(https);

    let azure_client = Arc::new(client);
    let listener = TcpListener::bind(addr).await?;
    log::info!("Listening on http://{}", addr);
    loop {
        let (tcp, _) = listener.accept().await?;
        let io = TokioIo::new(tcp);
        let base_addr = base_addr.clone();
        let scope = scope.clone();
        let credential = credential.clone();
        let azure_client = azure_client.clone();
        tokio::task::spawn(async move {
            let credential = credential.clone();
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(
                    io,
                    service_fn(|req| {
                        let credential = credential.clone();
                        let base_addr = base_addr.clone();
                        let azure_client = azure_client.clone();
                        let scope = scope.clone();
                        async move {
                            proxy_azure(
                                req,
                                base_addr,
                                // reuse existing client for connection pooling
                                azure_client,
                                credential,
                                scope,
                            )
                            .await
                        }
                    }),
                )
                .await
            {
                log::info!("Error serving connection: {:?}", err);
            }
        });
    }
}
