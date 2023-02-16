use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use ipnetwork::{Ipv4Network, Ipv6Network};
use mime::Mime;
use reqwest::{header::CONTENT_TYPE, Client};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use url::{Host, ParseError, Url};
use validator::Validate;

fn blacklisted_ipv4networks() -> impl Iterator<Item = Ipv4Network> {
    std::iter::empty()
        .chain(std::iter::once(
            Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
        ))
        .chain(std::iter::once(
            Ipv4Network::new(Ipv4Addr::new(169, 254, 0, 0), 16).unwrap(),
        ))
        .chain(std::iter::once(
            Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        ))
        .chain(std::iter::once(
            Ipv4Network::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
        ))
}

fn blacklisted_ipv6networks() -> impl Iterator<Item = Ipv6Network> {
    //TODO blacklist private networks etc.
    std::iter::empty::<Ipv6Network>()
}

struct AppState {
    client: Client,
}

#[derive(Serialize, Debug)]
pub enum ProxyError {
    RequestFailed,
    ForbiddenProxy,
    CouldNotResolve,
    BadContentType,
    MissingContentType,
    UnsupportedContentType,
    LabelMe,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        match *self {
            ProxyError::RequestFailed
            | ProxyError::ForbiddenProxy
            | ProxyError::BadContentType
            | ProxyError::MissingContentType => StatusCode::BAD_REQUEST,
            ProxyError::UnsupportedContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ProxyError::CouldNotResolve | ProxyError::LabelMe => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ParseError> for ProxyError {
    fn from(_: ParseError) -> Self {
        ProxyError::ForbiddenProxy
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(_: std::io::Error) -> Self {
        ProxyError::CouldNotResolve
    }
}

#[derive(Validate, Deserialize)]
pub struct Parameters {
    #[validate(url)]
    url: String,
}

fn check_addr(addr: IpAddr) -> Result<(), ProxyError> {
    match addr {
        IpAddr::V4(addr) => {
            for network in blacklisted_ipv4networks() {
                if network.contains(addr) {
                    return Err(ProxyError::ForbiddenProxy);
                }
            }
            Ok(())
        }
        IpAddr::V6(addr) => {
            for network in blacklisted_ipv6networks() {
                if network.contains(addr) {
                    return Err(ProxyError::ForbiddenProxy);
                }
            }
            Ok(())
        }
    }
}

fn check_url(url: &Url) -> Result<(), ProxyError> {
    match url.host() {
        Some(Host::Domain(_)) => Ok(()),
        Some(Host::Ipv4(addr)) => check_addr(IpAddr::V4(addr)),
        Some(Host::Ipv6(addr)) => check_addr(IpAddr::V6(addr)),
        None => todo!(),
    }
}

#[get("/proxy")]
async fn proxy(
    state: web::Data<AppState>,
    query: web::Query<Parameters>,
) -> Result<impl Responder, ProxyError> {
    //TODO better errors
    let url = Url::parse(&query.into_inner().url)?;
    check_url(&url)?;

    let resp = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|_| ProxyError::RequestFailed)?;

    let addr = match resp.remote_addr() {
        Some(addr) => Ok(addr),
        None => Err(ProxyError::LabelMe),
    }?;
    check_addr(addr.ip())?;

    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .ok_or(ProxyError::MissingContentType)?
        .to_str()
        .map_err(|_| ProxyError::LabelMe)?;

    let mime: Mime = content_type
        .parse()
        .map_err(|_| ProxyError::BadContentType)?;

    match mime.type_() {
        mime::IMAGE | mime::VIDEO => Ok(HttpResponse::Ok().streaming(resp.bytes_stream())),
        _ => Err(ProxyError::UnsupportedContentType),
    }
}

//TODO
//Add HMAC signing to verify of link
//Add config and command line options for the following
//  Max media size
//  Allowed mime types
//  Ip
//  Port
//  Timeout
//  SSL
//  User agent name
//  Better errors
//  HMAC key
//  Additional HTTP headers
//  Unix socket instead of listen ip
//  Blacklist networks
//  Vebose logging?
//Add command line help
//Make endpoint filename so it doesn't download as "proxy" but as actual filename (like how discord does it
//Optional file validation with something like imagemagick etc.?
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    HttpServer::new(|| {
        App::new()
            .app_data(web::Data::new(AppState {
                client: Client::new(),
            }))
            .service(proxy)
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
