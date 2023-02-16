#[macro_use]
extern crate lazy_static;
use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use dns_lookup::lookup_host;
use ipnetwork::Ipv4Network;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use url::{Host, Url, ParseError};
use validator::Validate;
//use mime::Mime;

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

#[derive(Serialize, Debug)]
pub enum ProxyError {
    RequestFailed,
    ForbiddenProxy,
    CouldNotResolve,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        match *self {
            ProxyError::RequestFailed => StatusCode::BAD_REQUEST,
            ProxyError::ForbiddenProxy => StatusCode::BAD_REQUEST,
            ProxyError::CouldNotResolve => StatusCode::INTERNAL_SERVER_ERROR,
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
        IpAddr::V6(_) => {
            todo!()
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
async fn proxy(query: web::Query<Parameters>) -> Result<impl Responder, ProxyError> {
    //TODO better errors
    let url = Url::parse(&query.into_inner().url)?;
    check_url(&url)?;

    let ips = lookup_host(url.host_str().unwrap())?;

    ips.into_iter().map(check_addr).collect::<Result<_,_>>()?;

    let resp = CLIENT
        .get(url)
        .send()
        .await
        .map_err(|_| ProxyError::RequestFailed)?;

    Ok(HttpResponse::Ok())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    HttpServer::new(|| App::new().service(proxy))
        .bind(("localhost", 8080))?
        .run()
        .await
}
