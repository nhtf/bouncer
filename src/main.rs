use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use clap::Parser;
use digest::MacError;
use hex::FromHexError;
use hmac::{Hmac, Mac};
use ipnetwork::IpNetwork;
use mime::Mime;
use reqwest::{header::CONTENT_TYPE, header::CONTENT_LENGTH, header::ToStrError, Client};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::IpAddr;
use url::{Host, ParseError, Url};
use validator::Validate;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "HMAC key")]
    key: String,

    #[arg(short, long, default_value = "0.0.0.0")]
    listen: String,

    #[arg(short, long, default_value_t = 8080u16)]
    port: u16,

    #[arg(short, long, default_value_t = 0u64)]
    max_size: u64,

    #[arg(short, long = "blacklist", default_value = "127.0.0.0/8;169.254.0.0/16;10.0.0.0/8;172.16.0.0/12")]
    blacklisted_networks: String,
}

struct AppState {
    client: Client,
    secret: String,
    max_size: u64,
    blacklisted_networks: Vec<IpNetwork>,
}

#[derive(Serialize, Debug)]
pub enum ProxyError {
    RequestFailed,
    ForbiddenProxy,
    CouldNotResolve,
    BadContentType,
    MissingContentType,
    MissingContentLength,
    BadContentLength,
    ContentTooLarge,
    UnsupportedContentType,
    InvalidDigest,
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
            | ProxyError::BadContentLength
            | ProxyError::MissingContentType
            | ProxyError::InvalidDigest => StatusCode::BAD_REQUEST,
            ProxyError::MissingContentLength => StatusCode::LENGTH_REQUIRED,
            ProxyError::ContentTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
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

impl From<MacError> for ProxyError {
    fn from(_: MacError) -> Self {
        ProxyError::InvalidDigest
    }
}

impl From<FromHexError> for ProxyError {
    fn from(_: FromHexError) -> Self {
        ProxyError::InvalidDigest
    }
}

impl From<ToStrError> for ProxyError {
    fn from(_: ToStrError) -> Self {
        ProxyError::LabelMe
    }
}

#[derive(Validate, Deserialize)]
pub struct Parameters {
    #[validate(url)]
    url: String,
}

fn contains<'a, I>(addr: IpAddr, mut networks: I) -> bool
where
    I: Iterator<Item = &'a IpNetwork>,
{
    networks.any(|network| network.contains(addr))
}

fn check_addr<'a, I>(addr: IpAddr, networks: I) -> Result<(), ProxyError>
where
    I: Iterator<Item = &'a IpNetwork>,
{
    match contains(addr, networks) {
        false => Ok(()),
        true => Err(ProxyError::ForbiddenProxy),
    }
}

fn check_url<'a, I>(url: &Url, networks: I) -> Result<(), ProxyError>
where
    I: Iterator<Item = &'a IpNetwork>,
{
    match url.host() {
        Some(Host::Domain(_)) => Ok(()),
        Some(Host::Ipv4(addr)) => check_addr(IpAddr::V4(addr), networks),
        Some(Host::Ipv6(addr)) => check_addr(IpAddr::V6(addr), networks),
        None => todo!(),
    }
}

#[get("/{digest}/proxy")]
async fn proxy(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<Parameters>,
) -> Result<impl Responder, ProxyError> {
    //TODO better errors
    let url = Url::parse(&query.into_inner().url)?;

    //Check if url is not blacklisted
    check_url(&url, state.blacklisted_networks.iter())?;

    //Verify digest
    //Unwrap should never fail since it also has been tested in main
    let mut mac = HmacSha256::new_from_slice(state.secret.as_bytes()).unwrap();
    mac.update(url.as_str().as_bytes());
    mac.verify_slice(&hex::decode(path.into_inner().as_bytes())?)?;

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

    //Check if resolved address is not blacklisted
    if contains(addr.ip(), state.blacklisted_networks.iter()) {
        return Err(ProxyError::ForbiddenProxy);
    }

    let headers = resp.headers();
    let content_type = headers 
        .get(CONTENT_TYPE)
        .ok_or(ProxyError::MissingContentType)?
        .to_str()?;

    let content_length: u64 = headers
        .get(CONTENT_LENGTH)
        .ok_or(ProxyError::MissingContentLength)?
        .to_str()?
        .parse()
        .map_err(|_| ProxyError::BadContentLength)?;

    if state.max_size != 0 && content_length < state.max_size {
        return Err(ProxyError::ContentTooLarge);
    }

    let mime: Mime = content_type
        .parse()
        .map_err(|_| ProxyError::BadContentType)?;

    match mime.type_() {
        mime::IMAGE | mime::VIDEO => Ok(HttpResponse::Ok().streaming(resp.bytes_stream())),
        _ => Err(ProxyError::UnsupportedContentType),
    }
}

//TODO
//Add config and command line options for the following
//  Allowed mime types
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
//Better logging of errors
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    HmacSha256::new_from_slice(args.key.as_bytes()).expect("Invalid key length");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                client: Client::new(),
                secret: args.key.clone(),
                max_size: args.max_size,
                blacklisted_networks: args.blacklisted_networks
                    .split(';')
                    .map(|network| network.trim().parse().expect("Expected valid CIDR network"))
                    .collect(),
            }))
            .service(proxy)
    })
    .bind((args.listen, args.port))?
    .run()
    .await
}
