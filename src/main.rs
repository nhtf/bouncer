use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use clap::Parser;
use digest::MacError;
use hex::FromHexError;
use hmac::{Hmac, Mac};
use ipnetwork::IpNetwork;
use mime::Mime;
use reqwest::{header::ToStrError, header::CONTENT_LENGTH, header::CONTENT_TYPE, Client, Response};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use url::{Host, ParseError, Url};
use validator::Validate;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "HMAC key", env = "BOUNCER_KEY")]
    key: String,

    #[arg(short, long, default_value = "0.0.0.0", env = "BOUNCER_LISTEN")]
    listen: String,

    #[arg(short, long, default_value_t = 8080u16, env = "BOUNCER_PORT")]
    port: u16,

    #[arg(short, long, default_value_t = 0u64, env = "BOUNCER_MAXSIZE")]
    max_size: u64,

    #[arg(
        short,
        long = "blacklist",
        default_value = "127.0.0.0/8;169.254.0.0/16;10.0.0.0/8;172.16.0.0/12;::1/128;fe80::/10;fec0::/10;fc00::/7;::ffff:0:0/96",
        env = "BOUNCER_BLACKLIST"
    )]
    blacklisted_networks: String,

    #[arg(
        short,
        long,
        help = "Request timeout in millis. 0 for no timeout",
        default_value_t = 0u64,
        env = "BOUNCER_TIMEOUT"
    )]
    timeout: u64, //TODO use Option<u64>?

    #[arg(
        short,
        long = "agent",
        help = "User agent header",
        default_value = "Bouncer/0.1.0",
        env = "BOUNCER_AGENT"
    )]
    user_agent: String,
}

struct AppState {
    client: Client,
    secret: String,
    max_size: u64,
    blacklisted_networks: Vec<IpNetwork>,
}

#[derive(Serialize, Debug)]
enum ProxyError {
    RequestFailed,
    ForbiddenProxy,
    BadContentType,
    MissingContentType,
    MissingContentLength,
    BadContentLength,
    ContentTooLarge,
    UnsupportedContentType,
    InvalidDigest,
    NoHost,
    InvalidScheme,
    CouldNotConsumeText,
    MalformedMetadata,
    LabelMe,
}

#[derive(Validate, Deserialize)]
struct Parameters {
    #[validate(url)]
    url: String,
}

#[derive(Validate, Serialize, Debug)]
struct SignedURL {
    #[validate(url)]
    url: String,

    digest: String,
}

#[derive(Validate, Serialize, Debug)]
struct MediaMetadata {
    #[validate]
    url: SignedURL,

    width: u64,
    height: u64,
}

#[derive(Validate, Serialize, Debug)]
struct Metadata {
    #[validate(url)]
    url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[validate]
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<MediaMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate]
    video: Option<MediaMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        match *self {
            ProxyError::MissingContentLength => StatusCode::LENGTH_REQUIRED,
            ProxyError::ContentTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ProxyError::UnsupportedContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ProxyError::LabelMe | ProxyError::CouldNotConsumeText => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let message = match *self {
            ProxyError::RequestFailed => "Could not GET url",
            ProxyError::ForbiddenProxy => "Will never proxy this address",
            ProxyError::BadContentType => "Content-Type header is invalid",
            ProxyError::MissingContentType => "Response is missing the Content-Type header",
            ProxyError::InvalidDigest => "URL digest does not match",
            ProxyError::BadContentLength => "Content length is not valid",
            ProxyError::MissingContentLength => "Response is missing the Content-Length header",
            ProxyError::ContentTooLarge => "Response body is too large to proxy",
            ProxyError::UnsupportedContentType => "Will not proxy Content-Type",
            ProxyError::NoHost => "No host specified",
            ProxyError::InvalidScheme => "Will only proxy http and https requests",
            ProxyError::MalformedMetadata => "Metadata is ill-formed",
            _ => "Internal server error",
        };
        HttpResponse::build(self.status_code())
            .content_type(mime::APPLICATION_JSON.to_string())
            .body(
                json!({
                        "error": message,
                })
                .to_string(),
            )
    }
}

macro_rules! into_proxy_error {
    ($from:ty,$to:expr) => {
        impl From<$from> for ProxyError {
            fn from(_: $from) -> Self {
                $to
            }
        }
    };
}

into_proxy_error!(ParseError, ProxyError::ForbiddenProxy);
into_proxy_error!(MacError, ProxyError::InvalidDigest);
into_proxy_error!(FromHexError, ProxyError::InvalidDigest);
into_proxy_error!(ToStrError, ProxyError::LabelMe);

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
        None => Err(ProxyError::NoHost),
    }
}

async fn fetch(
    url: &str,
    digest: &str,
    state: &web::Data<AppState>,
) -> Result<(Response, Mime), ProxyError> {
    let url = Url::parse(url)?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ProxyError::InvalidScheme);
    }
    //TODO only allow http and https scheme
    //Check if url is not blacklisted
    check_url(&url, state.blacklisted_networks.iter())?;

    //Verify digest
    //unwrap will never fail for this hashing algorithm
    let mut mac = HmacSha256::new_from_slice(state.secret.as_bytes()).unwrap();
    mac.update(url.as_str().as_bytes());
    mac.verify_slice(&hex::decode(digest.as_bytes())?)?;

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
    Ok((resp, mime))
}

fn extract_metadata(data: String, url: &str, secret: &str) -> Result<Metadata, ProxyError> {
    let doc = Html::parse_document(&data);

    let meta_selector = Selector::parse("meta").map_err(|_| ProxyError::LabelMe)?;
    //let link_selector = Selector::parse("link").map_err(|_| ProxyError::LabelMe)?;
    let metas: HashMap<&str, &str> = doc
        .select(&meta_selector)
        .map(|elem| elem.value())
        .map(|value| {
            (
                value.attr("property").or_else(|| value.attr("name")),
                value.attr("content"),
            )
        })
        .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b))))
        .collect();
    /*
    let links: HashMap<&str, &str> = doc
        .select(&link_selector)
        .map(|elem| elem.value())
        .map(|value| (value.attr("rel"), value.attr("content")))
        .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b))))
        .collect();
    */

    let metadata = Metadata {
        url: url.to_string(),
        title: metas
            .get("og:title")
            .or_else(|| metas.get("twitter:title"))
            .or_else(|| metas.get("title"))
            .map(|x| x.to_string()),
        description: metas
            .get("og:description")
            .or_else(|| metas.get("twitter:description"))
            .or_else(|| metas.get("description"))
            .map(|x| x.to_string()),
        image: metas
            .get("og:image")
            .or_else(|| metas.get("og:image:secure_url"))
            .or_else(|| metas.get("twitter:image"))
            .or_else(|| metas.get("twitter:image:src"))
            .map(|url| {
                MediaMetadata {
                    url: SignedURL {
                        url: url.to_string(),
                        digest: hex::encode(HmacSha256::new_from_slice(secret.as_bytes()).unwrap().chain_update(url).finalize().into_bytes()),
                    },
                    width: metas
                        .get("og:image:width")
                        .unwrap_or(&"0")
                        .parse()
                        .unwrap_or(0),
                    height: metas
                        .get("og:image:height")
                        .unwrap_or(&"0")
                        .parse()
                        .unwrap_or(0),
                }
            }),
        video: metas
            .get("og:video")
            .or_else(|| metas.get("og:video:url"))
            .or_else(|| metas.get("og:video:secure_url"))
            .map(|url| {
                MediaMetadata {
                    url: SignedURL {
                        url: url.to_string(),
                        digest: hex::encode(HmacSha256::new_from_slice(secret.as_bytes()).unwrap().chain_update(url).finalize().into_bytes()),
                    },
                    width: metas
                        .get("og:video:width")
                        .unwrap_or(&"0")
                        .parse()
                        .unwrap_or(0),
                    height: metas
                        .get("og:video:height")
                        .unwrap_or(&"0")
                        .parse()
                        .unwrap_or(0),
                }
            }),
        color: metas.get("theme-color").map(|x| x.to_string()),
    };

    metadata.validate().map_err(|_| ProxyError::MalformedMetadata)?;
    Ok(metadata)
}

#[get("/{digest}/embed")]
async fn embed(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<Parameters>,
) -> Result<impl Responder, ProxyError> {
    let (resp, mime) = fetch(&query.url, &path.into_inner(), &state).await?;

    if mime.type_() != mime::TEXT && mime.subtype() != mime::HTML {
        return Err(ProxyError::BadContentType);
    }
    let metadata = extract_metadata(resp.text().await.map_err(|_| ProxyError::CouldNotConsumeText)?, &query.url, &state.secret)?;

    Ok(web::Json(metadata))
}

#[get("/{digest}/proxy")]
async fn proxy(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<Parameters>,
) -> Result<impl Responder, ProxyError> {
    let (resp, mime) = fetch(&query.url, &path.into_inner(), &state).await?;
    match mime.type_() {
        mime::IMAGE | mime::VIDEO => Ok(HttpResponse::Ok().streaming(resp.bytes_stream())),
        _ => Err(ProxyError::UnsupportedContentType),
    }
}

//TODO
//Add config and command line options for the following
//  Allowed mime types
//  SSL
//  Better errors
//  Additional HTTP headers
//  Unix socket instead of listen ip
//  Vebose logging?
//Add command line help
//Make endpoint filename so it doesn't download as "proxy" but as actual filename (like how discord does it
//Optional file validation with something like imagemagick etc.?
//Better logging of errors
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    println!("Starting bouncer on: {}:{}", args.listen, args.port);

    HttpServer::new(move || {
        let mut builder = Client::builder().user_agent(args.user_agent.clone());
        if args.timeout != 0 {
            builder = builder.timeout(Duration::from_millis(args.timeout));
        }
        App::new()
            .app_data(web::Data::new(AppState {
                client: builder.build().expect("Reqwest client"),
                secret: args.key.clone(),
                max_size: args.max_size,
                blacklisted_networks: args
                    .blacklisted_networks
                    .split(';')
                    .map(|network| network.trim().parse().expect("Expected valid CIDR network"))
                    .collect(),
            }))
            .service(proxy)
            .service(embed)
    })
    .bind((args.listen, args.port))?
    .run()
    .await
}
