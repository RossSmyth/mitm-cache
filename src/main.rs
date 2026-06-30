use clap::{Parser, Subcommand};
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
    certificate_authority::RcgenAuthority,
    hyper::Request,
    rcgen::KeyPair,
    rustls::{
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
    tokio_tungstenite::tungstenite::http::uri::Scheme,
};
use hyper::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rustls_pemfile as pemfile;
use serde::{Serialize, ser::SerializeMap};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;

mod record;
mod replay;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone, Debug, Serialize)]
enum Contents {
    #[serde(rename = "redirect")]
    Redirect(String),
    #[serde(rename = "hash")]
    Hash(String),
    #[serde(rename = "text")]
    Text(String),
}

#[derive(Default, Serialize)]
struct Page {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    contents: Option<Contents>,
    // replaying not implemented
    #[serde(skip_serializing_if = "BTreeMap::is_empty", rename = "post")]
    post_responses: BTreeMap<String, Contents>,
}

#[derive(Default)]
struct Pages(BTreeMap<String, Page>);

impl Serialize for Pages {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut ser = serializer.serialize_map(Some(self.0.len() + 1))?;
        ser.serialize_entry("!version", &1)?;
        for (k, v) in &self.0 {
            ser.serialize_entry(k, v)?;
        }
        ser.end()
    }
}

#[derive(Clone)]
enum Handler {
    Record {
        client: Box<Client<HttpsConnector<HttpConnector>, Body>>,
        pages: Arc<RwLock<Pages>>,
        forget: Option<regex::Regex>,
        forget_redirects_from: Option<regex::Regex>,
        forget_redirects_to: Option<regex::Regex>,
        record_text: Option<regex::Regex>,
        reject: Option<regex::Regex>,
    },
    Replay(PathBuf),
}

pub fn process_uri(uri: &Uri) -> Uri {
    let mut parts = uri.clone().into_parts();

    // strip query
    if let Some(pq) = &mut parts.path_and_query
        && let Ok(pq2) = pq.path().parse()
    {
        *pq = pq2;
    }
    if let Some(auth) = &mut parts.authority
        && let Some(scheme) = &parts.scheme
        && scheme == &Scheme::HTTPS
        && auth.port_u16() == Some(443)
        && let Some(auth2) = auth
            .as_str()
            .strip_suffix(":443")
            .and_then(|x| x.parse().ok())
    {
        *auth = auth2;
    }
    Uri::from_parts(parts).unwrap_or(uri.clone())
}

impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        match self {
            Self::Record {
                client,
                pages,
                forget: forget_regex,
                forget_redirects_to,
                forget_redirects_from,
                record_text,
                reject,
            } => {
                record::record(
                    client,
                    pages,
                    req,
                    forget_regex.as_ref(),
                    forget_redirects_to.as_ref(),
                    forget_redirects_from.as_ref(),
                    record_text.as_ref(),
                    reject.as_ref(),
                )
                .await
            }
            Self::Replay(dir) => replay::replay(req, dir).await,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    Record {
        /// Record text from URLs matching this regex
        #[clap(long, short)]
        record_text: Option<regex::Regex>,
        /// Reject requests to URLs matching this regex
        #[clap(long, short = 'x')]
        reject: Option<regex::Regex>,
        /// Forget requests to URLs matching this regex
        #[clap(long, short = 'F')]
        forget: Option<regex::Regex>,
        /// Forget redirects from URLs matching this regex
        #[clap(long, short = 'f')]
        forget_redirects_from: Option<regex::Regex>,
        /// Forget redirects to URLs matching this regex
        #[clap(long, short = 't')]
        forget_redirects_to: Option<regex::Regex>,
    },
    Replay {
        /// Path to the cache fetched using fetch.nix
        dir: PathBuf,
    },
}

#[derive(Parser)]
struct Args {
    /// Proxy listen address
    #[clap(long, short)]
    listen: Option<SocketAddr>,
    /// Path to the ca.key file
    #[clap(long, short = 'k')]
    ca_key: Option<PathBuf>,
    /// Path to the ca.cer file
    #[clap(long, short = 'c')]
    ca_cert: Option<PathBuf>,
    /// Write MITM cache description to this file
    #[clap(long, short = 'o')]
    out: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> Result<(), hudsucker::Error> {
    let args = Args::parse();
    let addr = args
        .listen
        .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1337));

    let private_key_file = args.ca_key.unwrap_or_else(|| "ca.key".into());
    let private_key_bytes = tokio::fs::read(&private_key_file)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Unable to open private key file '{}'",
                private_key_file.display()
            )
        });

    let public_key_file = args.ca_cert.unwrap_or_else(|| "ca.cer".into());
    let ca_cert_bytes = tokio::fs::read(&public_key_file).await.unwrap_or_else(|_| {
        panic!(
            "Unable to open public key file '{}'",
            public_key_file.display()
        )
    });

    let private_key = PrivatePkcs8KeyDer::from(
        pemfile::pkcs8_private_keys(&mut &private_key_bytes[..])
            .next()
            .unwrap_or_else(|| panic!("The first item in this the file '{}' was expected to be a private x509 key. Nothing was found.", private_key_file.display()))
            .unwrap_or_else(|_| panic!("The first item in the pem file '{}' was not a valid x509 private key.", private_key_file.display()))
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = CertificateDer::from(
        pemfile::certs(&mut &ca_cert_bytes[..])
            .next()
            .unwrap_or_else(|| panic!("The first item in this pem file '{}' was expected to be a public x509 key. Nothing was found.", public_key_file.display()))
            .unwrap_or_else(|_| panic!("The first item in the pem file '{}' was not a valid x509 public key.", public_key_file.display()))
            .to_vec(),
    );

    let key_pair = KeyPair::try_from(&private_key).unwrap_or_else(|_| {
        panic!(
            "Failed to parse private key from the pem file '{}'",
            private_key_file.display()
        )
    });
    let ca_issuer = hudsucker::rcgen::Issuer::from_ca_cert_der(&ca_cert, key_pair)
        .expect("Failed to create x509 cert issuer with the supplied key-pair");
    let ca = RcgenAuthority::new(ca_issuer, 1_000, aws_lc_rs::default_provider());

    let pages = Arc::new(RwLock::new(Pages(BTreeMap::default())));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(match args.cmd {
            Command::Replay { dir } => Handler::Replay(dir),
            Command::Record {
                forget,
                forget_redirects_to,
                forget_redirects_from,
                record_text,
                reject,
            } => Handler::Record {
                client: Box::new(
                    Client::builder(TokioExecutor::new()).build(
                        HttpsConnectorBuilder::new()
                            .with_native_roots()
                            .expect("Unable to build http connect with native roots")
                            .https_or_http()
                            .enable_http1()
                            .build(),
                    ),
                ),
                pages: pages.clone(),
                forget,
                forget_redirects_from,
                forget_redirects_to,
                record_text,
                reject,
            },
        })
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to build proxy object.");

    let pages1 = pages.clone();
    tokio::spawn(async move {
        let mut ch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()).unwrap();
        let mut buf = Vec::new();
        while let Some(()) = ch.recv().await {
            let pages = pages.read().await;
            buf.clear();
            pages
                .serialize(&mut serde_json::Serializer::with_formatter(
                    &mut buf,
                    serde_json::ser::CompactFormatter,
                ))
                .unwrap();
            tokio::fs::write("tmp.json", &buf)
                .await
                .expect("Unable to write to file tmp.json");
        }
    });
    let ret = proxy.start().await;

    let pages = pages1.read().await;
    let mut buf = Vec::new();
    pages
        .serialize(&mut serde_json::Serializer::with_formatter(
            &mut buf,
            serde_json::ser::CompactFormatter,
        ))
        .unwrap_or_else(|_| panic!("Unable to serialize the data to json:\n{:?}", buf));

    let output = args.out.unwrap_or("out.json".into());
    tokio::fs::write(&output, &buf)
        .await
        .unwrap_or_else(|_| panic!("Unable to write output to file '{}'", output.display()));
    ret
}
