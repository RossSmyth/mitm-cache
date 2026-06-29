use base64::Engine;
use clap::{Parser, Subcommand};
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
    certificate_authority::RcgenAuthority,
    decode_request, decode_response,
    futures::channel::mpsc,
    hyper::{Request, Response},
    rcgen::KeyPair,
    rustls::{
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
    tokio_tungstenite::tungstenite::http::uri::Scheme,
};
use hyper::{StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rustls_pemfile as pemfile;
use serde::{Serialize, ser::SerializeMap};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{io::AsyncReadExt, sync::RwLock};

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
        client: Client<HttpsConnector<HttpConnector>, Body>,
        pages: Arc<RwLock<Pages>>,
        forget: Option<regex::Regex>,
        forget_redirects_from: Option<regex::Regex>,
        forget_redirects_to: Option<regex::Regex>,
        record_text: Option<regex::Regex>,
        reject: Option<regex::Regex>,
    },
    Replay(PathBuf),
}

fn process_uri(uri: &Uri) -> Uri {
    let mut parts = uri.clone().into_parts();

    // strip query
    if let Some(pq) = &mut parts.path_and_query {
        if let Ok(pq2) = pq.path().parse() {
            *pq = pq2;
        }
    }
    if let Some(auth) = &mut parts.authority {
        if let Some(scheme) = &parts.scheme {
            if scheme == &Scheme::HTTPS && auth.port_u16() == Some(443) {
                if let Some(auth2) = auth
                    .as_str()
                    .strip_suffix(":443")
                    .and_then(|x| x.parse().ok())
                {
                    *auth = auth2;
                }
            }
        }
    }
    Uri::from_parts(parts).unwrap_or(uri.clone())
}

impl HttpHandler for Handler {
    #[allow(clippy::manual_async_fn)]
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        async move {
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
                    let mut forget = false;
                    let mut all_urls = vec![];
                    let mut req1 = Some(req);
                    loop {
                        let req = req1.take().unwrap();
                        break match req.method().as_str() {
                            "CONNECT" => req.into(),
                            "GET" | "POST" | "HEAD" => {
                                let original_url = req.uri().clone();
                                println!("{req:?}");

                                let verb = req.method().clone();

                                let req = match decode_request(req) {
                                    Ok(req) => req,
                                    Err(err) => {
                                        let mut res = Response::new(
                                            format!(
                                                "Unable to decode the {} request at URI {}\n{:?}",
                                                verb, original_url, err
                                            )
                                            .into(),
                                        );
                                        *res.status_mut() = StatusCode::NOT_FOUND;
                                        return res.into();
                                    }
                                };

                                let (info, body) = req.into_parts();
                                let req_body = match body.collect().await.map(|x| x.to_bytes()) {
                                    Ok(req_body) => req_body,
                                    Err(err) => {
                                        let mut res = Response::new(
                                            format!(
                                                "Unable to collect the request body at {} into bytes\n{:?}",
                                                original_url, err
                                            ).into()
                                        );
                                        *res.status_mut() = StatusCode::NOT_FOUND;
                                        return res.into();
                                    }
                                };

                                let post_body = (info.method == "POST")
                                    .then(|| std::str::from_utf8(&req_body).ok())
                                    .flatten()
                                    .map(ToOwned::to_owned);

                                let req_method = info.method.clone();
                                let req_version = info.version;
                                let req_headers = info.headers.clone();
                                let req = Request::from_parts(
                                    info,
                                    Body::from_stream(futures_util::stream::iter([Ok::<
                                        _,
                                        hudsucker::Error,
                                    >(
                                        req_body
                                    )])),
                                );
                                let store_body_info = req.method() != "HEAD";
                                let url = process_uri(&original_url);
                                if matches!(forget_regex, Some(x) if x.is_match(&url.to_string())) {
                                    forget = true;
                                }
                                if !forget {
                                    all_urls.push(url.to_string());
                                }
                                if matches!(reject, Some(x) if x.is_match(&url.to_string())) {
                                    let mut res = Response::new(
                                        format!("Rejected '{}' based upon regex", original_url)
                                            .into(),
                                    );
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                }
                                let store_full_body = req.method() == "POST"
                                    || matches!(record_text, Some(x) if x.is_match(&url.to_string()));
                                let res = match client.request(req).await {
                                    Ok(res) => res,
                                    Err(err) => {
                                        let mut res = Response::new(format!("Unable to get the content upstream at {}.\nOriginal URL: '{}'\nError: {}", url, original_url, err).into());
                                        *res.status_mut() = StatusCode::NOT_FOUND;
                                        return res.into();
                                    }
                                };
                                let mut res = match decode_response(
                                    res.map(|body| Body::from_stream(body.into_data_stream())),
                                ) {
                                    Ok(res) => res,
                                    Err(err) => {
                                        let mut res = Response::new(format!("Unable to decode the upstream response at {}.\nOriginal URL: {}\nError: {}", url, original_url, err).into());
                                        *res.status_mut() = StatusCode::NOT_FOUND;
                                        return res.into();
                                    }
                                };
                                // println!("{res:?}");
                                if res.status().is_redirection() {
                                if let Ok(location) = res.headers().get("Location").unwrap().to_str() {
                                    let mut pages = pages.write().await;
                                    let location = if let Ok(target) = location.parse::<Uri>() {
                                        let target1 = process_uri(&target);
                                        if matches!(forget_redirects_from, Some(x) if x.is_match(&url.to_string()))
                                            || matches!(forget_redirects_to, Some(x) if x.is_match(&target1.to_string()))
                                        {
                                            forget = true;
                                            let mut req = Request::new(Body::from_stream(futures_util::stream::empty::<Result<hyper::body::Bytes, hudsucker::Error>>()));
                                            *req.method_mut() = req_method;
                                            *req.headers_mut() = req_headers;
                                            *req.version_mut() = req_version;
                                            if let Some(host) = target.host().and_then(|x| TryInto::try_into(x).ok()) {
                                                req.headers_mut().insert("host", host);
                                            }
                                            *req.uri_mut() = if target.port().is_some() {
                                                target
                                            } else {
                                                let target0 = target.clone();
                                                let mut parts = target.into_parts();
                                                if let Some(auth) = &mut parts.authority {
                                                    if let Ok(x) = format!("{}:{}", auth.host(), if matches!(&parts.scheme, Some(x) if *x == Scheme::HTTP) {
                                                        80
                                                    } else {
                                                        443
                                                    }).parse() {
                                                        *auth = x;
                                                    }
                                                }
                                                Uri::from_parts(parts).unwrap_or(target0)
                                            };
                                            req1 = Some(req);
                                            continue;
                                        }
                                        target1.to_string()
                                    } else {
                                        location.to_owned()
                                    };
                                    let contents = Contents::Redirect(location.to_owned());
                                    for url in all_urls {
                                        let page = pages.0.entry(url.to_string()).or_default();
                                        if let Some(post_body) = post_body.clone() {
                                            page.post_responses.entry(post_body).or_insert(contents.clone());
                                        } else if page.contents.is_none() {
                                            page.contents = Some(contents.clone());
                                        }
                                    }
                                }
                                res
                            } else if res.status().is_success() {
                                if store_body_info {
                                    let (info, mut body) = res.into_parts();
                                    let (mut tx, rx) = mpsc::channel(1);
                                    let ret_body = Body::from_stream(rx);
                                    let pages = pages.clone();
                                    tokio::spawn(async move {
                                        let mut sha256 = sha2::Sha256::new();
                                        let mut contents = Vec::<u8>::new();
                                        let mut error = false;
                                        while let Some(data) = body.frame().await {
                                            let data = match data {
                                                Ok(data) => data,
                                                Err(err) => {
                                                    error = true;
                                                    if futures_util::future::poll_fn(|cx| tx.poll_ready(cx)).await.is_err() {
                                                        break;
                                                    }
                                                    if tx.start_send(Err(err)).is_err() {
                                                        break;
                                                    }
                                                    continue;
                                                }
                                            };
                                            let Ok(data) = data.into_data() else {
                                                break;
                                            };
                                            if store_full_body {
                                                contents.extend_from_slice(&data);
                                            }
                                            sha256.update(&data);
                                            if futures_util::future::poll_fn(|cx| tx.poll_ready(cx)).await.is_err() {
                                                error = true;
                                                break;
                                            }
                                            if tx.start_send(Ok(data)).is_err() {
                                                error = true;
                                                break;
                                            }
                                        }
                                        if error {
                                            return;
                                        }
                                        let base64 = base64::engine::general_purpose::STANDARD
                                            .encode(sha256.finalize());
                                        let contents = if let Some(contents) =
                                            std::str::from_utf8(&contents)
                                                .ok()
                                                .filter(|_| store_full_body)
                                        {
                                            Contents::Text(contents.to_owned())
                                        } else {
                                            Contents::Hash("sha256-".to_owned() + &base64)
                                        };
                                        let mut pages = pages.write().await;
                                        for url in all_urls {
                                            let page = pages.0.entry(url).or_default();
                                            if let Some(post_body) = post_body.clone() {
                                                page.post_responses.entry(post_body).or_insert(contents.clone());
                                            } else if page.contents.is_none() {
                                                page.contents = Some(contents.clone());
                                            }
                                        }
                                    });
                                    Response::from_parts(info, ret_body)
                                } else {
                                    // remove hash headers to force the software to download this
                                    // so we get sha256
                                    let headers_to_remove = res
                                        .headers()
                                        .keys()
                                        .filter(|x| {
                                            x.as_str().ends_with("-md5")
                                                || x.as_str().ends_with("-sha1")
                                                || x.as_str().ends_with("-sha256")
                                                || x.as_str().ends_with("-sha512")
                                                || x.as_str() == "x-checksum"
                                        })
                                        .cloned()
                                        .collect::<Vec<_>>();
                                    for header in headers_to_remove {
                                        res.headers_mut().remove(header);
                                    }
                                    res
                                }
                            } else {
                                res
                            }
                            .into()
                            }
                            other => {
                                let original_url = req.uri().clone();

                                let mut res = Response::new(
                                    format!(
                                        "{} request for {} is not supported.\nRequest: \n{:?}",
                                        other, original_url, req
                                    )
                                    .into(),
                                );
                                *res.status_mut() = StatusCode::NOT_FOUND;
                                res.into()
                            }
                        };
                    }
                }
                Self::Replay(dir) => match req.method().as_str() {
                    "CONNECT" => req.into(),
                    "HEAD" | "GET" => {
                        let mut path = dir.clone();
                        let url = process_uri(&req.uri());
                        if let Some(scheme) = url.scheme_str() {
                            path.push(scheme);
                        }
                        if let Some(auth) = url.authority() {
                            path.push(auth.to_string());
                        }
                        for comp in url.path().split('/').filter(|x| !x.is_empty()) {
                            path.push(comp);
                        }
                        if let Ok(mut file) = tokio::fs::File::open(&path).await {
                            let (mut tx, rx) =
                                mpsc::channel::<Result<hyper::body::Bytes, hudsucker::Error>>(1);
                            let body = Body::from_stream(rx);
                            if req.method().as_str() != "HEAD" {
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65536];
                                    while let Ok(n) = file.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        if futures_util::future::poll_fn(|cx| tx.poll_ready(cx))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        if tx.start_send(Ok(buf[..n].to_vec().into())).is_err() {
                                            break;
                                        }
                                    }
                                });
                            }
                            Response::new(body).into()
                        } else {
                            let mut res = Response::new(
                                format!(
                                    "Unable to find '{}', was expected to be at '{}'",
                                    url,
                                    path.display()
                                )
                                .into(),
                            );
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            res.into()
                        }
                    }
                    verb => {
                        let mut res = Response::new(
                            format!(
                                "{} requests are not supported\nURL: '{}'\nRequest:\n{:?}",
                                verb,
                                req.uri(),
                                req
                            )
                            .into(),
                        );
                        *res.status_mut() = StatusCode::NOT_FOUND;
                        res.into()
                    }
                },
            }
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
    let private_key_bytes = tokio::fs::read(&private_key_file).await.expect(&format!(
        "Unable to open private key file '{}'",
        private_key_file.display()
    ));

    let public_key_file = args.ca_cert.unwrap_or_else(|| "ca.cer".into());
    let ca_cert_bytes = tokio::fs::read(&public_key_file).await.expect(&format!(
        "Unable to open public key file '{}'",
        public_key_file.display()
    ));

    let private_key = PrivatePkcs8KeyDer::from(
        pemfile::pkcs8_private_keys(&mut &private_key_bytes[..])
            .next()
            .expect(&format!("The first item in this the file '{}' was expected to be a private x509 key. Nothing was found.", private_key_file.display()))
            .expect(&format!("The first item in the pem file '{}' was not a valid x509 private key.", private_key_file.display()))
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = CertificateDer::from(
        pemfile::certs(&mut &ca_cert_bytes[..])
            .next()
            .expect(&format!("The first item in this pem file '{}' was expected to be a public x509 key. Nothing was found.", public_key_file.display()))
            .expect(&format!("The first item in the pem file '{}' was not a valid x509 public key.", public_key_file.display()))
            .to_vec(),
    );

    let key_pair = KeyPair::try_from(&private_key).expect(&format!(
        "Failed to parse private key from the pem file '{}'",
        private_key_file.display(),
    ));
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
                client: Client::builder(TokioExecutor::new()).build(
                    HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .expect("Unable to build http connect with native roots")
                        .https_or_http()
                        .enable_http1()
                        .build(),
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
                .expect(&format!("Unable to write to file tmp.json"));
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
        .expect(&format!("Unable to serialize the data to json:\n{:?}", buf));

    let output = args.out.unwrap_or("out.json".into());
    tokio::fs::write(&output, &buf).await.expect(&format!(
        "Unable to write output to file '{}'",
        output.display()
    ));
    ret
}
