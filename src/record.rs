use std::sync::Arc;

use base64::Engine;
use http_body_util::BodyExt;
use hudsucker::{
    Body, RequestOrResponse, decode_request, decode_response, futures::channel::mpsc,
    tokio_tungstenite::tungstenite::http::uri::Scheme,
};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use regex::Regex;
use sha2::Digest;
use tokio::sync::RwLock;

use crate::{Contents, Pages};

pub async fn record(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    pages: &Arc<RwLock<Pages>>,
    req: Request<Body>,
    forget_regex: Option<&Regex>,
    forget_redirects_to: Option<&Regex>,
    forget_redirects_from: Option<&Regex>,
    record_text: Option<&Regex>,
    reject: Option<&Regex>,
) -> RequestOrResponse {
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
                            )
                            .into(),
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
                    Body::from_stream(futures_util::stream::iter([Ok::<_, hudsucker::Error>(
                        req_body,
                    )])),
                );
                let store_body_info = req.method() != "HEAD";
                let url = crate::process_uri(&original_url);
                if matches!(forget_regex, Some(x) if x.is_match(&url.to_string())) {
                    forget = true;
                }
                if !forget {
                    all_urls.push(url.to_string());
                }
                if matches!(reject, Some(x) if x.is_match(&url.to_string())) {
                    let mut res = Response::new(
                        format!("Rejected '{}' based upon regex", original_url).into(),
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
                                        let target1 = crate::process_uri(&target);
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
                                                if let Some(auth) = &mut parts.authority
                                                    && let Ok(x) = format!("{}:{}", auth.host(), if matches!(&parts.scheme, Some(x) if *x == Scheme::HTTP) {
                                                        80
                                                    } else {
                                                        443
                                                    }).parse() {
                                                        *auth = x;
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
