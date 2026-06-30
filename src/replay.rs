use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use hudsucker::{Body, RequestOrResponse, futures::channel::mpsc};
use hyper::{Request, Response, StatusCode, Uri};
use tokio::io::AsyncReadExt;

// Relative to some base
fn get_cache_path(url: &Uri) -> PathBuf {
    let mut path = PathBuf::new();

    // To a pathy format
    let url = crate::process_uri(url);

    if let Some(scheme) = url.scheme_str() {
        path.push(scheme);
    }
    if let Some(auth) = url.authority() {
        path.push(auth.to_string());
    }
    for comp in url.path().split('/').filter(|x| !x.is_empty()) {
        path.push(comp);
    }

    path
}

pub async fn replay(req: Request<Body>, dir: &'static Dir) -> RequestOrResponse {
    match req.method().as_str() {
        // Connect = "Please proxy to this server"
        // Since we are the proxy, and we are an offline
        // replay, always just reply with a 200
        "CONNECT" => Response::new("Offline replay".into()).into(),
        "HEAD" => {
            // The probable path of the request if cached
            let path = get_cache_path(req.uri());

            // The path should exist with the current impl, but we don't actually
            // want to open as it's empty.
            if path.exists() {
                // HEAD only cares about the header meta data, which we do not cache.
                // So just get whatever default
                Response::new(Body::empty()).into()
            } else {
                // No file at the cache path.
                let mut res = Response::new(
                    format!(
                        "Unable to find '{}', was expected to be at '{}'",
                        req.uri(),
                        path.display()
                    )
                    .into(),
                );
                *res.status_mut() = StatusCode::NOT_FOUND;
                res.into()
            }
        }
        "GET" => {
            // The probable path of the request if cached
            let path = get_cache_path(req.uri());

            // Next, try to stream the file back to the client
            if let Ok(file) = crate::open_file(dir, &path).await {
                // Create a channel for streaming
                let (mut tx, rx) = mpsc::channel::<Result<hyper::body::Bytes, hudsucker::Error>>(1);

                // Create a body to stream back
                let body = Body::from_stream(rx);

                // Opened with cap-std, so conversion is fine
                let mut file = tokio::fs::File::from_std(file.into_std());

                // Spawn a task for reading the file to the stream
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

                Response::new(body).into()
            } else {
                // No file at the cache path.
                let mut res = Response::new(
                    format!(
                        "Unable to find '{}', was expected to be at '{}'",
                        req.uri(),
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
    }
}
