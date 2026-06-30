use std::path::Path;

use hudsucker::{Body, RequestOrResponse, futures::channel::mpsc};
use hyper::{Request, Response, StatusCode};
use tokio::io::AsyncReadExt;

pub async fn replay(req: Request<Body>, dir: &Path) -> RequestOrResponse {
    match req.method().as_str() {
        "CONNECT" => req.into(),
        "HEAD" | "GET" => {
            let mut path = dir.to_owned();
            let url = crate::process_uri(req.uri());
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
                let (mut tx, rx) = mpsc::channel::<Result<hyper::body::Bytes, hudsucker::Error>>(1);
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
    }
}
