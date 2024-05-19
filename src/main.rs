use std::{
    collections::HashMap,
    fmt::Display,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use eyre::Result;
use http_body_util::Full;
use hyper::{
    body::Bytes,
    header::{self, HeaderName},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use indoc::formatdoc;
use opendal::{EntryMode, ErrorKind, Operator, Scheme};
use percent_encoding::percent_decode_str;
use tokio::net::TcpListener;
use tracing::{debug, error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn error_rp(
    status: StatusCode,
    headers: &[(HeaderName, &str)],
    message: impl Display,
) -> Result<Response<Full<Bytes>>> {
    info!(%status);
    let mut builder = Response::builder().status(status);
    for header in headers {
        builder = builder.header(&header.0, header.1);
    }
    Ok(builder.body(Full::new(Bytes::from(formatdoc! {"
            <!DOCTYPE html>
            <html>
                <head>
                </head>
                <body>
                    <h1>{status}</h1>
                    <h1>{message}</h1>
                </body>
            </html>
        "})))?)
}

async fn serve(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
    let method = req.method();
    trace!(%method);
    if method != Method::GET {
        return error_rp(
            StatusCode::METHOD_NOT_ALLOWED,
            &[(header::ALLOW, "get")],
            "",
        );
    }

    // split scheme, map & file path from path
    let path = req.uri().path();
    trace!(path);
    let mut path_parts = path.splitn(4, '/').skip(1);
    let scheme = match path_parts.next() {
        Some(scheme) => scheme,
        None => return error_rp(StatusCode::BAD_REQUEST, &[], "missing scheme"),
    };
    let map = match path_parts.next() {
        Some(map) => map,
        None => return error_rp(StatusCode::BAD_REQUEST, &[], "missing map"),
    };
    let path = path_parts.next().unwrap_or(".");
    trace!(?scheme, ?map, ?path);

    // url decode & parse
    let scheme: Scheme = match scheme
        .parse()
        .ok()
        .filter(|scheme| Scheme::enabled().contains(scheme))
    {
        Some(scheme) => scheme,
        None => return error_rp(StatusCode::BAD_REQUEST, &[], "unsupported scheme"),
    };
    let map: HashMap<String, String> = form_urlencoded::parse(map.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let path = match percent_decode_str(path).decode_utf8() {
        Ok(path) => path,
        Err(_e) => return error_rp(StatusCode::BAD_REQUEST, &[], "invalid path"),
    };
    trace!(?scheme, ?map, ?path);

    let operator = match Operator::via_map(scheme, map) {
        Ok(operator) => operator,
        Err(_e) => {
            return error_rp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &[],
                "failed to create operator",
            );
        }
    };
    trace!(?operator);

    let metadata = match operator.stat(&path).await {
        Ok(metadata) => metadata,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => return error_rp(StatusCode::NOT_FOUND, &[], e),
            ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
            _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
        },
    };
    match metadata.mode() {
        EntryMode::FILE => {
            let buf = match operator.read(&path).await {
                Ok(buf) => buf,
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
                    _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
                },
            };
            Ok(Response::new(Full::new(buf.to_bytes())))
        }
        EntryMode::DIR => {
            let path = format!("{path}/");
            let entries = match operator.list_with(&path).recursive(false).await {
                Ok(entries) => entries,
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
                    _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
                },
            };
            let entries = match entries
                .into_iter()
                .map(|entry| -> Option<String> {
                    let entry = entry.path();
                    trace!(entry = entry, base = &path);
                    let relative_path = Path::new(entry)
                        .strip_prefix(&path)
                        .ok()?
                        .to_str()
                        .expect("path is invalid utf-8");
                    trace!(relative_path);
                    Some(format!(
                        "<li><a href=\"{relative_path}\">{relative_path}</a></li>"
                    ))
                })
                .collect::<Option<Vec<String>>>()
            {
                Some(entries) => entries.join("\n"),
                None => {
                    return error_rp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &[],
                        "directory contains invalid path",
                    )
                }
            };
            Ok(Response::new(Full::new(Bytes::from(formatdoc! {"
                <!DOCTYPE html>
                <html>
                    <head>
                    </head>
                    <body>
                        <h1>Contents of {path}</h1>
                        <ul>
                {entries}
                        </ul>
                    </body>
                </html>
            "}))))
        }
        EntryMode::Unknown => error_rp(
            StatusCode::INTERNAL_SERVER_ERROR,
            &[],
            "path is neither file nor directory",
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(if cfg!(debug_assertions) {
                    LevelFilter::TRACE.into()
                } else {
                    LevelFilter::INFO.into()
                })
                .from_env_lossy(),
        )
        .init();
    let listen_addr: SocketAddr = "127.0.0.1:3000".parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!(%listen_addr);
    loop {
        let (stream, client_addr) = listener.accept().await?;
        info!(%client_addr);
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(serve))
                .await
            {
                error!("error serving connection: {err:?}");
            }
        });
    }
}
