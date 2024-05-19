use std::{collections::HashMap, fmt::Display, net::SocketAddr, path::Path};

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
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet};
use tokio::net::TcpListener;
use tracing::{error, info, level_filters::LevelFilter, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const PATH_PERCENT_ENCODE_SET: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'/');

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

fn normalize_path(path: impl AsRef<str>) -> String {
    path.as_ref()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>()
        .join("/")
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
    let scheme_raw = scheme;
    let map = match path_parts.next() {
        Some(map) => map,
        None => return error_rp(StatusCode::BAD_REQUEST, &[], "missing map"),
    };
    let map_raw = map;
    let path = path_parts.next().unwrap_or("");
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
        Err(e) => {
            return error_rp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &[],
                format!("failed to create operator: {}", e),
            );
        }
    };
    trace!(?operator);

    let normalized = normalize_path(&path);
    let metadata = match operator.stat(&normalized).await {
        Ok(metadata) => metadata,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => return error_rp(StatusCode::NOT_FOUND, &[], e),
            ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
            _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
        },
    };
    match metadata.mode() {
        EntryMode::FILE => {
            if path != normalized {
                return error_rp(
                    StatusCode::PERMANENT_REDIRECT,
                    &[(
                        header::LOCATION,
                        &format!(
                            "/{scheme_raw}/{map_raw}/{}",
                            utf8_percent_encode(&normalized, PATH_PERCENT_ENCODE_SET),
                        ),
                    )],
                    "path is normalized",
                );
            }
            let buf = match operator.read(&normalized).await {
                Ok(buf) => buf,
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
                    _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
                },
            };
            Ok(Response::new(Full::new(buf.to_bytes())))
        }
        EntryMode::DIR => {
            let normalized = format!("{normalized}/");
            if normalized != "/" && path != normalized {
                return error_rp(
                    StatusCode::PERMANENT_REDIRECT,
                    &[(
                        header::LOCATION,
                        &format!(
                            "/{scheme_raw}/{map_raw}/{}",
                            utf8_percent_encode(&normalized, PATH_PERCENT_ENCODE_SET),
                        ),
                    )],
                    "path is normalized",
                );
            }
            if normalized == "/" && path != "" {
                return error_rp(
                    StatusCode::PERMANENT_REDIRECT,
                    &[(header::LOCATION, &format!("/{scheme_raw}/{map_raw}/"))],
                    "path is normalized",
                );
            }
            let entries = match operator.list_with(&normalized).recursive(false).await {
                Ok(entries) => entries,
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => return error_rp(StatusCode::FORBIDDEN, &[], e),
                    _ => return error_rp(StatusCode::INTERNAL_SERVER_ERROR, &[], e),
                },
            };
            let entries = match entries
                .into_iter()
                .map(|entry| -> Option<String> {
                    let entry_path = entry.path();
                    let mode = entry.metadata().mode();
                    trace!(entry = entry_path, base = &normalized);
                    let (href, special) = if normalized == "/" {
                        if mode == EntryMode::Unknown {
                            (entry_path.to_string(), true)
                        } else {
                            (entry_path.to_string(), false)
                        }
                    } else {
                        let stripped = Path::new(entry_path)
                            .strip_prefix(&normalized)
                            .ok()?
                            .to_str()
                            .expect("path is invalid utf-8");
                        match mode {
                            EntryMode::FILE => (stripped.to_string(), false),
                            EntryMode::DIR => (format!("{stripped}/"), false),
                            EntryMode::Unknown => (stripped.to_string(), true),
                        }
                    };
                    trace!(href, special);
                    Some(format!(
                        "<li><a href=\"{href}\">{href}</a>{}</li>",
                        if special { " (*)" } else { "" }
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
            info!(status = %StatusCode::OK);
            Ok(Response::new(Full::new(Bytes::from(formatdoc! {"
                <!DOCTYPE html>
                <html>
                    <head>
                    </head>
                    <body>
                        <h1>Contents of {normalized}</h1>
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
