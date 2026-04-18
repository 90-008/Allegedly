use crate::{
    CachedValue, CreatePlcOpLimiter, Db, Dt, Fetcher, FjallDb, GovernorMiddleware, IpLimiters, UA,
    doc, logo,
};
use futures::TryStreamExt;
use governor::Quota;
use poem::{
    Body, Endpoint, EndpointExt, Error, IntoResponse, Request, Response, Result, Route, Server,
    get, handler,
    http::{StatusCode, header::USER_AGENT},
    listener::{Listener, TcpListener, acme::AutoCert},
    middleware::{AddData, CatchPanic, Compression, Cors, Tracing},
    web::{Data, Json, Path},
};
use reqwest::{Client, Url};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

pub mod fjall;
pub mod pg;

pub use fjall::serve_fjall;
pub use pg::serve;

#[derive(Debug)]
pub enum ListenConf {
    Acme {
        domains: Vec<String>,
        cache_path: PathBuf,
        directory_url: String,
        ipv6: bool,
    },
    Bind(SocketAddr),
}

#[derive(Debug, Clone)]
pub struct ExperimentalConf {
    pub acme_domain: Option<String>,
    pub write_upstream: bool,
}

#[handler]
pub fn favicon() -> impl IntoResponse {
    include_bytes!("../../favicon.ico").with_content_type("image/x-icon")
}

pub fn failed_to_reach_named(name: &str) -> String {
    format!(
        r#"{}

Failed to reach the {name} server. Sorry.
"#,
        logo("mirror 502 :( ")
    )
}

pub fn bad_create_op(reason: &str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(format!(
            r#"{}

NooOOOooooo: {reason}
"#,
            logo("mirror 400 >:( ")
        ))
}

pub type PlcStatus = (bool, serde_json::Value);

pub async fn plc_status(url: &Url, client: &Client) -> PlcStatus {
    use serde_json::json;

    let mut url = url.clone();
    url.set_path("/_health");

    let Ok(response) = client.get(url).timeout(Duration::from_secs(3)).send().await else {
        return (false, json!({"error": "cannot reach plc server"}));
    };

    let status = response.status();

    let Ok(text) = response.text().await else {
        return (false, json!({"error": "failed to read response body"}));
    };

    let body = match serde_json::from_str(&text) {
        Ok(json) => json,
        Err(_) => serde_json::Value::String(text.to_string()),
    };

    if status.is_success() {
        (true, body)
    } else {
        (
            false,
            json!({
                "error": "non-ok status",
                "status": status.as_str(),
                "status_code": status.as_u16(),
                "response": body,
            }),
        )
    }
}

pub fn proxy_response(res: reqwest::Response) -> Response {
    let http_res: poem::http::Response<reqwest::Body> = res.into();
    let (parts, reqw_body) = http_res.into_parts();

    let parts = poem::ResponseParts {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
        extensions: parts.extensions,
    };

    let body = http_body_util::BodyDataStream::new(reqw_body)
        .map_err(|e| std::io::Error::other(Box::new(e)));

    Response::from_parts(parts, poem::Body::from_bytes_stream(body))
}

async fn run<A, L>(app: A, listener: L) -> std::io::Result<()>
where
    A: Endpoint + 'static,
    L: Listener + 'static,
{
    Server::new(listener)
        .name("allegedly (mirror)")
        .run(app)
        .await
}

/// kick off a tiny little server on a tokio task to tell people to use 443
async fn run_insecure_notice(ipv6: bool) -> Result<(), std::io::Error> {
    #[handler]
    fn oop_plz_be_secure() -> (StatusCode, String) {
        (
            StatusCode::BAD_REQUEST,
            format!(
                r#"{}

You probably want to change your request to use HTTPS instead of HTTP.
"#,
                logo("mirror (tls on 443 please)")
            ),
        )
    }

    let app = Route::new()
        .at("/favicon.ico", get(favicon))
        .nest("/", get(oop_plz_be_secure))
        .with(Tracing);
    Server::new(TcpListener::bind(if ipv6 {
        "[::]:80"
    } else {
        "0.0.0.0:80"
    }))
    .name("allegedly (mirror:80 helper)")
    .run(app)
    .await
}

pub async fn bind_or_acme<A>(app: A, listen: ListenConf) -> anyhow::Result<&'static str>
where
    A: Endpoint + 'static,
{
    match listen {
        ListenConf::Acme {
            domains,
            cache_path,
            directory_url,
            ipv6,
        } => {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("crypto provider to be installable");

            let mut auto_cert = AutoCert::builder()
                .directory_url(directory_url)
                .cache_path(cache_path);
            for domain in domains {
                auto_cert = auto_cert.domain(domain);
            }
            let auto_cert = auto_cert.build().expect("acme config to build");

            tracing::trace!("auto_cert: {auto_cert:?}");

            let notice_task = tokio::task::spawn(run_insecure_notice(ipv6));
            let listener = TcpListener::bind(if ipv6 { "[::]:443" } else { "0.0.0.0:443" });
            let app_res = run(app, listener.acme(auto_cert)).await;
            tracing::warn!("server task ended, aborting insecure server task...");
            notice_task.abort();
            app_res?;
            notice_task.await??;
        }
        ListenConf::Bind(addr) => run(app, TcpListener::bind(addr)).await?,
    }

    Ok("server (uh oh?)")
}
