use super::*;
use futures::StreamExt;
use poem::web::Query;
use serde::Deserialize;

#[derive(Clone)]
struct FjallState {
    client: Client,
    upstream: Url,
    fjall: FjallDb,
    sync_info: FjallSyncInfo,
    experimental: ExperimentalConf,
}

#[derive(Clone)]
struct FjallSyncInfo {
    latest_at: CachedValue<Dt, GetFjallLatestAt>,
    upstream_status: CachedValue<PlcStatus, CheckUpstream>,
}

#[derive(Clone)]
struct GetFjallLatestAt(FjallDb);
impl Fetcher<Dt> for GetFjallLatestAt {
    async fn fetch(&self) -> Result<Dt, Box<dyn std::error::Error>> {
        let db = self.0.clone();
        let now = tokio::task::spawn_blocking(move || db.get_latest())
            .await??
            .ok_or(anyhow::anyhow!(
                "expected to find at least one thing in the db"
            ))?;
        Ok(now)
    }
}

#[derive(Clone)]
struct CheckUpstream(Url, Client);
impl Fetcher<PlcStatus> for CheckUpstream {
    async fn fetch(&self) -> Result<PlcStatus, Box<dyn std::error::Error>> {
        Ok(plc_status(&self.0, &self.1).await)
    }
}

#[handler]
fn fjall_hello(
    Data(FjallState {
        upstream,
        experimental: exp,
        ..
    }): Data<&FjallState>,
    req: &Request,
) -> String {
    let post_info = match (exp.write_upstream, &exp.acme_domain, req.uri().host()) {
        (false, _, _) => "    - POST /*        Always rejected. This is a mirror.".to_string(),
        (_, None, _) => {
            "    - POST /:did     Create a PLC op. Allegedly will forward it upstream.".to_string()
        }
        (_, Some(d), Some(f)) if f == d => {
            "    - POST /:did     Create a PLC op. Allegedly will forward it upstream.".to_string()
        }
        (_, Some(d), _) => format!(
            r#"    - POST /*        Rejected, but experimental upstream op forwarding is
                     available at `POST https://{d}/:did`!"#
        ),
    };

    format!(
        r#"{}

This is a PLC[1] mirror running Allegedly in fjall mirror mode. The PLC API
is served from a the local database, which is mirrored from the upstream PLC
server.


Configured upstream:

    {upstream}


Available APIs:

    - GET  /_health  Health and version info

    - GET  /did:plc:{{did}}              Resolve a DID document
    - GET  /did:plc:{{did}}/log          Operation log
    - GET  /did:plc:{{did}}/log/audit    Full audit log (including nullified ops)
    - GET  /did:plc:{{did}}/log/last     Last operation
    - GET  /did:plc:{{did}}/data         Parsed document data

{post_info}


Allegedly is a suite of open-source CLI tools for working with PLC logs,
from microcosm:

    https://tangled.org/@microcosm.blue/Allegedly

    https://microcosm.blue


[1] https://web.plc.directory
[2] https://github.com/did-method-plc/did-method-plc
"#,
        logo("mirror (fjall)")
    )
}

#[handler]
async fn fjall_health(Data(FjallState { sync_info, .. }): Data<&FjallState>) -> impl IntoResponse {
    let mut overall_status = StatusCode::OK;

    let (ok, upstream_status) = sync_info
        .upstream_status
        .get()
        .await
        .expect("plc_status infallible");
    if !ok {
        overall_status = StatusCode::BAD_GATEWAY;
    }
    let latest = sync_info.latest_at.get().await.ok();

    (
        overall_status,
        Json(serde_json::json!({
            "server": "allegedly (mirror/fjall)",
            "version": env!("CARGO_PKG_VERSION"),
            "upstream_plc": upstream_status,
            "latest_at": latest,
        })),
    )
}

#[handler]
async fn fjall_resolve(req: &Request, Data(state): Data<&FjallState>) -> Result<Response> {
    let path = req.uri().path();
    let did_and_rest = path.strip_prefix("/").unwrap_or(path);

    let (did, sub_path) = match did_and_rest.find('/') {
        Some(i) => (&did_and_rest[..i], &did_and_rest[i..]),
        None => (did_and_rest, ""),
    };

    if !did.starts_with("did:plc:") {
        return Err(Error::from_string("invalid DID", StatusCode::BAD_REQUEST));
    }

    let did = did.to_string();
    let db = state.fjall.clone();
    let ops = tokio::task::spawn_blocking(move || {
        let iter = db.ops_for_did(&did)?;
        iter.collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
    .map_err(|e| Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    if ops.is_empty() {
        return Err(Error::from_string(
            format!(
                "DID not registered: {}",
                did_and_rest.split('/').next().unwrap_or(did_and_rest)
            ),
            StatusCode::NOT_FOUND,
        ));
    }

    let did_str = &ops[0].did;

    match sub_path {
        "" => {
            let data = doc::apply_op_log(
                did_str,
                ops.iter()
                    .filter(|op| !op.nullified)
                    .map(|op| &op.operation),
            );
            let Some(data) = data else {
                return Err(Error::from_string(
                    format!("DID not available: {did_str}"),
                    StatusCode::NOT_FOUND,
                ));
            };
            let doc = doc::format_did_doc(&data);
            Ok(Response::builder()
                .content_type("application/did+ld+json")
                .body(serde_json::to_string(&doc).unwrap()))
        }
        "/log" => {
            let log: Vec<&serde_json::Value> = ops
                .iter()
                .filter(|op| !op.nullified)
                .map(|op| &op.operation)
                .collect();
            Ok(Response::builder()
                .content_type("application/json")
                .body(serde_json::to_string(&log).unwrap()))
        }
        "/log/audit" => {
            let audit: Vec<serde_json::Value> = ops
                .iter()
                .map(|op| {
                    serde_json::json!({
                        "did": op.did,
                        "operation": op.operation,
                        "cid": op.cid,
                        "nullified": op.nullified,
                        "createdAt": op.created_at.to_rfc3339(),
                    })
                })
                .collect();
            Ok(Response::builder()
                .content_type("application/json")
                .body(serde_json::to_string(&audit).unwrap()))
        }
        "/log/last" => {
            let last = ops
                .iter()
                .filter(|op| !op.nullified)
                .last()
                .map(|op| &op.operation);
            let Some(last) = last else {
                return Err(Error::from_string(
                    format!("DID not available: {did_str}"),
                    StatusCode::NOT_FOUND,
                ));
            };
            Ok(Response::builder()
                .content_type("application/json")
                .body(serde_json::to_string(&last).unwrap()))
        }
        "/data" => {
            let data = doc::apply_op_log(
                did_str,
                ops.iter()
                    .filter(|op| !op.nullified)
                    .map(|op| &op.operation),
            );
            let Some(data) = data else {
                return Err(Error::from_string(
                    format!("DID not available: {did_str}"),
                    StatusCode::NOT_FOUND,
                ));
            };
            Ok(Response::builder()
                .content_type("application/json")
                .body(serde_json::to_string(&data).unwrap()))
        }
        _ => Err(Error::from_string("not found", StatusCode::NOT_FOUND)),
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    after: Option<String>,
    #[allow(dead_code)] // we just cap at 1000 for now, matching reference impl
    count: Option<usize>,
}

#[handler]
async fn fjall_export(
    _req: &Request,
    Query(query): Query<ExportQuery>,
    Data(FjallState { fjall, .. }): Data<&FjallState>,
) -> Result<Body> {
    let after = if let Some(a) = query.after {
        Some(
            chrono::DateTime::parse_from_rfc3339(&a)
                .map_err(|e| Error::from_string(e.to_string(), StatusCode::BAD_REQUEST))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let limit = 1000;
    let db = fjall.clone();

    let ops = tokio::task::spawn_blocking(move || {
        let iter = db.export_ops(after, limit)?;
        iter.collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
    .map_err(|e| Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    let stream = futures::stream::iter(ops).map(|op| {
        let mut json = serde_json::to_string(&op).unwrap();
        json.push('\n');
        Ok::<_, std::io::Error>(json)
    });

    Ok(Body::from_bytes_stream(stream))
}

#[handler]
async fn fjall_nope(Data(FjallState { upstream, .. }): Data<&FjallState>) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!(
            r#"{}

Sorry, this server does not accept POST requests.

You may wish to try sending that to our upstream: {upstream}.

If you operate this server, try running with `--experimental-write-upstream`.
"#,
            logo("mirror (nope)")
        ),
    )
}

pub async fn serve_fjall(
    upstream: Url,
    listen: ListenConf,
    experimental: ExperimentalConf,
    fjall: FjallDb,
) -> anyhow::Result<&'static str> {
    log::info!("starting fjall mirror server...");

    let client = Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client to build");

    let sync_info = FjallSyncInfo {
        latest_at: CachedValue::new(GetFjallLatestAt(fjall.clone()), Duration::from_secs(2)),
        upstream_status: CachedValue::new(
            CheckUpstream(upstream.clone(), client.clone()),
            Duration::from_secs(6),
        ),
    };

    let state = FjallState {
        client,
        upstream,
        fjall,
        sync_info,
        experimental: experimental.clone(),
    };

    let mut app = Route::new()
        .at("/", get(fjall_hello))
        .at("/favicon.ico", get(favicon))
        .at("/_health", get(fjall_health))
        .at("/export", get(fjall_export));

    if experimental.write_upstream {
        log::info!("enabling experimental write forwarding to upstream");

        let ip_limiter = IpLimiters::new(Quota::per_hour(10.try_into().unwrap()));
        let did_limiter = CreatePlcOpLimiter::new(Quota::per_hour(4.try_into().unwrap()));

        let upstream_proxier = fjall_forward_create_op_upstream
            .with(GovernorMiddleware::new(did_limiter))
            .with(GovernorMiddleware::new(ip_limiter));

        app = app.at("/did:plc:*", get(fjall_resolve).post(upstream_proxier));
    } else {
        app = app.at("/did:plc:*", get(fjall_resolve).post(fjall_nope));
    }

    let app = app
        .with(AddData::new(state))
        .with(Cors::new().allow_credentials(false))
        .with(Compression::new())
        .with(GovernorMiddleware::new(IpLimiters::new(Quota::per_minute(
            3000.try_into().expect("ratelimit middleware to build"),
        ))))
        .with(CatchPanic::new())
        .with(Tracing);

    bind_or_acme(app, listen).await
}

#[handler]
async fn fjall_forward_create_op_upstream(
    Data(FjallState {
        upstream,
        client,
        experimental,
        ..
    }): Data<&FjallState>,
    Path(did): Path<String>,
    req: &Request,
    body: Body,
) -> Result<Response> {
    if let Some(expected_domain) = &experimental.acme_domain {
        let Some(found_host) = req.uri().host() else {
            return Ok(bad_create_op(&format!(
                "missing `Host` header, expected {expected_domain:?} for experimental requests."
            )));
        };
        if found_host != expected_domain {
            return Ok(bad_create_op(&format!(
                "experimental requests must be made to {expected_domain:?}, but this request's `Host` header was {found_host}"
            )));
        }
    }

    let mut headers: reqwest::header::HeaderMap = req.headers().clone();
    log::trace!("original request headers: {headers:?}");
    headers.insert("Host", upstream.host_str().unwrap().parse().unwrap());
    let client_ua = headers
        .get(USER_AGENT)
        .map(|h| h.to_str().unwrap())
        .unwrap_or("unknown");
    headers.insert(
        USER_AGENT,
        format!("{UA} (forwarding from {client_ua:?})")
            .parse()
            .unwrap(),
    );
    log::trace!("adjusted request headers: {headers:?}");

    let mut target = upstream.clone();
    target.set_path(&did);
    let upstream_res = client
        .post(target)
        .timeout(Duration::from_secs(15))
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_bytes_stream()))
        .send()
        .await
        .map_err(|e| {
            log::warn!("upstream write fail: {e}");
            Error::from_string(
                failed_to_reach_named("upstream PLC"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    Ok(proxy_response(upstream_res))
}
