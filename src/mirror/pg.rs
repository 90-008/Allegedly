use super::*;

#[derive(Clone)]
struct State {
    client: Client,
    plc: Url,
    upstream: Url,
    sync_info: Option<SyncInfo>,
    experimental: ExperimentalConf,
}

/// server info that only applies in mirror (synchronizing) mode
#[derive(Clone)]
struct SyncInfo {
    latest_at: CachedValue<Dt, GetLatestAt>,
    upstream_status: CachedValue<PlcStatus, CheckUpstream>,
}

#[derive(Clone)]
struct GetLatestAt(Db);
impl Fetcher<Dt> for GetLatestAt {
    async fn fetch(&self) -> Result<Dt, Box<dyn std::error::Error>> {
        let now = self.0.get_latest().await?.ok_or(anyhow::anyhow!(
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
fn hello(
    Data(State {
        sync_info,
        upstream,
        experimental: exp,
        ..
    }): Data<&State>,
    req: &Request,
) -> String {
    let pre_info = if sync_info.is_some() {
        format!(
            r#"
This is a PLC[1] mirror running Allegedly in mirror mode. Mirror mode wraps and
synchronizes a local PLC reference server instance[2] (why?[3]).


Configured upstream:

    {upstream}

"#
        )
    } else {
        format!(
            r#"
This is a PLC[1] mirror running Allegedly in wrap mode. Wrap mode reverse-
proxies requests to a PLC server and can terminate TLS, like NGINX or Caddy.


Configured upstream (only used if experimental op forwarding is enabled):

    {upstream}

"#
        )
    };

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
{pre_info}

Available APIs:

    - GET  /_health  Health and version info

    - GET  /*        Proxies to wrapped server; see PLC API docs:
                     https://web.plc.directory/api/redoc

                     tip: try `GET /{{did}}` to resolve an identity

{post_info}


Allegedly is a suite of open-source CLI tools from for working with PLC logs,
from microcosm:

    https://tangled.org/@microcosm.blue/Allegedly

    https://microcosm.blue


[1] https://web.plc.directory
[2] https://github.com/did-method-plc/did-method-plc
[3] https://updates.microcosm.blue/3lz7nwvh4zc2u
"#,
        logo("mirror")
    )
}

#[handler]
async fn health(
    Data(State {
        plc,
        client,
        sync_info,
        ..
    }): Data<&State>,
) -> impl IntoResponse {
    let mut overall_status = StatusCode::OK;
    let (ok, wrapped_status) = plc_status(plc, client).await;
    if !ok {
        overall_status = StatusCode::BAD_GATEWAY;
    }

    if let Some(SyncInfo {
        latest_at,
        upstream_status,
    }) = sync_info
    {
        let (ok, upstream_status) = upstream_status.get().await.expect("plc_status infallible");
        if !ok {
            overall_status = StatusCode::BAD_GATEWAY;
        }
        let latest = latest_at.get().await.ok();
        (
            overall_status,
            Json(serde_json::json!({
                "server": "allegedly (mirror)",
                "version": env!("CARGO_PKG_VERSION"),
                "wrapped_plc": wrapped_status,
                "upstream_plc": upstream_status,
                "latest_at": latest,
            })),
        )
    } else {
        (
            overall_status,
            Json(serde_json::json!({
                "server": "allegedly (mirror)",
                "version": env!("CARGO_PKG_VERSION"),
                "wrapped_plc": wrapped_status,
            })),
        )
    }
}

#[handler]
async fn proxy(req: &Request, Data(state): Data<&State>) -> Result<Response> {
    let mut target = state.plc.clone();
    target.set_path(req.uri().path());
    target.set_query(req.uri().query());
    let wrapped_res = state
        .client
        .get(target)
        .timeout(Duration::from_secs(3))
        .headers(req.headers().clone())
        .send()
        .await
        .map_err(|e| {
            log::error!("upstream req fail: {e}");
            Error::from_string(
                failed_to_reach_named("wrapped reference PLC"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    Ok(proxy_response(wrapped_res))
}

#[handler]
async fn forward_create_op_upstream(
    Data(State {
        upstream,
        client,
        experimental,
        ..
    }): Data<&State>,
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

#[handler]
async fn nope(Data(State { upstream, .. }): Data<&State>) -> (StatusCode, String) {
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

pub async fn serve(
    upstream: Url,
    plc: Url,
    listen: ListenConf,
    experimental: ExperimentalConf,
    db: Option<Db>,
) -> anyhow::Result<&'static str> {
    log::info!("starting server...");

    let client = Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client to build");

    // when `db` is None, we're running in wrap mode. no db access, no upstream sync
    let sync_info = db.map(|db| SyncInfo {
        latest_at: CachedValue::new(GetLatestAt(db), Duration::from_secs(2)),
        upstream_status: CachedValue::new(
            CheckUpstream(upstream.clone(), client.clone()),
            Duration::from_secs(6),
        ),
    });

    let state = State {
        client,
        plc,
        upstream: upstream.clone(),
        sync_info,
        experimental: experimental.clone(),
    };

    let mut app = Route::new()
        .at("/", get(hello))
        .at("/favicon.ico", get(favicon))
        .at("/_health", get(health))
        .at("/export", get(proxy));

    if experimental.write_upstream {
        log::info!("enabling experimental write forwarding to upstream");

        let ip_limiter = IpLimiters::new(Quota::per_hour(10.try_into().unwrap()));
        let did_limiter = CreatePlcOpLimiter::new(Quota::per_hour(4.try_into().unwrap()));

        let upstream_proxier = forward_create_op_upstream
            .with(GovernorMiddleware::new(did_limiter))
            .with(GovernorMiddleware::new(ip_limiter));

        app = app.at("/did:plc:*", get(proxy).post(upstream_proxier));
    } else {
        app = app.at("/did:plc:*", get(proxy).post(nope));
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
