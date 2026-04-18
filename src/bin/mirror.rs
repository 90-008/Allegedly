use allegedly::{
    Db, ExperimentalConf, FjallDb, ListenConf,
    bin::{GlobalArgs, InstrumentationArgs, bin_init},
    logo, pages_to_pg, poll_upstream, poll_upstream_seq, seq_pages_to_fjall, serve, serve_fjall,
    tail_upstream_stream,
};
use clap::Parser;
use reqwest::Url;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{fs::create_dir_all, sync::mpsc, task::JoinSet};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// the wrapped did-method-plc server (not needed when using --wrap-fjall)
    #[arg(long, env = "ALLEGEDLY_WRAP")]
    wrap: Option<Url>,
    /// the wrapped did-method-plc server's database (write access required)
    #[arg(long, env = "ALLEGEDLY_WRAP_PG", conflicts_with = "wrap_fjall")]
    wrap_pg: Option<Url>,
    /// path to tls cert for the wrapped postgres db, if needed
    #[arg(long, env = "ALLEGEDLY_WRAP_PG_CERT")]
    wrap_pg_cert: Option<PathBuf>,
    /// path to a local fjall database directory (alternative to postgres)
    #[arg(long, env = "ALLEGEDLY_WRAP_FJALL", conflicts_with_all = ["wrap_pg", "wrap_pg_cert"])]
    wrap_fjall: Option<PathBuf>,
    /// compact the fjall db on startup
    #[arg(
        long,
        env = "ALLEGEDLY_FJALL_COMPACT",
        conflicts_with_all = ["wrap_pg", "wrap_pg_cert"]
    )]
    compact_fjall: bool,
    /// wrapping server listen address
    #[arg(short, long, env = "ALLEGEDLY_BIND")]
    #[clap(default_value = "127.0.0.1:8000")]
    bind: SocketAddr,
    /// obtain a certificate from letsencrypt
    ///
    /// for now this will force listening on all interfaces at :80 and :443
    /// (:80 will serve an "https required" error, *will not* redirect)
    #[arg(
        long,
        conflicts_with("bind"),
        requires("acme_cache_path"),
        env = "ALLEGEDLY_ACME_DOMAIN"
    )]
    acme_domain: Vec<String>,
    /// which local directory to keep the letsencrypt certs in
    #[arg(long, requires("acme_domain"), env = "ALLEGEDLY_ACME_CACHE_PATH")]
    acme_cache_path: Option<PathBuf>,
    /// which public acme directory to use
    ///
    /// eg. letsencrypt staging: "https://acme-staging-v02.api.letsencrypt.org/directory"
    #[arg(long, requires("acme_domain"), env = "ALLEGEDLY_ACME_DIRECTORY_URL")]
    #[clap(default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    acme_directory_url: Url,
    /// try to listen for ipv6
    #[arg(long, action, requires("acme_domain"), env = "ALLEGEDLY_ACME_IPV6")]
    acme_ipv6: bool,
    /// only accept experimental requests at this hostname
    ///
    /// a cert will be provisioned for it from letsencrypt. if you're not using
    /// acme (eg., behind a tls-terminating reverse proxy), open a feature request.
    #[arg(
        long,
        requires("acme_domain"),
        env = "ALLEGEDLY_EXPERIMENTAL_ACME_DOMAIN"
    )]
    experimental_acme_domain: Option<String>,
    /// accept writes! by forwarding them upstream
    #[arg(long, action, env = "ALLEGEDLY_EXPERIMENTAL_WRITE_UPSTREAM")]
    experimental_write_upstream: bool,
    /// switch from polling to /export/stream once the latest op is within
    /// this many days of now (plc.directory only supports ~1 week of backfill)
    #[arg(long, env = "ALLEGEDLY_STREAM_CUTOVER_DAYS", default_value = "5")]
    stream_cutover_days: u32,
}

pub async fn run(
    GlobalArgs {
        upstream,
        upstream_throttle_ms,
    }: GlobalArgs,
    Args {
        wrap,
        wrap_pg,
        wrap_pg_cert,
        wrap_fjall,
        compact_fjall,
        bind,
        acme_domain,
        acme_cache_path,
        acme_directory_url,
        acme_ipv6,
        experimental_acme_domain,
        experimental_write_upstream,
        stream_cutover_days,
    }: Args,
    sync: bool,
) -> anyhow::Result<()> {
    let listen_conf = match (bind, acme_domain.is_empty(), acme_cache_path) {
        (_, false, Some(cache_path)) => {
            create_dir_all(&cache_path).await?;
            let mut domains = acme_domain.clone();
            if let Some(ref experimental_domain) = experimental_acme_domain {
                domains.push(experimental_domain.clone())
            }
            tracing::info!("configuring acme for https at {domains:?}...");
            ListenConf::Acme {
                domains,
                cache_path,
                directory_url: acme_directory_url.to_string(),
                ipv6: acme_ipv6,
            }
        }
        (bind, true, None) => ListenConf::Bind(bind),
        (_, _, _) => unreachable!(),
    };

    let experimental_conf = ExperimentalConf {
        acme_domain: experimental_acme_domain,
        write_upstream: experimental_write_upstream,
    };

    let mut tasks = JoinSet::new();

    if let Some(fjall_path) = wrap_fjall {
        let db = FjallDb::open(&fjall_path)?;
        if compact_fjall {
            tracing::info!("compacting fjall...");
            db.compact()?;
        }

        tracing::debug!("getting the latest seq from fjall...");
        let latest_seq = db
            .get_latest()?
            .map(|(seq, _)| seq)
            .expect("there to be at least one op in the db. did you backfill?");
        tracing::info!("starting seq polling from seq {latest_seq}...");

        let (send_page, recv_page) = mpsc::channel::<allegedly::SeqPage>(8);

        let mut export_url = upstream.clone();
        export_url.set_path("/export");
        let mut stream_url = upstream.clone();
        stream_url.set_path("/export/stream");
        let throttle = Duration::from_millis(upstream_throttle_ms);
        let cutover_age = Duration::from_secs(stream_cutover_days as u64 * 86_400);

        // the poll -> stream task: poll until we're caught up, then switch to stream.
        // on stream disconnect, fall back to polling to resync.
        let send_page_bg = send_page.clone();
        let db_for_poll = db.clone();
        tasks.spawn(async move {
            let mut current_seq = latest_seq;
            loop {
                tracing::info!("seq polling from seq {current_seq}");
                let (inner_tx, mut inner_rx) = mpsc::channel::<allegedly::SeqPage>(8);

                // run poller; it ends only when the channel closes
                let poll_url = export_url.clone();
                let poll_task = tokio::spawn(poll_upstream_seq(
                    Some(current_seq),
                    poll_url,
                    throttle,
                    inner_tx,
                ));

                // drain pages from poller until the last op is within cutover_age of now,
                // meaning we're close enough to the tip that the stream can cover the rest
                let mut last_seq_from_poll = current_seq;

                while let Some(page) = inner_rx.recv().await {
                    let near_tip = page.ops.last().map_or(false, |op| {
                        let age = chrono::Utc::now().signed_duration_since(op.created_at);
                        age.to_std().map_or(false, |d| d <= cutover_age)
                    });
                    if let Some(last) = page.ops.last() {
                        last_seq_from_poll = last.seq;
                    }
                    if send_page_bg.send(page).await.is_err() {
                        poll_task.abort();
                        return anyhow::Ok("fjall-poll-stream (dest closed)");
                    }
                    if near_tip {
                        break;
                    }
                }

                poll_task.abort();
                current_seq = last_seq_from_poll;

                // switch to streaming
                tracing::info!("caught up at seq {current_seq}, switching to /export/stream");
                let (stream_inner_tx, mut stream_inner_rx) = mpsc::channel::<allegedly::SeqPage>(8);
                let stream_task = tokio::spawn(tail_upstream_stream(
                    Some(current_seq),
                    stream_url.clone(),
                    stream_inner_tx,
                ));

                while let Some(page) = stream_inner_rx.recv().await {
                    if let Some(last) = page.ops.last() {
                        current_seq = last.seq;
                    }
                    if send_page_bg.send(page).await.is_err() {
                        stream_task.abort();
                        return anyhow::Ok("fjall-poll-stream (dest closed)");
                    }
                }

                // stream ended/errored — loop back to polling to resync
                match stream_task.await {
                    Ok(Ok(())) => tracing::info!("stream closed cleanly, resyncing via poll"),
                    Ok(Err(e)) => tracing::warn!("stream error: {e}, resyncing via poll"),
                    Err(e) => tracing::warn!("stream task join error: {e}"),
                }

                // rest current_seq to what's actually in the DB. current_seq tracks
                // pages forwarded to seq_pages_to_fjall, which may be ahead of what
                // was actually stored (ops can be dropped by VERIFY=true). polling
                // from the in-memory current_seq would permanently skip those ops.
                let db = db_for_poll.clone();
                match tokio::task::spawn_blocking(move || db.get_latest()).await {
                    Ok(Ok(Some((seq, _)))) => {
                        if seq < current_seq {
                            tracing::info!(
                                "resetting poll cursor from {current_seq} to db latest {seq} to avoid skipping dropped ops"
                            );
                            current_seq = seq;
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => tracing::warn!("failed to read db latest for poll reset: {e}"),
                    Err(e) => tracing::warn!("spawn_blocking failed for poll reset: {e}"),
                }
            }
        });

        tasks.spawn(seq_pages_to_fjall(db.clone(), recv_page));
        tasks.spawn(serve_fjall(upstream, listen_conf, experimental_conf, db));
    } else {
        let wrap = wrap.ok_or(anyhow::anyhow!(
            "--wrap is required unless using --wrap-fjall"
        ))?;

        let db: Option<Db> = if sync {
            let wrap_pg = wrap_pg.ok_or(anyhow::anyhow!(
                "a wrapped reference postgres (--wrap-pg) or fjall db (--wrap-fjall) must be provided to sync"
            ))?;
            let db = Db::new(wrap_pg.as_str(), wrap_pg_cert).await?;

            tracing::debug!("getting the latest op from the db...");
            let latest = db
                .get_latest()
                .await?
                .expect("there to be at least one op in the db. did you backfill?");
            tracing::debug!("starting polling from {latest}...");

            let (send_page, recv_page) = mpsc::channel(8);

            let mut poll_url = upstream.clone();
            poll_url.set_path("/export");
            let throttle = Duration::from_millis(upstream_throttle_ms);

            tasks.spawn(poll_upstream(Some(latest), poll_url, throttle, send_page));
            tasks.spawn(pages_to_pg(db.clone(), recv_page));
            Some(db)
        } else {
            None
        };

        tasks.spawn(serve(upstream, wrap, listen_conf, experimental_conf, db));
    }

    while let Some(next) = tasks.join_next().await {
        match next {
            Err(e) if e.is_panic() => {
                tracing::error!("a joinset task panicked: {e}. bailing now. (should we panic?)");
                return Err(e.into());
            }
            Err(e) => {
                tracing::error!("a joinset task failed to join: {e}");
                return Err(e.into());
            }
            Ok(Err(e)) => {
                tracing::error!("a joinset task completed with error: {e}");
                return Err(e);
            }
            Ok(Ok(name)) => {
                tracing::trace!("a task completed: {name:?}. {} left", tasks.len());
            }
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
struct CliArgs {
    #[command(flatten)]
    globals: GlobalArgs,
    #[command(flatten)]
    instrumentation: InstrumentationArgs,
    #[command(flatten)]
    args: Args,
    /// Run the mirror in wrap mode, no upstream synchronization (read-only)
    #[arg(long, action)]
    wrap_mode: bool,
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    bin_init(args.instrumentation.enable_opentelemetry);
    tracing::info!("{}", logo("mirror"));
    run(args.globals, args.args, !args.wrap_mode).await?;
    Ok(())
}
