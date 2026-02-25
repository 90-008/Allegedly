use allegedly::{
    Db, Dt, ExportPage, FjallDb, FolderSource, HttpSource, backfill, backfill_to_fjall,
    backfill_to_pg,
    bin::{GlobalArgs, bin_init},
    full_pages, logo, pages_to_fjall, pages_to_pg, pages_to_stdout, poll_upstream,
};
use clap::Parser;
use reqwest::Url;
use std::{path::PathBuf, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

pub const DEFAULT_HTTP: &str = "https://plc.t3.storage.dev/plc.directory/";

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Remote URL prefix to fetch bundles from
    #[arg(long)]
    #[clap(default_value = DEFAULT_HTTP)]
    http: Url,
    /// Local folder to fetch bundles from (overrides `http`)
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Local fjall database to fetch raw ops from (overrides `http` and `dir`)
    #[arg(long, conflicts_with_all = ["dir"])]
    from_fjall: Option<PathBuf>,
    /// Don't do weekly bulk-loading at all.
    ///
    /// overrides `http` and `dir`, makes catch_up redundant
    #[arg(long, action)]
    no_bulk: bool,
    /// Parallel bundle fetchers
    ///
    /// Default: 4 for http fetches, 1 for local folder
    #[arg(long)]
    source_workers: Option<usize>,
    /// Bulk load into did-method-plc-compatible postgres instead of stdout
    ///
    /// Pass a postgres connection url like "postgresql://localhost:5432"
    #[arg(long, env = "ALLEGEDLY_TO_POSTGRES")]
    to_postgres: Option<Url>,
    /// Cert for postgres (if needed)
    #[arg(long)]
    postgres_cert: Option<PathBuf>,
    /// Delete all operations from the postgres db before starting
    ///
    /// only used if `--to-postgres` is present
    #[arg(long, action)]
    postgres_reset: bool,
    /// Bulk load into a local fjall embedded database
    ///
    /// Pass a directory path for the fjall database
    #[arg(long, conflicts_with_all = ["to_postgres", "postgres_cert", "postgres_reset"])]
    to_fjall: Option<PathBuf>,
    /// Delete all operations from the fjall db before starting
    ///
    /// only used if `--to-fjall` is present
    #[arg(long, action, requires = "to_fjall")]
    fjall_reset: bool,
    /// Stop at the week ending before this date
    #[arg(long)]
    until: Option<Dt>,
    /// After the weekly imports, poll upstream until we're caught up
    #[arg(long, action)]
    catch_up: bool,
}

pub async fn run(
    GlobalArgs {
        upstream,
        upstream_throttle_ms,
    }: GlobalArgs,
    Args {
        http,
        dir,
        from_fjall,
        no_bulk,
        source_workers,
        to_postgres,
        postgres_cert,
        postgres_reset,
        to_fjall,
        fjall_reset,
        until,
        catch_up,
    }: Args,
) -> anyhow::Result<()> {
    let mut tasks = JoinSet::<anyhow::Result<&'static str>>::new();

    let (bulk_tx, bulk_out) = mpsc::channel(32); // bulk uses big pages

    // a bulk sink can notify us as soon as the very last op's time is known
    // so we can start catching up while the sink might restore indexes and such
    let (found_last_tx, found_last_out) = if catch_up {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let (poll_tx, poll_out) = mpsc::channel::<ExportPage>(128); // normal/small pages
    let (full_tx, full_out) = mpsc::channel(1); // don't need to buffer at this filter

    // set up sources
    if no_bulk {
        // simple mode, just poll upstream from teh beginning
        if http != DEFAULT_HTTP.parse()? {
            log::warn!("ignoring non-default bulk http setting since --no-bulk was set");
        }
        if let Some(d) = dir {
            log::warn!("ignoring bulk dir setting ({d:?}) since --no-bulk was set.");
        }
        if let Some(u) = until {
            log::warn!(
                "ignoring `until` setting ({u:?}) since --no-bulk was set. (feature request?)"
            );
        }
        let mut upstream = upstream;
        upstream.set_path("/export");
        let throttle = Duration::from_millis(upstream_throttle_ms);
        tasks.spawn(poll_upstream(None, upstream, throttle, poll_tx));
        tasks.spawn(full_pages(poll_out, full_tx));
        if let Some(fjall_path) = to_fjall {
            log::trace!("opening fjall db at {fjall_path:?}...");
            let db = FjallDb::open(&fjall_path)?;
            log::trace!("opened fjall db");

            tasks.spawn(pages_to_fjall(db, full_out));
        } else {
            tasks.spawn(pages_to_stdout(full_out, None));
        }
    } else {
        // fun mode

        // set up bulk sources
        if let Some(fjall_path) = from_fjall {
            log::trace!("opening source fjall db at {fjall_path:?}...");
            let db = FjallDb::open(&fjall_path)?;
            log::trace!("opened source fjall db");
            tasks.spawn(backfill(db, bulk_tx, source_workers.unwrap_or(4), until));
        } else if let Some(dir) = dir {
            if http != DEFAULT_HTTP.parse()? {
                anyhow::bail!(
                    "non-default bulk http setting can't be used with bulk dir setting ({dir:?})"
                );
            }
            tasks.spawn(backfill(
                FolderSource(dir),
                bulk_tx,
                source_workers.unwrap_or(1),
                until,
            ));
        } else {
            tasks.spawn(backfill(
                HttpSource(http),
                bulk_tx,
                source_workers.unwrap_or(4),
                until,
            ));
        }

        // and the catch-up source...
        if let Some(last) = found_last_out {
            let throttle = Duration::from_millis(upstream_throttle_ms);
            tasks.spawn(async move {
                let mut upstream = upstream;
                upstream.set_path("/export");

                poll_upstream(last.await?, upstream, throttle, poll_tx).await
            });
        }

        // set up sinks
        if let Some(fjall_path) = to_fjall {
            log::trace!("opening fjall db at {fjall_path:?}...");
            let db = FjallDb::open(&fjall_path)?;
            log::trace!("opened fjall db");

            tasks.spawn(backfill_to_fjall(
                db.clone(),
                fjall_reset,
                bulk_out,
                found_last_tx,
            ));
            if catch_up {
                tasks.spawn(pages_to_fjall(db, full_out));
            }
        } else if let Some(pg_url) = to_postgres {
            log::trace!("connecting to postgres...");
            let db = Db::new(pg_url.as_str(), postgres_cert).await?;
            log::trace!("connected to postgres");

            tasks.spawn(backfill_to_pg(
                db.clone(),
                postgres_reset,
                bulk_out,
                found_last_tx,
            ));
            if catch_up {
                tasks.spawn(pages_to_pg(db, full_out));
            }
        } else {
            tasks.spawn(pages_to_stdout(bulk_out, found_last_tx));
            if catch_up {
                tasks.spawn(pages_to_stdout(full_out, None));
            }
        }
    }

    while let Some(next) = tasks.join_next().await {
        match next {
            Err(e) if e.is_panic() => {
                log::error!("a joinset task panicked: {e}. bailing now. (should we panic?)");
                return Err(e.into());
            }
            Err(e) => {
                log::error!("a joinset task failed to join: {e}");
                return Err(e.into());
            }
            Ok(Err(e)) => {
                log::error!("a joinset task completed with error: {e}");
                return Err(e);
            }
            Ok(Ok(name)) => {
                log::trace!("a task completed: {name:?}. {} left", tasks.len());
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
    args: Args,
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    bin_init(false);
    log::info!("{}", logo("backfill"));
    run(args.globals, args.args).await?;
    Ok(())
}
