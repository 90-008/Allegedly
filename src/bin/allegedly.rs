use allegedly::bin::{GlobalArgs, InstrumentationArgs, bin_init};
use allegedly::{Dt, logo, pages_to_stdout, pages_to_weeks, poll_upstream};
use clap::{CommandFactory, Parser, Subcommand};
use std::{path::PathBuf, time::Duration, time::Instant};
use tokio::fs::create_dir_all;
use tokio::sync::mpsc;

mod backfill;
mod mirror;

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    globals: GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Use weekly bundled ops to get a complete directory mirror FAST
    Backfill {
        #[command(flatten)]
        args: backfill::Args,
    },
    /// Scrape a PLC server, collecting ops into weekly bundles
    ///
    /// Bundles are gzipped files named `<WEEK>.jsonl.gz` where WEEK is a unix
    /// timestamp rounded down to a multiple of 604,800 (one week in seconds).
    ///
    /// Will stop by default at floor((now - 73hrs) / one week) * one week. PLC
    /// operations can be invalidated within 72 hrs, so stopping before that
    /// time ensures that the bundles are (hopefully) immutable.
    Bundle {
        /// Where to save the bundled files
        #[arg(short, long)]
        #[clap(default_value = "./weekly/")]
        dest: PathBuf,
        /// Start the export from this time. Should be a week boundary.
        #[arg(short, long)]
        #[clap(default_value = "2022-11-17T00:00:00Z")]
        after: Dt,
        /// Overwrite existing files, if present
        #[arg(long, action)]
        clobber: bool,
    },
    /// Wrap a did-method-plc server, syncing upstream and blocking op submits
    Mirror {
        #[command(flatten)]
        args: mirror::Args,
        #[command(flatten)]
        instrumentation: InstrumentationArgs,
    },
    /// Wrap any did-method-plc server, without syncing upstream (read-only)
    Wrap {
        #[command(flatten)]
        args: mirror::Args,
        #[command(flatten)]
        instrumentation: InstrumentationArgs,
    },
    /// Poll an upstream PLC server and log new ops to stdout
    Tail {
        /// Begin tailing from a specific timestamp for replay or wait-until
        #[arg(short, long)]
        after: Option<Dt>,
    },
}

impl Commands {
    fn enable_otel(&self) -> bool {
        match self {
            Commands::Mirror {
                instrumentation, ..
            }
            | Commands::Wrap {
                instrumentation, ..
            } => instrumentation.enable_opentelemetry,
            _ => false,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let matches = Cli::command().get_matches();
    let name = matches.subcommand().map(|(name, _)| name).unwrap_or("???");
    bin_init(args.command.enable_otel());
    log::info!("{}", logo(name));

    let globals = args.globals.clone();

    let t0 = Instant::now();
    match args.command {
        Commands::Backfill { args } => backfill::run(globals, args).await?,
        Commands::Bundle {
            dest,
            after,
            clobber,
        } => {
            let mut url = globals.upstream;
            url.set_path("/export");
            let throttle = Duration::from_millis(globals.upstream_throttle_ms);
            let (tx, rx) = mpsc::channel(32); // read ahead if gzip stalls for some reason
            tokio::task::spawn(async move {
                poll_upstream(Some(after), url, throttle, tx)
                    .await
                    .expect("to poll upstream")
            });
            log::trace!("ensuring output directory exists");
            create_dir_all(&dest)
                .await
                .expect("to ensure output dir exists");
            pages_to_weeks(rx, dest, clobber)
                .await
                .expect("to write bundles to output files");
        }
        Commands::Mirror { args, .. } => mirror::run(globals, args, true).await?,
        Commands::Wrap { args, .. } => mirror::run(globals, args, false).await?,
        Commands::Tail { after } => {
            let mut url = globals.upstream;
            url.set_path("/export");
            let start_at = after.or_else(|| Some(chrono::Utc::now()));
            let throttle = Duration::from_millis(globals.upstream_throttle_ms);
            let (tx, rx) = mpsc::channel(1);
            tokio::task::spawn(async move {
                poll_upstream(start_at, url, throttle, tx)
                    .await
                    .expect("to poll upstream")
            });
            pages_to_stdout(rx, None)
                .await
                .expect("to write pages to stdout");
        }
    }
    log::info!("whew, {:?}. goodbye!", t0.elapsed());
    Ok(())
}
