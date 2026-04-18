use allegedly::{
    FjallDb, audit_fjall,
    bin::{GlobalArgs, InstrumentationArgs, bin_init},
    file_to_invalid_ops, fix_ops_fjall, invalid_ops_to_stdout, logo,
};
use clap::Parser;
use std::path::PathBuf;
use tokio::task::JoinSet;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// path to a local fjall database directory
    #[arg(long, env = "ALLEGEDLY_FJALL")]
    fjall: Option<PathBuf>,
    /// path to a file containing invalid ops to fix using upstream
    #[arg(long, env = "ALLEGEDLY_FIX")]
    fix: Option<PathBuf>,
    /// drop invalid ops instead of trying to fix them from upstream
    #[arg(long, env = "ALLEGEDLY_DROP")]
    drop: bool,
}

pub async fn run(globals: GlobalArgs, Args { fjall, fix, drop }: Args) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();

    if let Some(fjall) = fjall {
        let (invalid_ops_tx, invalid_ops_rx) = tokio::sync::mpsc::channel(128);
        let db = FjallDb::open(&fjall)?;

        if let Some(fix) = fix {
            tasks.spawn(file_to_invalid_ops(fix, invalid_ops_tx));
            tasks.spawn(fix_ops_fjall(db, globals.upstream, drop, invalid_ops_rx));
        } else {
            tasks.spawn(audit_fjall(db, invalid_ops_tx));
            tasks.spawn(invalid_ops_to_stdout(invalid_ops_rx));
        }
    } else {
        anyhow::bail!("no audit target provided");
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
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    bin_init(args.instrumentation.enable_opentelemetry);
    tracing::info!("{}", logo("audit"));
    run(args.globals, args.args).await?;
    Ok(())
}
