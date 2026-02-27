use allegedly::{
    FjallDb, audit_fjall,
    bin::{InstrumentationArgs, bin_init},
    drop_invalid_ops_fjall, file_to_invalid_ops, invalid_ops_to_stdout, logo,
};
use clap::Parser;
use std::path::PathBuf;
use tokio::task::JoinSet;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// path to a local fjall database directory
    #[arg(long, env = "ALLEGEDLY_FJALL")]
    fjall: Option<PathBuf>,
    /// path to a file containing invalid ops to fix
    #[arg(long, env = "ALLEGEDLY_FIX")]
    fix: Option<PathBuf>,
}

pub async fn run(Args { fjall, fix }: Args) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();

    if let Some(fjall) = fjall {
        let (invalid_ops_tx, invalid_ops_rx) = tokio::sync::mpsc::channel(128);
        let db = FjallDb::open(&fjall)?;

        if let Some(fix) = fix {
            tasks.spawn(file_to_invalid_ops(fix, invalid_ops_tx));
            tasks.spawn(drop_invalid_ops_fjall(db, invalid_ops_rx));
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
    instrumentation: InstrumentationArgs,
    #[command(flatten)]
    args: Args,
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    bin_init(args.instrumentation.enable_opentelemetry);
    log::info!("{}", logo("audit"));
    run(args.args).await?;
    Ok(())
}
