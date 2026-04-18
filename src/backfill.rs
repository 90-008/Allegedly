use crate::{BundleSource, Dt, ExportPage, Week, week_to_pages};
use std::sync::Arc;
use std::time::Instant;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};

const FIRST_WEEK: Week = Week::from_n(1668643200);

pub async fn backfill(
    source: impl BundleSource + Send + 'static,
    dest: mpsc::Sender<ExportPage>,
    source_workers: usize,
    until: Option<Dt>,
) -> anyhow::Result<&'static str> {
    // queue up the week bundles that should be available
    let weeks = Arc::new(Mutex::new(
        until
            .map(|u| Week::range(FIRST_WEEK..u.into()))
            .unwrap_or(Week::range(FIRST_WEEK..)),
    ));
    weeks.lock().await.reverse();

    let mut workers: JoinSet<anyhow::Result<()>> = JoinSet::new();

    let t_step = Instant::now();
    tracing::info!(
        "fetching backfill for {} weeks with {source_workers} workers...",
        weeks.lock().await.len()
    );

    // spin up the fetchers to work in parallel
    for w in 0..source_workers {
        let weeks = weeks.clone();
        let dest = dest.clone();
        let source = source.clone();
        workers.spawn(async move {
            while let Some(week) = weeks.lock().await.pop() {
                let when = Into::<Dt>::into(week).to_rfc3339();
                tracing::trace!("worker {w}: fetching week {when} (-{})", week.n_ago());
                week_to_pages(source.clone(), week, dest.clone())
                    .await
                    .inspect_err(|e| tracing::error!("failing week_to_pages: {e}"))?;
            }
            tracing::info!("done with the weeks ig");
            Ok(())
        });
    }

    // TODO: handle missing/failed weeks

    // wait for the big backfill to finish
    while let Some(res) = workers.join_next().await {
        res.inspect_err(|e| tracing::error!("problem joining source workers: {e}"))?
            .inspect_err(|e| tracing::error!("problem *from* source worker: {e}"))?;
    }
    tracing::info!(
        "finished fetching backfill in {:?}. senders remaining: {}",
        t_step.elapsed(),
        dest.strong_count()
    );
    Ok("backfill")
}
