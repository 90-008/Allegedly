use serde::{Deserialize, Serialize};

use tokio::sync::{mpsc, oneshot};

mod backfill;
mod cached_value;
mod client;
pub mod doc;
mod mirror;
mod plc_fjall;
mod plc_pg;
mod poll;
mod ratelimit;
mod weekly;

pub mod bin;

pub use backfill::backfill;
pub use cached_value::{CachedValue, Fetcher};
pub use client::{CLIENT, UA};
pub use mirror::{ExperimentalConf, ListenConf, serve, serve_fjall};
pub use plc_fjall::{FjallDb, backfill_to_fjall, fjall_to_pages, pages_to_fjall};
pub use plc_pg::{Db, backfill_to_pg, pages_to_pg};
pub use poll::{PageBoundaryState, get_page, poll_upstream};
pub use ratelimit::{CreatePlcOpLimiter, GovernorMiddleware, IpLimiters};
pub use weekly::{BundleSource, FolderSource, HttpSource, Week, pages_to_weeks, week_to_pages};

pub type Dt = chrono::DateTime<chrono::Utc>;

/// One page of PLC export
///
/// plc.directory caps /export at 1000 ops; backfill tasks may send more in a page.
#[derive(Debug)]
pub struct ExportPage {
    pub ops: Vec<Op>,
}

impl ExportPage {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// A fully-deserialized plc operation
///
/// including the plc's wrapping with timestmap and nullified state
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Op {
    pub did: String,
    pub cid: String,
    pub created_at: Dt,
    pub nullified: bool,
    pub operation: Box<serde_json::value::RawValue>,
}

#[cfg(test)]
impl PartialEq for Op {
    fn eq(&self, other: &Self) -> bool {
        self.did == other.did
            && self.cid == other.cid
            && self.created_at == other.created_at
            && self.nullified == other.nullified
            && serde_json::from_str::<serde_json::Value>(self.operation.get()).unwrap()
                == serde_json::from_str::<serde_json::Value>(other.operation.get()).unwrap()
    }
}

/// Database primary key for an op
#[derive(Debug, PartialEq)]
pub struct OpKey {
    pub did: String,
    pub cid: String,
}

impl From<&Op> for OpKey {
    fn from(Op { did, cid, .. }: &Op) -> Self {
        Self {
            did: did.to_string(),
            cid: cid.to_string(),
        }
    }
}

/// page forwarder who drops its channels on receipt of a small page
///
/// PLC will return up to 1000 ops on a page, and returns full pages until it
/// has caught up, so this is a (hacky?) way to stop polling once we're up.
pub async fn full_pages(
    mut rx: mpsc::Receiver<ExportPage>,
    tx: mpsc::Sender<ExportPage>,
) -> anyhow::Result<&'static str> {
    while let Some(page) = rx.recv().await {
        let n = page.ops.len();
        if n < 900 {
            let last_age = page.ops.last().map(|op| chrono::Utc::now() - op.created_at);
            let Some(age) = last_age else {
                log::info!("full_pages done, empty final page");
                return Ok("full pages (hmm)");
            };
            if age <= chrono::TimeDelta::hours(6) {
                log::info!("full_pages done, final page of {n} ops");
            } else {
                log::warn!("full_pages finished with small page of {n} ops, but it's {age} old");
            }
            return Ok("full pages (cool)");
        }
        log::trace!("full_pages: continuing with page of {n} ops");
        tx.send(page).await?;
    }
    Err(anyhow::anyhow!(
        "full_pages ran out of source material, sender closed"
    ))
}

pub async fn pages_to_stdout(
    mut rx: mpsc::Receiver<ExportPage>,
    notify_last_at: Option<oneshot::Sender<Option<Dt>>>,
) -> anyhow::Result<&'static str> {
    let mut last_at = None;
    while let Some(page) = rx.recv().await {
        for op in &page.ops {
            println!("{}", serde_json::to_string(op)?);
        }
        if notify_last_at.is_some()
            && let Some(s) = PageBoundaryState::new(&page)
        {
            last_at = last_at.filter(|&l| l >= s.last_at).or(Some(s.last_at));
        }
    }
    if let Some(notify) = notify_last_at {
        log::trace!("notifying last_at: {last_at:?}");
        if notify.send(last_at).is_err() {
            log::error!("receiver for last_at dropped, can't notify");
        };
    }
    Ok("pages_to_stdout")
}

pub fn logo(name: &str) -> String {
    format!(
        r"

    \    |  |                         |  |
   _ \   |  |   -_)   _` |   -_)   _` |  |  |  |    ({name})
 _/  _\ _| _| \___| \__, | \___| \__,_| _| \_, |    (v{})
                     ____|                  __/
",
        env!("CARGO_PKG_VERSION"),
    )
}
