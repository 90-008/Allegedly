use crate::{CLIENT, Dt, ExportPage, Op, OpKey};
use reqwest::Url;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum GetPageError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

/// ops are primary-keyed by (did, cid)
/// plc orders by `created_at` but does not guarantee distinct times per op
/// we assume that the order will at least be deterministic: this may be unsound
#[derive(Debug, PartialEq)]
pub struct LastOp {
    pub created_at: Dt,   // any op greater is definitely not duplicated
    pk: (String, String), // did, cid
}

impl From<Op> for LastOp {
    fn from(op: Op) -> Self {
        Self {
            created_at: op.created_at,
            pk: (op.did, op.cid),
        }
    }
}

impl From<&Op> for LastOp {
    fn from(op: &Op) -> Self {
        Self {
            created_at: op.created_at,
            pk: (op.did.clone(), op.cid.clone()),
        }
    }
}

// bit of a hack
impl From<Dt> for LastOp {
    fn from(dt: Dt) -> Self {
        Self {
            created_at: dt,
            pk: ("".to_string(), "".to_string()),
        }
    }
}

/// State for removing duplicates ops between PLC export page boundaries
#[derive(Debug, PartialEq)]
pub struct PageBoundaryState {
    /// The previous page's last timestamp
    ///
    /// Duplicate ops from /export only occur for the same exact timestamp
    pub last_at: Dt,
    /// The previous page's ops at its last timestamp
    keys_at: Vec<OpKey>, // expected to ~always be length one
}

impl PageBoundaryState {
    /// Initialize the boundary state with a PLC page
    pub fn new(page: &ExportPage) -> Option<Self> {
        // grab the very last op
        let (last_at, last_key) = page.ops.last().map(|op| (op.created_at, op.into()))?;

        // set initial state
        let mut me = Self {
            last_at,
            keys_at: vec![last_key],
        };

        // and make sure all keys at this time are captured from the back
        me.capture_nth_last_at(page, last_at, 1);

        Some(me)
    }
    /// Apply the deduplication and update state
    ///
    /// The beginning of the page will be modified to remove duplicates from the
    /// previous page.
    ///
    /// The end of the page is inspected to update the deduplicator state for
    /// the next page.
    fn apply_to_next(&mut self, page: &mut ExportPage) {
        // walk ops forward, kicking previously-seen ops until created_at advances
        let to_remove: Vec<usize> = page
            .ops
            .iter()
            .enumerate()
            .take_while(|(_, op)| op.created_at == self.last_at)
            .filter(|(_, op)| self.keys_at.contains(&(*op).into()))
            .map(|(i, _)| i)
            .collect();

        // actually remove them. last to first so indices don't shift
        for dup_idx in to_remove.into_iter().rev() {
            page.ops.remove(dup_idx);
        }

        // grab the very last op
        let Some((last_at, last_key)) = page.ops.last().map(|op| (op.created_at, op.into())) else {
            // there are no ops left? oop. bail.
            // last_at and existing keys remain in tact
            return;
        };

        // reset state (as long as time actually moved forward on this page)
        if last_at > self.last_at {
            self.last_at = last_at;
            self.keys_at = vec![last_key];
        } else {
            // weird cases: either time didn't move (fine...) or went backwards (not fine)
            assert_eq!(last_at, self.last_at, "time moved backwards on a page");
            self.keys_at.push(last_key);
        }
        // and make sure all keys at this time are captured from the back
        self.capture_nth_last_at(page, last_at, 1);
    }

    /// walk backwards from 2nd last and collect keys until created_at changes
    fn capture_nth_last_at(&mut self, page: &ExportPage, last_at: Dt, skips: usize) {
        page.ops
            .iter()
            .rev()
            .skip(skips)
            .take_while(|op| op.created_at == last_at)
            .for_each(|op| {
                self.keys_at.push(op.into());
            });
    }
}

/// Get one PLC export page
///
/// Extracts the final op so it can be used to fetch the following page
pub async fn get_page(url: Url) -> Result<(ExportPage, Option<LastOp>), GetPageError> {
    use futures::TryStreamExt;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    log::trace!("Getting page: {url}");

    let res = CLIENT.get(url).send().await?.error_for_status()?;
    let stream = Box::pin(
        res.bytes_stream()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .into_async_read()
            .compat(),
    );

    let mut lines = BufReader::new(stream).lines();
    let mut ops = Vec::new();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Op>(line) {
                    Ok(op) => ops.push(op),
                    Err(e) => log::warn!("failed to parse op: {e} ({line})"),
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::warn!("transport error mid-page: {}; returning partial page", e);
                break;
            }
        }
    }

    let last_op = ops.last().map(Into::into);

    Ok((ExportPage { ops }, last_op))
}

/// Poll an upstream PLC server for new ops
///
/// Pages of operations are written to the `dest` channel.
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use allegedly::{ExportPage, Op, poll_upstream};
///
/// let after = Some(chrono::Utc::now());
/// let upstream = "https://plc.wtf/export".parse().unwrap();
/// let throttle = std::time::Duration::from_millis(300);
///
/// let (tx, mut rx) = tokio::sync::mpsc::channel(1);
/// tokio::task::spawn(poll_upstream(after, upstream, throttle, tx));
///
/// while let Some(ExportPage { ops }) = rx.recv().await {
///     println!("received {} plc ops", ops.len());
///
///     for Op { did, cid, operation, .. } in ops {
///         // in this example we're alerting when changes are found for one
///         // specific identity
///         if did == "did:plc:hdhoaan3xa3jiuq4fg4mefid" {
///             println!("Update found for {did}! cid={cid}\n -> operation: {}", operation.get());
///         }
///     }
/// }
/// # }
/// ```
pub async fn poll_upstream(
    after: Option<Dt>,
    base: Url,
    throttle: Duration,
    dest: mpsc::Sender<ExportPage>,
) -> anyhow::Result<&'static str> {
    log::info!("starting upstream poller at {base} after {after:?}");
    let mut tick = tokio::time::interval(throttle);
    let mut prev_last: Option<LastOp> = after.map(Into::into);
    let mut boundary_state: Option<PageBoundaryState> = None;
    loop {
        tick.tick().await;

        let mut url = base.clone();
        if let Some(ref pl) = prev_last {
            url.query_pairs_mut()
                .append_pair("after", &pl.created_at.to_rfc3339());
        };

        let (mut page, next_last) = match get_page(url).await {
            Ok(res) => res,
            Err(e) => {
                log::warn!("error polling upstream: {e}");
                continue;
            }
        };

        if let Some(ref mut state) = boundary_state {
            state.apply_to_next(&mut page);
        } else {
            boundary_state = PageBoundaryState::new(&page);
        }
        if !page.is_empty() {
            match dest.try_send(page) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(page)) => {
                    log::warn!("export: destination channel full, awaiting...");
                    dest.send(page).await?;
                }
                e => e?,
            };
        }

        prev_last = next_last.or(prev_last);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const FIVES_TS: i64 = 1431648000;
    const NEXT_TS: i64 = 1431648001;

    fn valid_op() -> Op {
        serde_json::from_value(serde_json::json!({
            "did": "did",
            "cid": "cid",
            "createdAt": "2015-05-15T00:00:00Z",
            "nullified": false,
            "operation": {},
        }))
        .unwrap()
    }

    fn next_op() -> Op {
        serde_json::from_value(serde_json::json!({
            "did": "didnext",
            "cid": "cidnext",
            "createdAt": "2015-05-15T00:00:01Z",
            "nullified": false,
            "operation": {},
        }))
        .unwrap()
    }

    fn base_state() -> PageBoundaryState {
        let page = ExportPage {
            ops: vec![valid_op()],
        };
        PageBoundaryState::new(&page).expect("to have a base page boundary state")
    }

    #[test]
    fn test_boundary_new_empty() {
        let page = ExportPage { ops: vec![] };
        let state = PageBoundaryState::new(&page);
        assert!(state.is_none());
    }

    #[test]
    fn test_boundary_new_one_op() {
        let page = ExportPage {
            ops: vec![valid_op()],
        };
        let state = PageBoundaryState::new(&page).unwrap();
        assert_eq!(state.last_at, Dt::from_timestamp(FIVES_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![OpKey {
                cid: "cid".to_string(),
                did: "did".to_string(),
            }]
        );
    }

    #[test]
    fn test_add_new_empty() {
        let mut state = base_state();
        state.apply_to_next(&mut ExportPage { ops: vec![] });
        assert_eq!(state, base_state());
    }

    #[test]
    fn test_add_new_same_op() {
        let mut page = ExportPage {
            ops: vec![valid_op()],
        };
        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state, base_state());
    }

    #[test]
    fn test_add_new_same_time() {
        // make an op with a different OpKey
        let mut op = valid_op();
        op.cid = "cid2".to_string();
        let mut page = ExportPage { ops: vec![op] };

        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(FIVES_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![
                OpKey {
                    cid: "cid".to_string(),
                    did: "did".to_string(),
                },
                OpKey {
                    cid: "cid2".to_string(),
                    did: "did".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_add_new_same_time_dup_before() {
        // make an op with a different OpKey
        let mut op = valid_op();
        op.cid = "cid2".to_string();
        let mut page = ExportPage {
            ops: vec![valid_op(), op],
        };

        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(FIVES_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![
                OpKey {
                    cid: "cid".to_string(),
                    did: "did".to_string(),
                },
                OpKey {
                    cid: "cid2".to_string(),
                    did: "did".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_add_new_same_time_dup_after() {
        // make an op with a different OpKey
        let mut op = valid_op();
        op.cid = "cid2".to_string();
        let mut page = ExportPage {
            ops: vec![op, valid_op()],
        };

        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(FIVES_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![
                OpKey {
                    cid: "cid".to_string(),
                    did: "did".to_string(),
                },
                OpKey {
                    cid: "cid2".to_string(),
                    did: "did".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_add_new_next_time() {
        let mut page = ExportPage {
            ops: vec![next_op()],
        };
        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(NEXT_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![OpKey {
                cid: "cidnext".to_string(),
                did: "didnext".to_string(),
            },]
        );
    }

    #[test]
    fn test_add_new_next_time_with_dup() {
        let mut page = ExportPage {
            ops: vec![valid_op(), next_op()],
        };
        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(NEXT_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![OpKey {
                cid: "cidnext".to_string(),
                did: "didnext".to_string(),
            },]
        );
        assert_eq!(page.ops.len(), 1);
        assert_eq!(page.ops[0], next_op());
    }

    #[test]
    fn test_add_new_next_time_with_dup_and_new_prev_same_time() {
        // make an op with a different OpKey
        let mut op = valid_op();
        op.cid = "cid2".to_string();

        let mut page = ExportPage {
            ops: vec![
                valid_op(), // should get dropped
                op.clone(), // should be kept
                next_op(),
            ],
        };
        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(NEXT_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![OpKey {
                cid: "cidnext".to_string(),
                did: "didnext".to_string(),
            },]
        );
        assert_eq!(page.ops.len(), 2);
        assert_eq!(page.ops[0], op);
        assert_eq!(page.ops[1], next_op());
    }

    #[test]
    fn test_add_new_next_time_with_dup_later_and_new_prev_same_time() {
        // make an op with a different OpKey
        let mut op = valid_op();
        op.cid = "cid2".to_string();

        let mut page = ExportPage {
            ops: vec![
                op.clone(), // should be kept
                valid_op(), // should get dropped
                next_op(),
            ],
        };
        let mut state = base_state();
        state.apply_to_next(&mut page);
        assert_eq!(state.last_at, Dt::from_timestamp(NEXT_TS, 0).unwrap());
        assert_eq!(
            state.keys_at,
            vec![OpKey {
                cid: "cidnext".to_string(),
                did: "didnext".to_string(),
            },]
        );
        assert_eq!(page.ops.len(), 2);
        assert_eq!(page.ops[0], op);
        assert_eq!(page.ops[1], next_op());
    }
}
