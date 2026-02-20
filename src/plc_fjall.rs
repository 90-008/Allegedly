use crate::{Dt, ExportPage, Op, PageBoundaryState};
use data_encoding::BASE32_NOPAD;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, OwnedWriteBatch, PersistMode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

const SEP: u8 = 0;

type IpldCid = cid::CidGeneric<64>;

// 24 bytes -> 15 bytes
fn encode_did(buf: &mut Vec<u8>, did: &str) -> anyhow::Result<usize> {
    let input = did.trim_start_matches("did:plc:").to_uppercase();
    let len = BASE32_NOPAD
        .decode_len(input.len())
        .map_err(|_| anyhow::anyhow!("failed to calculate decode len for {did}"))?;

    let start = buf.len();
    buf.resize(start + len, 0);

    BASE32_NOPAD
        .decode_mut(input.as_bytes(), &mut buf[start..])
        .map_err(|_| anyhow::anyhow!("failed to encode did {did}"))
}

// 59 bytes -> 36 bytes
fn encode_cid(buf: &mut Vec<u8>, s: &str) -> anyhow::Result<usize> {
    IpldCid::try_from(s)?
        .write_bytes(buf)
        .map_err(|e| anyhow::anyhow!("failed to encode cid {s}: {e}"))
}

fn decode_cid(bytes: &[u8]) -> anyhow::Result<String> {
    IpldCid::try_from(bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode cid: {e}"))
        .map(|cid| cid.to_string())
}

fn op_key(created_at: &Dt, cid: &str) -> anyhow::Result<Vec<u8>> {
    let micros = created_at.timestamp_micros() as u64;
    let mut key = Vec::with_capacity(8 + 1 + cid.len());
    key.extend_from_slice(&micros.to_be_bytes());
    key.push(SEP);
    encode_cid(&mut key, cid)?;
    Ok(key)
}

fn by_did_prefix(did: &str) -> anyhow::Result<Vec<u8>> {
    let mut p = Vec::with_capacity(BASE32_NOPAD.decode_len(did.len())? + 1);
    encode_did(&mut p, did)?;
    p.push(SEP);
    Ok(p)
}

fn by_did_key(did: &str, cid: &str) -> anyhow::Result<Vec<u8>> {
    let mut key = by_did_prefix(did)?;
    encode_cid(&mut key, cid)?;
    Ok(key)
}

fn decode_timestamp(key: &[u8]) -> anyhow::Result<Dt> {
    let micros = u64::from_be_bytes(
        key.try_into()
            .map_err(|e| anyhow::anyhow!("invalid timestamp key {key:?}: {e}"))?,
    );
    Dt::from_timestamp_micros(micros as i64)
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp {micros}"))
}

// this is basically Op, but without the cid and created_at fields
// since we have them in the key already
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbOp {
    pub did: String,
    pub nullified: bool,
    pub operation: Box<serde_json::value::RawValue>,
}

#[derive(Clone)]
pub struct FjallDb {
    inner: Arc<FjallInner>,
}

struct FjallInner {
    db: Database,
    ops: Keyspace,
    by_did: Keyspace,
}

impl FjallDb {
    pub fn open(path: impl AsRef<Path>) -> fjall::Result<Self> {
        let db = Database::builder(path)
            .max_journaling_size(/* 1 GiB */ 1_024 * 1_024 * 1_024)
            .open()?;
        let opts = KeyspaceCreateOptions::default;
        let ops = db.keyspace("ops", || {
            opts().max_memtable_size(/* 256 MiB */ 256 * 1_024 * 1_024)
        })?;
        let by_did = db.keyspace("by_did", || {
            opts().max_memtable_size(/* 128 MiB */ 128 * 1_024 * 1_024)
        })?;
        Ok(Self {
            inner: Arc::new(FjallInner { db, ops, by_did }),
        })
    }

    pub fn clear(&self) -> fjall::Result<()> {
        self.inner.ops.clear()?;
        self.inner.by_did.clear()?;
        Ok(())
    }

    pub fn persist(&self) -> fjall::Result<()> {
        self.inner.db.persist(PersistMode::SyncAll)
    }

    pub fn get_latest(&self) -> anyhow::Result<Option<Dt>> {
        let Some(guard) = self.inner.ops.last_key_value() else {
            return Ok(None);
        };
        let key = guard
            .key()
            .map_err(|e| anyhow::anyhow!("fjall key error: {e}"))?;

        key.get(..8)
            .ok_or_else(|| anyhow::anyhow!("invalid timestamp key {key:?}"))
            .map(decode_timestamp)
            .flatten()
            .map(Some)
    }

    pub fn insert_op(&self, batch: &mut OwnedWriteBatch, op: &Op) -> anyhow::Result<usize> {
        let pk = by_did_key(&op.did, &op.cid)?;
        if self.inner.by_did.get(&pk)?.is_some() {
            return Ok(0);
        }
        let ts_key = op_key(&op.created_at, &op.cid)?;
        let value = serde_json::to_vec(op)?;
        batch.insert(&self.inner.ops, &ts_key, &value);
        batch.insert(
            &self.inner.by_did,
            &pk,
            &op.created_at.timestamp_micros().to_be_bytes(),
        );
        Ok(1)
    }

    pub fn ops_for_did(&self, did: &str) -> anyhow::Result<Vec<Op>> {
        let prefix = by_did_prefix(did)?;

        let mut entries: Vec<(Dt, Vec<u8>)> = Vec::new();
        for guard in self.inner.by_did.prefix(&prefix) {
            let (by_did_key, ts_bytes) = guard
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
            // construct op key from timestamp and cid
            let cid_bytes = by_did_key
                .get(prefix.len()..)
                .ok_or_else(|| anyhow::anyhow!("invalid by_did key {by_did_key:?}"))?;
            let op_key = [ts_bytes.as_ref(), &[SEP], cid_bytes].concat();
            entries.push((decode_timestamp(&ts_bytes)?, op_key));
        }

        entries.sort_by_key(|(ts, _)| *ts);

        let mut ops = Vec::with_capacity(entries.len());
        for (ts, op_key) in entries {
            let Some(value) = self.inner.ops.get(&op_key)? else {
                anyhow::bail!("op not found in db: {op_key:?}");
            };
            let op: DbOp = serde_json::from_slice(&value)?;
            let cid = decode_cid(
                op_key
                    .get(9..)
                    .ok_or_else(|| anyhow::anyhow!("invalid op key {op_key:?}"))?,
            )?;
            let op = Op {
                did: op.did,
                cid,
                created_at: ts,
                nullified: op.nullified,
                operation: op.operation,
            };
            ops.push(op);
        }
        Ok(ops)
    }

    pub fn export_ops(&self, after: Option<Dt>, limit: usize) -> anyhow::Result<Vec<Op>> {
        let iter = if let Some(after) = after {
            let start = (after.timestamp_micros() as u64).to_be_bytes();
            self.inner.ops.range(start..)
        } else {
            self.inner.ops.iter()
        };

        let mut ops = Vec::with_capacity(limit);
        for item in iter.take(limit) {
            let (key, value) = item
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
            let op: DbOp = serde_json::from_slice(&value)?;
            let created_at = decode_timestamp(
                key.get(..8)
                    .ok_or_else(|| anyhow::anyhow!("invalid op key {key:?}"))?,
            )?;
            let cid = decode_cid(
                key.get(9..)
                    .ok_or_else(|| anyhow::anyhow!("invalid op key {key:?}"))?,
            )?;
            let op = Op {
                did: op.did,
                cid,
                created_at,
                nullified: op.nullified,
                operation: op.operation,
            };
            ops.push(op);
        }
        Ok(ops)
    }
}

pub async fn backfill_to_fjall(
    db: FjallDb,
    reset: bool,
    mut pages: mpsc::Receiver<ExportPage>,
    notify_last_at: Option<oneshot::Sender<Option<Dt>>>,
) -> anyhow::Result<&'static str> {
    let t0 = Instant::now();

    if reset {
        let db = db.clone();
        tokio::task::spawn_blocking(move || db.clear()).await??;
        log::warn!("fjall reset: cleared all data");
    }

    let mut last_at = None;
    let mut ops_inserted: usize = 0;

    while let Some(page) = pages.recv().await {
        let should_track = notify_last_at.is_some();
        if should_track {
            if let Some(s) = PageBoundaryState::new(&page) {
                last_at = last_at.filter(|&l| l >= s.last_at).or(Some(s.last_at));
            }
        }

        let db = db.clone();
        let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut batch = db.inner.db.batch();
            let mut count: usize = 0;
            for op in &page.ops {
                count += db.insert_op(&mut batch, op)?;
            }
            batch.commit()?;
            Ok(count)
        })
        .await??;
        ops_inserted += count;
    }
    log::debug!("finished receiving bulk pages");

    if let Some(notify) = notify_last_at {
        log::trace!("notifying last_at: {last_at:?}");
        if notify.send(last_at).is_err() {
            log::error!("receiver for last_at dropped, can't notify");
        };
    }

    let db = db.clone();
    tokio::task::spawn_blocking(move || db.persist()).await??;

    log::info!(
        "backfill_to_fjall: inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("backfill_to_fjall")
}

pub async fn pages_to_fjall(
    db: FjallDb,
    mut pages: mpsc::Receiver<ExportPage>,
) -> anyhow::Result<&'static str> {
    log::info!("starting pages_to_fjall writer...");

    let t0 = Instant::now();
    let mut ops_inserted: usize = 0;

    while let Some(page) = pages.recv().await {
        log::trace!("writing page with {} ops", page.ops.len());
        let db = db.clone();
        let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut batch = db.inner.db.batch();
            let mut count: usize = 0;
            for op in &page.ops {
                count += db.insert_op(&mut batch, op)?;
            }
            batch.commit()?;
            Ok(count)
        })
        .await??;
        ops_inserted += count;
    }

    log::info!(
        "no more pages. inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("pages_to_fjall")
}
