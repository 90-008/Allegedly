use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub trait Fetcher<T> {
    fn fetch(&self) -> impl Future<Output = Result<T, Box<dyn Error>>>;
}

#[derive(Debug)]
struct ExpiringValue<T: Clone> {
    value: T,
    expires: Instant,
}

impl<T: Clone> ExpiringValue<T> {
    fn get(&self, now: Instant) -> Option<T> {
        if now <= self.expires {
            tracing::trace!("returning val (fresh for {:?})", self.expires - now);
            Some(self.value.clone())
        } else {
            tracing::trace!("hiding expired val");
            None
        }
    }
}

// TODO: generic over the fetcher's actual error type
#[derive(Clone)]
pub struct CachedValue<T: Clone, F: Fetcher<T>> {
    latest: Arc<Mutex<Option<ExpiringValue<T>>>>,
    fetcher: F,
    validitiy: Duration,
}

impl<T: Clone, F: Fetcher<T>> CachedValue<T, F> {
    pub fn new(f: F, validitiy: Duration) -> Self {
        Self {
            latest: Default::default(),
            fetcher: f,
            validitiy,
        }
    }
    pub async fn get(&self) -> Result<T, Box<dyn Error>> {
        let now = Instant::now();
        return self.get_impl(now).await;
    }
    async fn get_impl(&self, now: Instant) -> Result<T, Box<dyn Error>> {
        let mut val = self.latest.lock().await;
        if let Some(v) = val.as_ref().and_then(|v| v.get(now)) {
            return Ok(v);
        }
        tracing::debug!(
            "value {}, fetching...",
            if val.is_some() {
                "expired"
            } else {
                "not present"
            }
        );
        let new = self
            .fetcher
            .fetch()
            .await
            .inspect_err(|e| tracing::warn!("value fetch failed, next access will retry: {e}"))?;
        tracing::debug!("fetched ok, saving a copy for cache.");
        *val = Some(ExpiringValue {
            value: new.clone(),
            expires: now + self.validitiy,
        });
        Ok(new)
    }
}
