use crate::client::upstream_pool::{Key, UpstreamPool};
use std::{
  convert::Infallible,
  sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
  },
};

pub async fn upstream_healthcheck_task(
  pool: Arc<UpstreamPool>,
  key: Key,
  upstream_health: Arc<AtomicBool>,
) -> Infallible {
  log::debug!("starting upstream healthchecker for {key}");

  loop {
    let store = match pool.healthcheck(key.clone()).await {
      Ok(()) => true,
      Err(e) => {
        log::debug!("upstream healthcheck failed: {e} - {e:?}");
        false
      }
    };

    let prev = upstream_health.swap(store, Ordering::AcqRel);
    if prev != store {
      if store {
        log::info!("upstream {key} health set to ok");
      } else {
        log::info!("upstream {key} health set to error");
      }
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
  }
}
