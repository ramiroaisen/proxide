use crate::{
  client::pool::{healthcheck, Key},
  proxy_protocol::ProxyProtocolVersion,
  serde::{sni::Sni, url::StreamUpstreamOrigin},
};
use std::{
  convert::Infallible,
  sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
  },
  time::Duration,
};

pub async fn upstream_healthcheck_task(
  interval: Duration,
  key: Key,
  upstream_health: Arc<AtomicBool>,
) -> Infallible {
  log::debug!("starting upstream healthchecker for {key}");

  loop {
    let store = match healthcheck(key.clone()).await {
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

    tokio::time::sleep(interval).await;
  }
}

#[allow(clippy::too_many_arguments)]
pub async fn stream_upstream_healthcheck_task(
  interval: Duration,
  upstream_health: Arc<AtomicBool>,
  target: StreamUpstreamOrigin,
  proxy_tcp_nodelay: bool,
  proxy_read_timeout: Duration,
  proxy_write_timeout: Duration,
  send_proxy_protocol: Option<ProxyProtocolVersion>,
  proxy_protocol_write_timeout: Duration,
  sni: Option<Sni>,
  danger_accept_invalid_certs: bool,
) -> Infallible {
  log::debug!("starting upstream healthchecker for {target}");

  loop {
    let store = match super::stream::healthcheck(
      &target,
      proxy_tcp_nodelay,
      proxy_read_timeout,
      proxy_write_timeout,
      send_proxy_protocol,
      proxy_protocol_write_timeout,
      sni.clone(),
      danger_accept_invalid_certs,
    )
    .await
    {
      Ok(()) => true,
      Err(e) => {
        log::debug!("upstream healthcheck failed: {e} - {e:?}");
        false
      }
    };

    let prev = upstream_health.swap(store, Ordering::AcqRel);
    if prev != store {
      if store {
        log::info!("upstream {target} health set to ok");
      } else {
        log::info!("upstream {target} health set to error");
      }
    }

    tokio::time::sleep(interval).await;
  }
}
