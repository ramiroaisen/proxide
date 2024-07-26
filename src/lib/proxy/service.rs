#![allow(clippy::declare_interior_mutable_const)] // silence const headers warning
#![allow(non_camel_case_types)] // silence #[dynamic] warning
#![allow(non_upper_case_globals)]
use http::header::CONTENT_TYPE;
// silence #[dynamic] warning
use http::Uri;
use hyper::body::Body as HyperBody;
use hyper::header::{HeaderValue, CONNECTION, HOST};
use hyper::{
  body::Incoming,
  header::{HeaderName, SERVER},
  service::Service,
  Request, Response,
};
use hyper::{Method, StatusCode};
use hyper_rustls::ConfigBuilderExt;
use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use rustls::pki_types::ServerName;
use static_init::dynamic;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{convert::Infallible, ops::Deref, pin::Pin, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::time::FutureExt;
use url::Host;

use super::error::ProxyStreamError;
use super::header::CONNECTION_UPGRADE;
use super::util::{remove_hop_headers, resolve_host_port};
use crate::backoff::BackOff;
use crate::body::{map_request_body, Body};
use crate::client::pool::ProxyProtocolConfig;
use crate::client::send_request;
use crate::config::defaults::{
  DEFAULT_HTTP_BALANCE, DEFAULT_HTTP_PROXY_READ_TIMEOUT, DEFAULT_HTTP_PROXY_RETRIES,
  DEFAULT_HTTP_PROXY_WRITE_TIMEOUT, DEFAULT_HTTP_RETRY_BACKOFF,
  DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT, DEFAULT_PROXY_TCP_NODELAY, DEFAULT_STREAM_BALANCE,
  DEFAULT_STREAM_PROXY_READ_TIMEOUT, DEFAULT_STREAM_PROXY_RETRIES,
  DEFAULT_STREAM_PROXY_WRITE_TIMEOUT, DEFAULT_STREAM_RETRY_BACKOFF,
  DEFAULT_STREAM_SERVER_READ_TIMEOUT, DEFAULT_STREAM_SERVER_WRITE_TIMEOUT,
};
use crate::config::matcher::RequestInfo;
use crate::config::{Balance, Config, HttpApp, HttpHandle, HttpUpstream, StreamHandle};
use crate::net::timeout::TimeoutIo;
use crate::proxy::balance::balance_sort;
use crate::proxy::error::ProxyHttpError;
use crate::proxy::header::{
  HTTP, HTTPS, SERVER_HEADER_VALUE, X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO, X_REAL_IP,
};
use crate::proxy_protocol::ProxyHeader;
use crate::serde::duration::SDuration;
use crate::serde::header_name::SHeaderName;
use crate::serde::header_value::SHeaderValue;
use crate::service::{AddrService, Connection, StreamService};
#[cfg(feature = "stats")]
use crate::stats::counters_io::CountersIo;
use crate::tls::danger_no_cert_verifier::DangerNoCertVerifier;
use crate::upgrade::{request_connection_upgrade, response_connection_upgrade};

#[allow(unused)]
use crate::serde::content_type::ContentTypeMatcher;

#[inline(always)]
#[must_use = "increment_open_connections returns a drop guard"]
fn increment_open_connections(atomic: Arc<AtomicUsize>) -> impl Drop {
  atomic.fetch_add(1, Ordering::Relaxed);
  defer::defer(move || {
    atomic.fetch_sub(1, Ordering::Relaxed);
  })
}

#[inline(always)]
pub fn resolve_upstream_app<'a>(
  host: &str,
  config: &'a Config,
  bind_addr: SocketAddr,
  bind_ssl: bool,
) -> Option<&'a HttpApp> {
  for app in &config.http.apps {
    for listen in &app.listen {
      if !listen.addr.matches_addr(bind_addr) {
        continue;
      }

      if listen.ssl.is_some() != bind_ssl {
        continue;
      }

      match app.server_names.as_ref() {
        Some(list) => {
          for server_name in list {
            if server_name.matches(host) {
              return Some(app);
            }
          }
        }
        None => {
          return Some(app);
        }
      }
    }
  }

  None
}

#[inline(always)]
#[cfg(any(
  feature = "compression-br",
  feature = "compression-zstd",
  feature = "compression-gzip",
  feature = "compression-deflate"
))]
fn compress(
  app_compression: &[crate::config::Compress],
  app_compression_content_types: &[ContentTypeMatcher],
  app_compression_min_size: u64,
  accept_encoding: Option<&HeaderValue>,
  status: StatusCode,
  upstream_body: Body,
  upstream_headers: hyper::HeaderMap,
) -> (Body, hyper::HeaderMap) {
  if let Some(selected) = crate::compression::should_compress(
    app_compression,
    app_compression_content_types,
    app_compression_min_size,
    accept_encoding,
    status,
    upstream_body.size_hint(),
    &upstream_headers,
  ) {
    const ACCEPT_ENCODING_VALUE: HeaderValue = HeaderValue::from_static("accept-encoding");
    let body = crate::compression::compress_body(upstream_body, selected);
    let mut response_headers = upstream_headers;
    remove_hop_headers(&mut response_headers);
    response_headers.insert(
      hyper::header::CONTENT_ENCODING,
      selected.algo.to_header_value(),
    );
    response_headers.remove(hyper::header::CONTENT_LENGTH);
    crate::proxy::header::add_vary(&mut response_headers, ACCEPT_ENCODING_VALUE);
    return (body, response_headers);
  }

  let mut response_headers = upstream_headers.clone();
  remove_hop_headers(&mut response_headers);
  (upstream_body, response_headers)
}

pub async fn serve_proxy(
  request: Request<Incoming>,
  config: &Config,
  local_addr: SocketAddr,
  remote_addr: SocketAddr,
  proxy_header: Option<ProxyHeader>,
  is_ssl: bool,
) -> Result<Response<Body>, ProxyHttpError> {
  #[cfg(feature = "access-log")]
  let start = std::time::Instant::now();

  let proxy_header_addr = proxy_header.as_ref().and_then(|h| h.source_addr());

  let request_uri = request.uri().clone();
  let request_method = request.method().clone();
  let request_version = request.version();
  let request_is_upgrade =
    request_connection_upgrade(request.method(), request.headers()).is_some();

  #[cfg(feature = "access-log")]
  let request_referer = request.headers().get(hyper::header::REFERER).cloned();
  #[cfg(feature = "access-log")]
  let request_user_agent = request.headers().get(hyper::header::USER_AGENT).cloned();

  let (host, port) = resolve_host_port(&request)?;
  let host = host.to_string();

  let app = match resolve_upstream_app(&host, config, local_addr, is_ssl) {
    Some(app) => app,
    None => {
      return Err(ProxyHttpError::UnresolvedApp);
    }
  };

  #[cfg(feature = "access-log")]
  let mut proxied_to = None;

  let result = (async {
    #[cfg(any(
      feature = "compression-br",
      feature = "compression-zstd",
      feature = "compression-gzip",
      feature = "compression-deflate"
    ))]
    let request_accept_encoding = request
      .headers()
      .get(hyper::header::ACCEPT_ENCODING)
      .cloned();

    let handle_balance: Option<Balance>;
    let handle_retries: Option<usize>;
    let handle_retry_backoff: Option<BackOff>;
    let handle_proxy_headers: &[(SHeaderName, SHeaderValue)];
    let handle_response_headers: &[(SHeaderName, SHeaderValue)];
    let handle_proxy_protocol_write_timeout: Option<SDuration>;
    let handle_state_round_robin_index: &Arc<AtomicUsize>;
    let handle_proxy_read_timeout: Option<SDuration>;
    let handle_proxy_write_timeout: Option<SDuration>;
    let handle_proxy_tcp_nodelay: Option<bool>;
    let upstreams: &[HttpUpstream];

    // TODO: document this and move out of the service function
    #[cfg(feature = "interpolation")]
    macro_rules! interpolate {
      ($source:expr) => {{
        let src = $source;

        use std::fmt::Write;
        use $crate::interpolate::{tokens, Token as T};
        let mut target = String::with_capacity(src.len());

        for token in tokens(src) {
          match token {
            T::Lit(v) => {
              target.push_str(v);
            }

            T::Var(ident) => {
              match ident {
                "scheme" => target.push_str(if is_ssl { "https" } else { "http" }),
                "host" => target.push_str(&host),
                "port" => if let Some(port) = port { let _ = write!(target, ":{}", port); },
                "method" => target.push_str(request_method.as_str()),
                "version" => target.push_str(match request_version {
                  hyper::Version::HTTP_09 => "0.9",
                  hyper::Version::HTTP_10 => "1.0",
                  hyper::Version::HTTP_11 => "1.1",
                  hyper::Version::HTTP_2 => "2.0",
                  hyper::Version::HTTP_3 => "3.0",
                  _ => "unknown",
                }),
                "request_uri" => {
                  match request_uri.path_and_query() {
                    Some(uri) => target.push_str(uri.as_str()),
                    None => target.push_str("/"),
                  }
                }

                "connection_remote_ip" => {
                  let _ = write!(target, "{}", remote_addr.ip());
                },

                "proxy_protocol_remote_ip" => {
                  match proxy_header_addr {
                    None => {
                      target.push_str("unknown");
                    }

                    Some(addr) => {
                      let _ = write!(target, "{}", addr.ip());
                    }
                  }
                },

                "remote_ip" => {
                  match proxy_header_addr {
                    None => {
                      let _ = write!(target, "{}", remote_addr.ip());
                    }
                    Some(addr) => {
                      let _ = write!(target, "{}", addr.ip());
                    }
                  }
                },
                _ => {
                  target.push('$');
                  target.push_str(ident);
                }
              }
            }
          }
        }

        target
      }}
    }

    #[cfg(feature = "interpolation")]
    macro_rules! interpolate_header_value {
      ($source:expr) => {{
        let source = $source;
        let target = interpolate!(source);
        HeaderValue::try_from(target)
          .map_err(|_| ProxyHttpError::InvalidHeaderInterpolation(source.into()))?
      }};
    }

    macro_rules! add_headers {
      ($headers:expr, $list:expr) => {{
        #[cfg(feature = "interpolation")]
        for (k, v) in $list.iter() {
          if v.as_bytes().is_empty() {
            $headers.remove(k.deref());
          } else {
            let value = interpolate_header_value!(v.to_str().unwrap());
            $headers.insert(HeaderName::from(k.clone()), value);
          }
        }

        #[cfg(not(feature = "interpolation"))]
        for (k, v) in $list.iter() {
          if v.as_bytes().is_empty() {
            $headers.remove(k.deref());
          } else {
            $headers.insert(HeaderName::from(k.clone()), HeaderValue::from(v.clone()));
          }
        }
      }};
    }

    let mut handle = &app.handle;

    'handle: loop {
      match handle {
        HttpHandle::Return {
          status,
          response_headers,
          body: content,
        } => {
          let body = match content {
            Some(content) => {
              #[cfg(feature = "interpolation")]
              let data = interpolate!(content);

              #[cfg(not(feature = "interpolation"))]
              let data = String::from(content);

              Body::full(data)
            }

            None => Body::empty(),
          };

          let mut response = Response::new(body);
          *response.status_mut() = (*status).into();
          add_headers!(response.headers_mut(), config.http.response_headers);
          add_headers!(response.headers_mut(), app.response_headers);
          add_headers!(response.headers_mut(), response_headers);

          response.headers_mut().insert(SERVER, SERVER_HEADER_VALUE);

          return Ok(response);
        }

        HttpHandle::Stats { response_headers } => {
          let json = serde_json::to_value(config).map_err(ProxyHttpError::StatsSerialize)?;
          let yaml = serde_yaml::to_string(&json).unwrap();
          let body = Body::full(yaml);

          let mut res = Response::new(body);
          *res.status_mut() = StatusCode::OK;
          res.headers_mut().insert(
            CONTENT_TYPE,
            // HeaderValue::from_static("application/json;charset=utf-8"),
            HeaderValue::from_static("text/plain;charset=utf-8"),
          );
          res.headers_mut().insert(SERVER, SERVER_HEADER_VALUE);
          add_headers!(res.headers_mut(), config.http.response_headers);
          add_headers!(res.headers_mut(), app.response_headers);
          add_headers!(res.headers_mut(), response_headers);
          return Ok(res);
        }

        HttpHandle::HeapProfile { response_headers } => {
          #[cfg(not(all(target_os = "linux", feature = "jemalloc")))]
          {
            return Err(ProxyHttpError::HeapProfileNotCompiled);
          }

          #[cfg(all(target_os = "linux", feature = "jemalloc"))]
          {
            let mut ctl = match jemalloc_pprof::PROF_CTL.as_ref() {
              Some(ctl) => ctl.lock().await,
              None => {
                let mut res = Response::new(Body::full("Profilling is not activated (1)"));
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                res.headers_mut().insert(SERVER, SERVER_HEADER_VALUE);
                return Ok(res);
              }
            };

            if !ctl.activated() {
              return Err(ProxyHttpError::HeapProfileNotActivated);
            }

            let dump = ctl.dump_pprof().map_err(ProxyHttpError::HeapProfileError)?;

            drop(ctl);
            let mut res = Response::new(Body::full(dump));
            *res.status_mut() = StatusCode::OK;
            res.headers_mut().insert(SERVER, SERVER_HEADER_VALUE);
            res.headers_mut().insert(
              hyper::header::CONTENT_TYPE,
              HeaderValue::from_static("application/octet-stream"),
            );
            add_headers!(res.headers_mut(), config.http.response_headers);
            add_headers!(res.headers_mut(), app.response_headers);
            add_headers!(res.headers_mut(), response_headers);
            return Ok(res);
          }
        }

        HttpHandle::Proxy {
          balance,
          upstream,
          retries,
          retry_backoff,
          proxy_headers,
          response_headers,
          proxy_protocol_write_timeout,
          state_round_robin_index,
          proxy_read_timeout,
          proxy_write_timeout,
          proxy_tcp_nodelay,
        } => {
          handle_balance = *balance;
          upstreams = upstream;
          handle_retries = *retries;
          handle_retry_backoff = *retry_backoff;
          handle_proxy_headers = proxy_headers;
          handle_response_headers = response_headers;
          handle_proxy_protocol_write_timeout = *proxy_protocol_write_timeout;
          handle_state_round_robin_index = state_round_robin_index;
          handle_proxy_read_timeout = *proxy_read_timeout;
          handle_proxy_write_timeout = *proxy_write_timeout;
          handle_proxy_tcp_nodelay = *proxy_tcp_nodelay;
          break 'handle;
        }

        HttpHandle::When(matchers) => {
          let target = RequestInfo {
            request: &request,
            remote_addr,
          };

          for matcher in matchers {
            if matcher.matcher.matches(&target) {
              handle = &matcher.handle;
              continue 'handle;
            }
          }

          return Err(ProxyHttpError::UnresolvedLocation);
        }
      }
    }

    if upstreams.is_empty() {
      return Err(ProxyHttpError::UnresolvedUpstream);
    }

    let proxy_host = {
      let host_string = match port {
        Some(port) => format!("{}:{}", host, port),
        None => host.clone(),
      };

      HeaderValue::try_from(host_string).map_err(|_| ProxyHttpError::InvalidHost)?
    };

    let proxy_x_real_ip = match proxy_header_addr {
      None => HeaderValue::try_from(remote_addr.ip().to_string()).unwrap(),
      Some(addr) => HeaderValue::try_from(addr.ip().to_string()).unwrap(),
    };

    let proxy_x_forwarded_for = match proxy_header_addr {
      Some(proxy_protocol_addr) => match request.headers().get(X_FORWARDED_FOR) {
        Some(prev) => match prev.to_str() {
          Ok(prev) => HeaderValue::try_from(format!(
            "{},{},{}",
            prev,
            proxy_protocol_addr.ip(),
            remote_addr.ip()
          ))
          .unwrap(),
          Err(_) => {
            HeaderValue::try_from(format!("{},{}", proxy_protocol_addr.ip(), remote_addr.ip()))
              .unwrap()
          }
        },

        None => HeaderValue::try_from(format!("{},{}", proxy_protocol_addr.ip(), remote_addr.ip()))
          .unwrap(),
      },

      None => match request.headers().get(X_FORWARDED_FOR) {
        Some(prev) => match prev.to_str() {
          Ok(prev) => HeaderValue::try_from(format!("{},{}", prev, remote_addr.ip())).unwrap(),
          Err(_) => proxy_x_real_ip.clone(),
        },

        None => proxy_x_real_ip.clone(),
      },
    };

    let proxy_method = request_method.clone();
    let mut proxy_headers = request.headers().clone();
    remove_hop_headers(&mut proxy_headers);
    proxy_headers.insert(HOST, proxy_host.clone());
    proxy_headers.insert(X_REAL_IP, proxy_x_real_ip);
    proxy_headers.insert(X_FORWARDED_HOST, proxy_host);
    proxy_headers.insert(X_FORWARDED_FOR, proxy_x_forwarded_for);
    proxy_headers.insert(X_FORWARDED_PROTO, if is_ssl { HTTPS } else { HTTP });
    add_headers!(proxy_headers, config.http.proxy_headers);
    add_headers!(proxy_headers, handle_proxy_headers);
    // the $config.http.app.upstream proxy headers will be added on demand for the selected upstream

    let mut root_request = Some(map_request_body(request, Body::incoming));
    let mut last_error: Option<ProxyHttpError> = None;

    let retries = crate::option!(
      handle_retries,
      app.retries,
      config.http.retries,
      => DEFAULT_HTTP_PROXY_RETRIES
    );

    let backoff = crate::option!(
      handle_retry_backoff,
      app.retry_backoff,
      config.http.retry_backoff,
      => DEFAULT_HTTP_RETRY_BACKOFF
    );

    let balance = crate::option!(
      handle_balance,
      app.balance,
      config.http.balance,
      => DEFAULT_HTTP_BALANCE
    );

    for i in 0..=retries {
      if i != 0 {
        tokio::time::sleep(backoff.duration_for(i - 1)).await;
      }

      let sorted_upstreams = balance_sort(
        upstreams,
        balance,
        remote_addr.ip(),
        handle_state_round_robin_index,
      );

      'upstreams: for upstream in sorted_upstreams {
        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
        macro_rules! compression {
          () => {{
            let compression: &[_] = crate::option!(
              upstream.compression.as_deref(),
              app.compression.as_deref(),
              config.http.compression.as_deref(),
              => crate::config::defaults::DEFAULT_COMPRESSION
            );

            compression
          }};
        }

        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
        macro_rules! compression_content_types {
          () => {{
            let content_types: &[_] = crate::option!(
              upstream.compression_content_types.as_deref(),
              app.compression_content_types.as_deref(),
              config.http.compression_content_types.as_deref(),
              => crate::config::defaults::DEFAULT_COMPRESSION_CONTENT_TYPES
            );

            content_types
          }};
        }

        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
        macro_rules! compression_min_size {
          () => {
            crate::option!(
              upstream.compression_min_size,
              app.compression_min_size,
              config.http.compression_min_size,
              => crate::config::defaults::DEFAULT_COMPRESSION_MIN_SIZE
            )
          }
        }

        let proxy_sni = upstream.sni.clone();

        let proxy_uri = {
          let path = match request_uri.path_and_query() {
            Some(path) => path.as_str(),
            None => "/",
          };

          Uri::try_from(format!(
            "{scheme}://{host}{port}{path_prefix}{path}",
            scheme = upstream.base_url.scheme(),
            host = match upstream.base_url.host_str() {
              Some(host) => host,
              None => return Err(ProxyHttpError::InvalidUpstreamUrlMissingHost),
            },
            port = match upstream.base_url.port() {
              // TODO: remove this allocation
              Some(port) => format!(":{}", port),
              None => String::new(),
            },
            path_prefix = match upstream.base_url.path() {
              "/" => "",
              path => path,
            },
            path = path,
          ))
          .map_err(ProxyHttpError::UpstreamUrlParse)?
        };

        #[cfg(feature = "access-log")]
        {
          proxied_to = Some(proxy_uri.to_string());
        }

        let read_timeout = crate::option!(
          @timeout
          upstream.proxy_read_timeout,
          handle_proxy_read_timeout,
          app.proxy_read_timeout,
          config.http.proxy_read_timeout
          => DEFAULT_HTTP_PROXY_READ_TIMEOUT
        );

        let write_timeout = crate::option!(
          @timeout
          upstream.proxy_write_timeout,
          handle_proxy_write_timeout,
          app.proxy_write_timeout,
          config.http.proxy_write_timeout
          => DEFAULT_HTTP_PROXY_WRITE_TIMEOUT
        );

        let proxy_tcp_nodelay = crate::option!(
          upstream.proxy_tcp_nodelay,
          handle_proxy_tcp_nodelay,
          app.proxy_tcp_nodelay,
          config.http.proxy_tcp_nodelay,
          config.proxy_tcp_nodelay,
          => DEFAULT_PROXY_TCP_NODELAY
        );

        let request = root_request.take().expect("root request loop take");

        let proxy_protocol_config = match upstream.send_proxy_protocol {
          None => None,
          Some(version) => {
            let timeout = crate::option!(
              @timeout
              upstream.proxy_protocol_write_timeout,
              handle_proxy_protocol_write_timeout,
              config.http.proxy_protocol_write_timeout,
              config.proxy_protocol_write_timeout,
              => DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT
            );

            let header = match &proxy_header {
              Some(ProxyHeader::Tcp4(tcp4)) => ProxyHeader::Tcp4(tcp4.clone()),

              Some(ProxyHeader::Tcp6(tcp6)) => ProxyHeader::Tcp6(tcp6.clone()),

              _ => match ProxyHeader::try_from((remote_addr, local_addr)) {
                Ok(header) => header,
                Err(_) => ProxyHeader::Unknown,
              },
            };

            Some(ProxyProtocolConfig {
              header,
              version,
              timeout,
            })
          }
        };

        // upgrade asked
        if request_is_upgrade {
          log::debug!("received upstream request");
          proxy_headers.insert(CONNECTION, CONNECTION_UPGRADE);

          let mut proxy_request = hyper::Request::new(Body::empty());
          *proxy_request.version_mut() = upstream.version.into();
          *proxy_request.method_mut() = proxy_method.clone();
          *proxy_request.uri_mut() = proxy_uri;
          *proxy_request.headers_mut() = proxy_headers.clone();
          add_headers!(proxy_request.headers_mut(), upstream.proxy_headers);

          let open_connections_guard =
            increment_open_connections(upstream.state_open_connections.clone());
          let upstream_response = match send_request(
            proxy_request,
            proxy_sni,
            upstream.danger_accept_invalid_certs,
            #[cfg(feature = "stats")]
            &upstream.stats_total_read_bytes,
            #[cfg(feature = "stats")]
            &upstream.stats_total_write_bytes,
            Some(read_timeout),
            Some(write_timeout),
            proxy_tcp_nodelay,
            proxy_protocol_config,
          )
          .await
          {
            Ok(response) => {
              upstream.state_health.store(true, Ordering::Relaxed);
              #[cfg(feature = "stats")]
              upstream
                .stats_total_connections
                .fetch_add(1, Ordering::Relaxed);
              response
            }
            Err(e) => {
              log::warn!("proxy request error: {e} {e:?}");
              upstream.state_health.store(false, Ordering::Relaxed);
              drop(open_connections_guard);
              last_error = Some(e.into());
              root_request = Some(request);
              continue 'upstreams;
            }
          };

          let upstream_is_upgrade =
            response_connection_upgrade(upstream_response.headers()).is_some();

          // upgrade accepted
          if upstream_is_upgrade {
            log::debug!("received upgrade response");
            let mut response = hyper::Response::<_>::new(Body::empty());
            *response.version_mut() = request_version;
            *response.status_mut() = upstream_response.status();

            let mut response_headers = upstream_response.headers().clone();
            remove_hop_headers(&mut response_headers);
            response_headers.insert(CONNECTION, CONNECTION_UPGRADE);
            response_headers.insert(SERVER, SERVER_HEADER_VALUE);
            add_headers!(response_headers, config.http.response_headers);
            add_headers!(response_headers, app.response_headers);
            add_headers!(response_headers, handle_response_headers);
            add_headers!(response_headers, upstream.response_headers);
            *response.headers_mut() = response_headers;

            let request_upgrade = hyper::upgrade::on(request);
            let upstream_upgrade = hyper::upgrade::on(upstream_response);

            tokio::spawn(async move {
              let (request_upgrade, upstream_upgrade) =
                match tokio::join!(request_upgrade, upstream_upgrade) {
                  (Ok(request_upgrade), Ok(upstream_upgrade)) => {
                    (request_upgrade, upstream_upgrade)
                  }

                  (Err(client), Err(upstream)) => {
                    log::warn!("error handling upgrade in both: {client} <=> {upstream}");
                    return Err(ProxyHttpError::UpgradeIoBoth { client, upstream });
                  }

                  (Err(e), _) => {
                    log::warn!("error handling upgrade in request: {e}");
                    return Err(ProxyHttpError::UpgradeIoClient(e));
                  }

                  (_, Err(e)) => {
                    log::warn!("error handling upgrade in upstream: {e} - {e:?}");
                    return Err(ProxyHttpError::UpgradeIoUpstream(e));
                  }
                };

              let mut response_io = TokioIo::new(request_upgrade);
              let mut upstream_io = TokioIo::new(upstream_upgrade);
              if let Err(e) =
                tokio::io::copy_bidirectional(&mut response_io, &mut upstream_io).await
              {
                log::warn!("error in copy_bidirectional after upgrade: {e} - {e:?}");
              }
              drop(open_connections_guard);
              Ok::<(), ProxyHttpError>(())
            });

            return Ok(response);

            // upgrade not accepted
          } else {
            log::debug!("received non upgrade response");
            let (
              hyper::http::response::Parts {
                status: upstream_status,
                headers: upstream_headers,
                ..
              },
              upstream_body,
            ) = upstream_response.into_parts();

            #[cfg(any(
              feature = "compression-br",
              feature = "compression-zstd",
              feature = "compression-gzip",
              feature = "compression-deflate"
            ))]
            let (mut response_body, mut response_headers) = compress(
              compression!(),
              compression_content_types!(),
              compression_min_size!(),
              request_accept_encoding.as_ref(),
              upstream_status,
              upstream_body,
              upstream_headers,
            );

            #[cfg(not(any(
              feature = "compression-br",
              feature = "compression-zstd",
              feature = "compression-gzip",
              feature = "compression-deflate"
            )))]
            let (mut response_body, mut response_headers) = {
              let mut response_headers = upstream_headers;
              remove_hop_headers(&mut response_headers);
              (upstream_body, response_headers)
            };

            {
              response_body.on_drop(move || {
                drop(open_connections_guard);
              });
            }

            response_headers.insert(SERVER, SERVER_HEADER_VALUE);

            let mut response = hyper::Response::new(response_body);
            *response.version_mut() = request_version;
            *response.status_mut() = upstream_status;
            *response.headers_mut() = response_headers;
            add_headers!(response.headers_mut(), config.http.response_headers);
            add_headers!(response.headers_mut(), app.response_headers);
            add_headers!(response.headers_mut(), handle_response_headers);
            add_headers!(response.headers_mut(), upstream.response_headers);

            return Ok(response);
          }

          // non upgrade
        } else {
          log::debug!("received non upgrade request");

          let open_connections_guard;

          let upstream_response = if matches!(
            request_method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
          ) && request.body().size_hint().upper() == Some(0)
          {
            let body = Body::empty();
            let mut proxy_request = hyper::Request::new(body);
            *proxy_request.version_mut() = upstream.version.into();
            *proxy_request.method_mut() = proxy_method.clone();
            *proxy_request.uri_mut() = proxy_uri;
            *proxy_request.headers_mut() = proxy_headers.clone();
            add_headers!(proxy_request.headers_mut(), upstream.proxy_headers);

            open_connections_guard =
              increment_open_connections(upstream.state_open_connections.clone());
            match send_request(
              proxy_request,
              proxy_sni,
              upstream.danger_accept_invalid_certs,
              #[cfg(feature = "stats")]
              &upstream.stats_total_read_bytes,
              #[cfg(feature = "stats")]
              &upstream.stats_total_write_bytes,
              Some(read_timeout),
              Some(write_timeout),
              proxy_tcp_nodelay,
              proxy_protocol_config,
            )
            .await
            {
              Ok(response) => {
                upstream.state_health.store(true, Ordering::Relaxed);
                #[cfg(feature = "stats")]
                upstream
                  .stats_total_connections
                  .fetch_add(1, Ordering::Relaxed);
                response
              }
              Err(e) => {
                log::warn!("proxy request error: {e} {e:?}");
                upstream.state_health.store(false, Ordering::Relaxed);
                last_error = Some(e.into());
                root_request = Some(request);
                continue 'upstreams;
              }
            }
          } else {
            let (parts, body) = request.into_parts();

            let mut proxy_request = hyper::Request::new(body);
            *proxy_request.version_mut() = upstream.version.into();
            *proxy_request.method_mut() = proxy_method.clone();
            *proxy_request.uri_mut() = proxy_uri;
            *proxy_request.headers_mut() = proxy_headers.clone();
            add_headers!(proxy_request.headers_mut(), upstream.proxy_headers);

            open_connections_guard =
              increment_open_connections(upstream.state_open_connections.clone());
            match send_request(
              proxy_request,
              proxy_sni,
              upstream.danger_accept_invalid_certs,
              #[cfg(feature = "stats")]
              &upstream.stats_total_read_bytes,
              #[cfg(feature = "stats")]
              &upstream.stats_total_write_bytes,
              Some(read_timeout),
              Some(write_timeout),
              proxy_tcp_nodelay,
              proxy_protocol_config,
            )
            .await
            {
              Ok(response) => {
                upstream.state_health.store(true, Ordering::Relaxed);
                #[cfg(feature = "stats")]
                upstream
                  .stats_total_connections
                  .fetch_add(1, Ordering::Relaxed);
                response
              }
              Err(mut e) => {
                log::warn!("proxy request error: {e} {e:?}");
                upstream.state_health.store(false, Ordering::Relaxed);
                match e.request_mut().take() {
                  Some(proxy_request_ref) => {
                    let mut body = Body::empty();
                    std::mem::swap(&mut body, proxy_request_ref.body_mut());
                    let request = Request::from_parts(parts, body);
                    last_error = Some(e.into());
                    root_request = Some(request);
                    continue 'upstreams;
                  }

                  None => {
                    return Err(e.into());
                  }
                }
              }
            }
          };

          let (
            hyper::http::response::Parts {
              status: upstream_status,
              headers: upstream_headers,
              ..
            },
            upstream_body,
          ) = upstream_response.into_parts();

          let response_status = upstream_status;

          #[cfg(any(
            feature = "compression-br",
            feature = "compression-zstd",
            feature = "compression-gzip",
            feature = "compression-deflate"
          ))]
          let (mut response_body, mut response_headers) = compress(
            compression!(),
            compression_content_types!(),
            compression_min_size!(),
            request_accept_encoding.as_ref(),
            upstream_status,
            upstream_body,
            upstream_headers,
          );

          #[cfg(not(any(
            feature = "compression-br",
            feature = "compression-zstd",
            feature = "compression-gzip",
            feature = "compression-deflate"
          )))]
          let (mut response_body, mut response_headers) = {
            let mut response_headers = upstream_headers;
            remove_hop_headers(&mut response_headers);
            (upstream_body, response_headers)
          };

          response_body.on_drop(move || {
            drop(open_connections_guard);
          });

          response_headers.insert(SERVER, SERVER_HEADER_VALUE);

          let mut response = hyper::Response::new(response_body);
          *response.version_mut() = request_version;
          *response.status_mut() = response_status;
          *response.headers_mut() = response_headers;
          add_headers!(response.headers_mut(), config.http.response_headers);
          add_headers!(response.headers_mut(), app.response_headers);
          add_headers!(response.headers_mut(), handle_response_headers);
          add_headers!(response.headers_mut(), upstream.response_headers);

          return Ok(response);
        }
      }
    }

    let error = last_error.expect("http proxy last_error take");

    Err(error)
  })
  .await;

  #[cfg(feature = "access-log")]
  match &result {
    Ok(response) => {
      use crate::log::{access_log, DisplayHeader, DisplayOption, DisplayPort};
      access_log!(
                "HTTP {remote_addr} => {local_addr} | {method} {scheme}://{host}{port}{path} - {referer} - {user_agent} => {proxied_to} | {status} {status_text} - {content_length} - {ms}ms",
                remote_addr = remote_addr,
                local_addr = local_addr,
                method = request_method,
                scheme = if is_ssl { "https" } else { "http" },
                host = host,
                port = DisplayPort(port),
                path = DisplayOption(request_uri.path_and_query()),
                referer = DisplayHeader(request_referer.as_ref()),
                user_agent = DisplayHeader(request_user_agent.as_ref()),
                proxied_to = proxied_to.as_deref().unwrap_or("None"),
                status = response.status().as_u16(),
                status_text = response.status().canonical_reason().unwrap_or(""),
                content_length = DisplayHeader(
                    response.headers().get(hyper::header::CONTENT_LENGTH)
                ),
                ms = start.elapsed().as_millis()
            );
    }

    Err(e) => {
      use crate::log::{access_log, DisplayHeader, DisplayOption, DisplayPort};
      access_log!(
                "HTTP {remote_addr} => {local_addr} | {method} {scheme}://{host}{port}{path} - {referer} - {user_agent} => {proxied_to} | ERROR {error} - {error:?} - {ms}ms",
                remote_addr = remote_addr,
                local_addr = local_addr,
                method = request_method,
                scheme = if is_ssl { "https" } else { "http" },
                host = host,
                port = DisplayPort(port),
                path = DisplayOption(request_uri.path_and_query()),
                referer = DisplayHeader(request_referer.as_ref()),
                user_agent = DisplayHeader(request_user_agent.as_ref()),
                proxied_to = proxied_to.as_deref().unwrap_or("None"),
                error = e,
                ms = start.elapsed().as_millis()
            );
    }
  }

  result
}

pub async fn serve_stream_proxy<S: AsyncWrite + AsyncRead + Unpin>(
  stream: S,
  local_addr: SocketAddr,
  remote_addr: SocketAddr,
  is_ssl: bool,
  proxy_header: Option<ProxyHeader>,
  config: &Config,
) -> Result<(), ProxyStreamError> {
  let app = 'resolve: {
    for app in &config.stream.apps {
      for listen in &app.listen {
        if listen.addr.matches_addr(local_addr) && listen.ssl.is_some() == is_ssl {
          break 'resolve app;
        }
      }
    }

    return Err(ProxyStreamError::UnresolvableUpstream);
  };

  let (
    upstreams,
    handle_balance,
    handle_stream_retries,
    handle_stream_retry_backoff,
    handle_proxy_protocol_write_timeout,
    handle_proxy_read_timeout,
    handle_proxy_write_timeout,
    handle_proxy_tcp_nodelay,
  ) = match &app.handle {
    StreamHandle::Proxy {
      balance,
      upstream,
      retries: stream_retries,
      retry_backoff: stream_retry_backoff,
      proxy_protocol_write_timeout,
      proxy_read_timeout,
      proxy_write_timeout,
      proxy_tcp_nodelay,
    } => (
      upstream,
      *balance,
      *stream_retries,
      *stream_retry_backoff,
      *proxy_protocol_write_timeout,
      *proxy_read_timeout,
      *proxy_write_timeout,
      *proxy_tcp_nodelay,
    ),
  };

  let mut last_error: Option<ProxyStreamError> = None;

  let retries = crate::option!(
    handle_stream_retries,
    config.stream.retries,
    => DEFAULT_STREAM_PROXY_RETRIES
  );

  let backoff = crate::option!(
    handle_stream_retry_backoff,
    config.stream.retry_backoff,
    => DEFAULT_STREAM_RETRY_BACKOFF
  );

  let balance = crate::option!(
    handle_balance,
    config.stream.balance,
    => DEFAULT_STREAM_BALANCE
  );

  let server_read_timeout = crate::option!(
    @timeout
    app.server_read_timeout,
    config.stream.server_read_timeout,
    => DEFAULT_STREAM_SERVER_READ_TIMEOUT
  );

  let server_write_timeout = crate::option!(
    @timeout
    app.server_write_timeout,
    config.stream.server_write_timeout,
    => DEFAULT_STREAM_SERVER_WRITE_TIMEOUT
  );

  let io = TimeoutIo::new(stream, server_read_timeout, server_write_timeout);
  tokio::pin!(io);

  for i in 0..=retries {
    if i != 0 {
      tokio::time::sleep(backoff.duration_for(i - 1)).await;
    }

    let sorted_upstreams = crate::proxy::balance::balance_sort(
      upstreams,
      balance,
      remote_addr.ip(),
      &app.state_round_robin_index,
    );

    'upstreams: for upstream in sorted_upstreams {
      match upstream.origin.scheme() {
        "tcp" | "ssl" | "tls" => {
          let domain = match upstream.origin.domain() {
            Some(domain) => domain,
            None => {
              return Err(ProxyStreamError::UrlMissingDomain);
            }
          };

          let port = match upstream.origin.port() {
            Some(port) => port,
            None => {
              return Err(ProxyStreamError::UrlMissingPort);
            }
          };

          let proxy_read_timeout = crate::option!(
            @timeout
            upstream.proxy_read_timeout,
            handle_proxy_read_timeout,
            app.proxy_read_timeout,
            config.stream.proxy_read_timeout
            => DEFAULT_STREAM_PROXY_READ_TIMEOUT
          );

          let proxy_write_timeout = crate::option!(
            @timeout
            upstream.proxy_write_timeout,
            handle_proxy_write_timeout,
            app.proxy_write_timeout,
            config.stream.proxy_write_timeout
            => DEFAULT_STREAM_PROXY_WRITE_TIMEOUT
          );

          let proxy_tcp_nodelay = crate::option!(
            upstream.proxy_tcp_nodelay,
            handle_proxy_tcp_nodelay,
            app.proxy_tcp_nodelay,
            config.stream.proxy_tcp_nodelay,
            config.proxy_tcp_nodelay,
            => DEFAULT_PROXY_TCP_NODELAY
          );

          // unwrap: upstream origin host is checked at construction
          let connect = match upstream.origin.host().unwrap() {
            Host::Domain(domain) => TcpStream::connect((domain, port)).await,
            Host::Ipv4(ipv4) => TcpStream::connect((ipv4, port)).await,
            Host::Ipv6(ipv6) => TcpStream::connect((ipv6, port)).await,
          };

          let proxy_stream = match connect {
            Ok(stream) => {
              #[cfg(feature = "stats")]
              upstream
                .stats_total_connections
                .fetch_add(1, Ordering::Relaxed);
              stream
            }
            Err(e) => {
              last_error = Some(ProxyStreamError::TcpConnect(e));
              continue 'upstreams;
            }
          };

          if proxy_tcp_nodelay {
            proxy_stream
              .set_nodelay(true)
              .map_err(ProxyStreamError::SetTcpNoDelay)?;
          }

          #[cfg(feature = "stats")]
          let mut proxy_stream = CountersIo::new(
            proxy_stream,
            upstream.stats_total_read_bytes.clone(),
            upstream.stats_total_write_bytes.clone(),
          );

          #[cfg(not(feature = "stats"))]
          let mut proxy_stream = proxy_stream;

          if let Some(version) = upstream.send_proxy_protocol {
            let timeout = crate::option!(
              @timeout
              upstream.proxy_protocol_write_timeout,
              handle_proxy_protocol_write_timeout,
              config.stream.proxy_protocol_write_timeout,
              config.proxy_protocol_write_timeout,
              => DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT
            );

            let header = match &proxy_header {
              Some(header) => header.clone(),
              None => match ProxyHeader::try_from((remote_addr, local_addr)) {
                Ok(header) => header,
                Err(_) => ProxyHeader::Unknown,
              },
            };

            let buf = crate::proxy_protocol::encode(&header, version)
              .map_err(ProxyStreamError::ProxyProtocolEncode)?;

            proxy_stream
              .write_all(&buf)
              .timeout(timeout)
              .await
              .map_err(|_| ProxyStreamError::ProxyProtocolWriteTimeout)?
              .map_err(ProxyStreamError::ProxyProtocolWrite)?;
          };

          match upstream.origin.scheme() {
            "tcp" => {
              let proxy_io = TimeoutIo::new(proxy_stream, proxy_read_timeout, proxy_write_timeout);
              tokio::pin!(proxy_io);

              let open_connections_guard =
                increment_open_connections(upstream.state_open_connections.clone());

              let r = copy(&mut io, &mut proxy_io).await;
              drop(open_connections_guard);
              return r;
            }

            "ssl" | "tls" => {
              let server_name = match &upstream.sni {
                Some(sni) => sni.0.clone(),
                None => ServerName::try_from(domain.to_owned())?,
              };

              let tls_connector = match upstream.danger_accept_invalid_certs {
                true => {
                  #[dynamic]
                  static DANGER_TLS_NO_CERT_VERFIER_CONNECTOR: tokio_rustls::TlsConnector = {
                    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                      crate::tls::crypto::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .expect("cannot build tls client config with default protocol versions")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DangerNoCertVerifier))
                    .with_no_client_auth();

                    config.enable_sni = true;
                    tokio_rustls::TlsConnector::from(Arc::new(config))
                  };

                  &*DANGER_TLS_NO_CERT_VERFIER_CONNECTOR
                }

                false => {
                  #[dynamic]
                  static TLS_CONNECTOR: tokio_rustls::TlsConnector = {
                    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                      crate::tls::crypto::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .expect("cannot build tls client config with default protocol versions")
                    .with_native_roots()
                    .expect("cannot build tls client config with native roots")
                    .with_no_client_auth();

                    tokio_rustls::TlsConnector::from(Arc::new(config))
                  };

                  &*TLS_CONNECTOR
                }
              };

              let open_connections_guard =
                increment_open_connections(upstream.state_open_connections.clone());

              let tls_stream = match tls_connector.connect(server_name, proxy_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                  last_error = Some(ProxyStreamError::TlsConnect(e));
                  continue 'upstreams;
                }
              };

              let proxy_io = TimeoutIo::new(tls_stream, proxy_read_timeout, proxy_write_timeout);
              tokio::pin!(proxy_io);

              let r = copy(&mut io, &mut proxy_io).await;

              drop(open_connections_guard);

              return r;
            }

            _ => unreachable!(),
          }
        }

        other => {
          return Err(ProxyStreamError::UnsupportedScheme(other.to_string()));
        }
      }
    }
  }

  let error = last_error.expect("stream proxy last_error take");

  Err(error)
}

async fn copy<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
  a: &mut A,
  b: &mut B,
) -> Result<(), ProxyStreamError> {
  match tokio::io::copy_bidirectional(a, b).await {
    Ok(_) => Ok(()),
    Err(e) => Err(ProxyStreamError::Copy(e)),
  }
}

#[derive(Debug, Clone)]
pub struct ProxyHttpService {
  inner: ProxyServiceInner,
  remote_addr: SocketAddr,
  proxy_header: Option<ProxyHeader>,
}

impl Deref for ProxyHttpService {
  type Target = ProxyServiceInner;
  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

#[derive(Debug, Clone)]
pub struct ProxyServiceInner {
  pub config: Arc<Config>,
  pub addr: SocketAddr,
  pub ssl: bool,
}

impl ProxyHttpService {
  pub fn new(
    inner: ProxyServiceInner,
    remote_addr: SocketAddr,
    proxy_header: Option<ProxyHeader>,
  ) -> Self {
    Self {
      inner,
      remote_addr,
      proxy_header,
    }
  }
}

impl Service<Request<Incoming>> for ProxyHttpService {
  type Response = Response<Body>;
  type Error = Infallible;
  type Future = ServiceFuture<Result<Self::Response, Self::Error>>;

  fn call(&self, req: Request<Incoming>) -> Self::Future {
    let me = self.clone();
    // we spawn here to avoid cancellation
    // this has almost no impact on performance and help to the predictability of the service as it avoids cancellations
    let handle = tokio::spawn(async move {
      match serve_proxy(
        req,
        &me.config,
        me.addr,
        me.remote_addr,
        me.proxy_header.clone(),
        me.ssl,
      )
      .await
      {
        Ok(response) => Ok(response),
        Err(e) => {
          log::warn!("proxy ended with error: {e}");
          Ok(e.to_response())
        }
      }
    });

    ServiceFuture { inner: handle }
  }
}

pub struct ProxyStreamService {
  config: Arc<Config>,
}

impl ProxyStreamService {
  pub fn new(config: Arc<Config>) -> Self {
    Self { config }
  }
}

impl<S: AsyncWrite + AsyncRead + Unpin + Send + 'static> StreamService<S> for ProxyStreamService {
  type Future = ServiceFuture<Result<(), ProxyStreamError>>;
  type Error = ProxyStreamError;

  fn serve(&self, connection: Connection<S>) -> Self::Future {
    let Connection {
      stream,
      local_addr,
      remote_addr,
      proxy_header,
      is_ssl,
    } = connection;

    let config = self.config.clone();

    let handle = tokio::spawn(async move {
      serve_stream_proxy(
        stream,
        local_addr,
        remote_addr,
        is_ssl,
        proxy_header,
        &config,
      )
      .await
    });

    ServiceFuture { inner: handle }
  }
}

#[pin_project]
pub struct ServiceFuture<O> {
  #[pin]
  inner: JoinHandle<O>,
}

impl<O> Future for ServiceFuture<O> {
  type Output = O;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match self.project().inner.poll(cx) {
      Poll::Ready(o) => Poll::Ready(o.unwrap()),
      Poll::Pending => Poll::Pending,
    }
  }
}

pub struct ProxyAddrService {
  inner: ProxyServiceInner,
}

impl ProxyAddrService {
  pub fn new(inner: ProxyServiceInner) -> Self {
    Self { inner }
  }
}

impl AddrService<ProxyHttpService> for ProxyAddrService {
  fn make_service(&self, addr: SocketAddr, proxy_header: Option<ProxyHeader>) -> ProxyHttpService {
    ProxyHttpService::new(self.inner.clone(), addr, proxy_header)
  }
}
