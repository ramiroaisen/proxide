use hyper::{
  body::{Body, Incoming},
  service::{HttpService, Service},
  Request, Response,
};
use hyper_util::{
  rt::{TokioExecutor, TokioIo /*TokioTimer*/},
  server::conn::auto,
};
use indexmap::IndexSet;
use parking_lot::Mutex;
use quinn::crypto::rustls::NoInitialCipherSuite;
use rustls::ServerConfig;
use std::future::Future;
use std::{
  fmt::Display,
  net::{IpAddr, SocketAddr},
  sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  },
  time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::time::FutureExt;

use crate::{
  graceful::GracefulGuard,
  net::timeout::TimeoutIo,
  proxy::service::{HttpConnectionKind, MakeHttpService},
  proxy_protocol::{ExpectProxyProtocol, ProxyHeader},
  service::{Connection, StreamService},
};

#[cfg(feature = "h3")]
use futures_util::stream::StreamExt;
#[cfg(feature = "h3")]
use h3_quinn;
#[cfg(feature = "h3")]
use h3_quinn::quinn::{Endpoint, TransportConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnectionKind {
  Http,
  Https,
  #[cfg(feature = "h3")]
  H3,
  Ssl,
  Tcp,
}

impl Display for ConnectionKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ConnectionKind::Http => write!(f, "http"),
      ConnectionKind::Https => write!(f, "https"),
      #[cfg(feature = "h3")]
      ConnectionKind::H3 => write!(f, "h3"),
      ConnectionKind::Ssl => write!(f, "ssl"),
      ConnectionKind::Tcp => write!(f, "tcp"),
    }
  }
}

static CONNECTION_UID: AtomicUsize = AtomicUsize::new(0);

#[static_init::dynamic]
static CONNECTIONS: Mutex<IndexSet<ConnectionItem>> = Mutex::new(IndexSet::new());

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionItem {
  uid: usize,
  ip: IpAddr,
  kind: ConnectionKind,
  since: Instant,
}

impl ConnectionItem {
  fn new(ip: IpAddr, kind: ConnectionKind) -> Self {
    Self {
      uid: CONNECTION_UID.fetch_add(1, Ordering::AcqRel),
      ip,
      kind,
      since: Instant::now(),
    }
  }
}

pub struct ConnectionItemGuard(ConnectionItem);

impl Drop for ConnectionItemGuard {
  fn drop(&mut self) {
    connection_end(&self.0);
  }
}

#[must_use = "connection start returns a drop guard"]
pub fn connection_start(connection: ConnectionItem) -> ConnectionItemGuard {
  CONNECTIONS.lock().insert(connection);
  ConnectionItemGuard(connection)
}

fn connection_end(connection: &ConnectionItem) {
  // shift remove does not perturb the natural order of the elements
  CONNECTIONS.lock().shift_remove(connection);
}

#[cfg(feature = "log-state")]
pub fn log_ip_connections() {
  let connections = CONNECTIONS.lock();
  let mut total_https = 0;
  let mut total_http = 0;
  #[cfg(feature = "h3")]
  let mut total_h3 = 0;
  let mut total_ssl = 0;
  let mut total_tcp = 0;
  for connection in connections.iter() {
    match connection.kind {
      ConnectionKind::Http => total_http += 1,
      ConnectionKind::Https => total_https += 1,
      #[cfg(feature = "h3")]
      ConnectionKind::H3 => total_h3 += 1,
      ConnectionKind::Ssl => total_ssl += 1,
      ConnectionKind::Tcp => total_tcp += 1,
    }
  }

  log::info!(
    #[cfg(feature = "h3")]
    "= server connections - https: {} -  http: {} - h3: {} - ssl: {} - tcp: {} | total: {} =",
    #[cfg(not(feature = "h3"))]
    "= server connections - https: {} -  http: {} - ssl: {} - tcp: {} | total: {} =",
    total_https,
    total_http,
    #[cfg(feature = "h3")]
    total_h3,
    total_ssl,
    total_tcp,
    #[cfg(feature = "h3")]
    total_https + total_http + total_h3 + total_ssl + total_tcp
    #[cfg(not(feature = "h3"))]
    total_https + total_http + total_ssl + total_tcp
  );

  for ConnectionItem {
    ip, kind, since, ..
  } in connections.iter()
  {
    log::info!(
      "{ip} {kind} {elapsed}",
      elapsed = crate::log::DisplayDuration(since.elapsed())
    );
  }
}

fn server() -> auto::Builder<TokioExecutor> {
  // let mut server = auto::Builder::new(TokioExecutor::new());
  // let mut h2 = server.http2();
  // h2.timer(TokioTimer::new());
  // h2.keep_alive_interval(Duration::from_secs(10));
  // h2.keep_alive_timeout(Duration::from_secs(60));
  // server
  auto::Builder::new(TokioExecutor::new())
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_http<M, S, B, Sig>(
  local_addr: SocketAddr,
  tcp: TcpListener,
  make_service: M,
  signal: Sig,
  read_timeout: Duration,
  write_timeout: Duration,
  graceful_shutdown_timeout: Option<Duration>,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  proxy_protocol_read_timeout: Duration,
) where
  M: MakeHttpService<Service = S>,
  S: Clone,
  S: Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
  <S as Service<Request<Incoming>>>::Future: Send + 'static,
  <S as Service<Request<Incoming>>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  S: HttpService<Incoming, ResBody = B>,
  <S as HttpService<Incoming>>::Future: Send + 'static,
  <S as HttpService<Incoming>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  B: Body + Send + 'static,
  B::Data: Send,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  Sig: Future<Output = ()>,
{
  tokio::pin!(signal);

  let graceful = crate::graceful::GracefulShutdown::new();

  let http = server();

  let (conn_sender, conn_recv) =
    kanal::bounded_async::<(GracefulGuard<TcpStream>, SocketAddr, Option<ProxyHeader>)>(0);

  let accept_task = {
    let graceful = graceful.clone();
    async move {
      loop {
        tokio::select! {
          accept = tcp.accept() => {
            let (stream, remote_addr) = match accept {
              Ok(accept) => accept,
              Err(e) => {
                log::error!("error accepting tcp stream (tcp) - sleeping for 1 second: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
              }
            };

            #[cfg(feature = "server-tcp-nodelay")]
            if let Err(e) = stream.set_nodelay(true) {
              log::warn!("error setting tcp stream nodelay: {e}");
            }

            let mut stream = graceful.guard(stream);

            let conn_sender = conn_sender.clone();

            tokio::spawn(async move {

              let proxy_header: Option<ProxyHeader>;

              if let Some(expect_proxy_protocol) = expect_proxy_protocol {
                let header = match crate::proxy_protocol::read(&mut stream, expect_proxy_protocol)
                  .timeout(proxy_protocol_read_timeout)
                  .await
                {
                  Ok(Ok(header)) => header,
                  Ok(Err(e)) => {
                    log::warn!("error reading proxy protocol header(1): {e}");
                    return;
                  }
                  Err(_) => {
                    log::warn!("error reading proxy protocol(1): timeout after {proxy_protocol_read_timeout:?}");
                    return;
                  }
                };

                proxy_header = Some(header);
              } else {
                proxy_header = None;
              };

              let _ = conn_sender.send((
                stream,
                remote_addr,
                proxy_header,
              )).await;
            });
          },

          _ = &mut signal => {
            break;
          }
        };
      }

      drop(tcp);
    }
  };

  let connection_task = async move {
    loop {
      let (stream, remote_addr, proxy_header) = match conn_recv.recv().await {
        Ok(conn) => conn,
        Err(_) => break,
      };

      // no need to graceful.guard() here as it is already guarded after the accept
      let io = Box::pin(TokioIo::new(TimeoutIo::new(
        stream,
        read_timeout,
        write_timeout,
      )));

      let service = make_service.make_service(
        local_addr,
        remote_addr,
        HttpConnectionKind::Http,
        proxy_header,
      );
      let conn = http
        .serve_connection_with_upgrades(io, service)
        .into_owned();
      let watched = graceful.watch(conn);

      let connection = ConnectionItem::new(remote_addr.ip(), ConnectionKind::Http);

      let guard = connection_start(connection);
      tokio::spawn(async move {
        if let Err(e) = watched.await {
          log::warn!("error handling http connection - {e}: {e:?}");
        }
        drop(guard);
      });
    }

    if let Some(timeout) = graceful_shutdown_timeout {
      if graceful.shutdown().timeout(timeout).await.is_err() {
        log::info!(
          "graceful shutdown timeout ({}s) reached for http server",
          timeout.as_secs()
        );
      };
    } else {
      graceful.shutdown().await;
    }
  };

  tokio::join!(accept_task, connection_task);
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_https<M, S, B, Sig>(
  local_addr: SocketAddr,
  tcp: TcpListener,
  tls_config: Arc<ServerConfig>,
  make_service: M,
  signal: Sig,
  read_timeout: Duration,
  write_timeout: Duration,
  graceful_shutdown_timeout: Option<Duration>,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  proxy_protocol_read_timeout: Duration,
) where
  M: MakeHttpService<Service = S>,
  S: Clone,
  S: Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
  <S as Service<Request<Incoming>>>::Future: Send + 'static,
  <S as Service<Request<Incoming>>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  S: HttpService<Incoming, ResBody = B>,
  <S as HttpService<Incoming>>::Future: Send + 'static,
  <S as HttpService<Incoming>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  B: Body + Send + 'static,
  B::Data: Send,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  Sig: Future<Output = ()>,
{
  let tls_acceptor = TlsAcceptor::from(tls_config);

  let graceful = crate::graceful::GracefulShutdown::new();

  tokio::pin!(signal);

  let (conn_sender, conn_recv) = kanal::bounded_async::<(
    TlsStream<GracefulGuard<TcpStream>>,
    SocketAddr,
    Option<ProxyHeader>,
  )>(0);

  let accept_task = {
    let graceful = graceful.clone();
    async move {
      loop {
        tokio::select! {
          accept = tcp.accept() => {
            let (tcp_stream, remote_addr) = match accept {
              Ok(accept) => accept,
              Err(e) => {
                log::error!("error accepting tcp stream in https mode - sleeping for 1 second: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
              }
            };

            #[cfg(feature = "server-tcp-nodelay")]
            if let Err(e) = tcp_stream.set_nodelay(true) {
              log::warn!("error setting tcp stream nodelay: {e}");
            }

            let tls_acceptor = tls_acceptor.clone();
            let conn_sender = conn_sender.clone();

            let mut stream = graceful.guard(tcp_stream);

            tokio::spawn(async move {

              let proxy_header = match expect_proxy_protocol {
                None => None,
                Some(version) => match crate::proxy_protocol::read(&mut stream, version).timeout(proxy_protocol_read_timeout).await {
                  Ok(Ok(header)) => Some(header),
                  Ok(Err(e)) => {
                    log::warn!("error reading proxy protocol: {e}");
                    return;
                  }
                  Err(_) => {
                    log::warn!("error reading proxy protocol: timeout after {proxy_protocol_read_timeout:?}");
                    return;
                  }
                }
              };

              let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                  log::warn!("error accepting https connection: {e} - {e:?}");
                  return;
                }
              };

              let _ = conn_sender.send((tls_stream, remote_addr, proxy_header)).await;
            });
          },

          _ = &mut signal => {
            break;
          }
        }
      }

      drop(tcp);
    }
  };

  let connection_task = async move {
    let http = server();

    loop {
      let (tls_stream, remote_addr, proxy_header) = match conn_recv.recv().await {
        Ok(tls_stream) => tls_stream,
        Err(_) => break,
      };

      // no need to graceful.guard() here as it is already guarded after the accept
      let io = Box::pin(TokioIo::new(TimeoutIo::new(
        tls_stream,
        read_timeout,
        write_timeout,
      )));

      let service = make_service.make_service(
        local_addr,
        remote_addr,
        HttpConnectionKind::Https,
        proxy_header,
      );
      let conn = http
        .serve_connection_with_upgrades(io, service)
        .into_owned();

      let watched = graceful.watch(conn);

      let connection = ConnectionItem::new(remote_addr.ip(), ConnectionKind::Https);

      let guard = connection_start(connection);
      tokio::spawn(async move {
        if let Err(e) = watched.await {
          log::warn!("error handling https connection - {e}: {e:?}");
        }
        drop(guard);
      });
    }

    if let Some(timeout) = graceful_shutdown_timeout {
      if graceful.shutdown().timeout(timeout).await.is_err() {
        log::info!(
          "graceful shutdown timeout ({}s) reached for https server",
          timeout.as_secs()
        );
      };
    } else {
      graceful.shutdown().await;
    }
  };

  tokio::join!(connection_task, accept_task);
}

#[derive(Debug, thiserror::Error)]
pub enum H3ServeError {
  #[error("failed to convert rustls ServerConfig to quinn::crypto::rustls::QuicServerConfig: {0}")]
  QuicConfigFrom(#[from] NoInitialCipherSuite),

  #[error("failed to bind QUIC endpoint: {0}")]
  EndpointBind(#[source] std::io::Error),
}

#[cfg(feature = "h3")]
#[allow(clippy::too_many_arguments)]
pub async fn serve_h3<M, S, B, Sig>(
  local_addr: SocketAddr,
  tls_config: Arc<ServerConfig>,
  make_service: M,
  signal: Sig,
  graceful_shutdown_timeout: Option<Duration>,
) -> Result<(), H3ServeError>
where
  M: MakeHttpService<Service = S> + Clone + Send + 'static,
  S: Clone + Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
  <S as Service<Request<Incoming>>>::Future: Send + 'static,
  <S as Service<Request<Incoming>>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  S: HttpService<Incoming, ResBody = B>,
  <S as HttpService<Incoming>>::Future: Send + 'static,
  <S as HttpService<Incoming>>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  B: Body + Send + 'static,
  B::Data: Send,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  Sig: Future<Output = ()>,
{
  // Build QUIC endpoint from rustls ServerConfig

  let mut transport = TransportConfig::default();
  let mut server_cfg = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
  ));

  server_cfg.transport = Arc::new(transport);

  let endpoint = h3_quinn::quinn::Endpoint::server(server_cfg, local_addr)
    .map_err(H3ServeError::EndpointBind)?;

  tokio::pin!(signal);

  loop {
    use bytes::Bytes;

    tokio::select! {
      incomming = endpoint.accept() => {
        if let Some(conn_fut) = incomming {
          let remote_addr = conn_fut.remote_address();
          let make_service = make_service.clone();
          tokio::spawn(async move {
            match conn_fut.await {
              Ok(conn) => {
                let mut h3_conn = match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await {
                  Ok(conn) => conn,
                  Err(err) => {
                    log::warn!("error creating h3 connection: {err} - {err:?}");
                    return;
                  }
                };

                loop {
                  match h3_conn.accept().await {
                    Ok(Some(resolver)) => {
                      let make_service = make_service.clone();
                      tokio::spawn(async move {
                        let (req, mut stream) = match resolver.resolve_request().await {
                          Ok(req) => req,
                          Err(err) => {
                            log::warn!("error resolving h3 request: {err} - {err:?}");
                            return;
                          }
                        };

                        let service = make_service.make_service(
                          local_addr,
                          remote_addr,
                          HttpConnectionKind::H3,
                          None,
                        );

                        let res = service.call(req).await;
                      });
                    }
                    // Connection closed
                    Ok(None) => break,
                    // Error accepting request
                    Err(err) => {
                      log::warn!("error accepting h3 request: {err} - {err:?}");
                      break;
                    }
                  }
                }
              }
              Err(err) => {
                log::warn!("failed establishing quic connection: {err:?}");
              }
            }
          });
        } else {
          // Endpoint is closed
          break;
        }
      }

      _ = &mut signal => break,
    }
  }

  if let Some(timeout) = graceful_shutdown_timeout {
    tokio::select! {
      _ = tokio::time::sleep(timeout) => {
        log::info!("graceful shutdown timeout ({}s) reached for h3 server", timeout.as_secs());
      }

      _ = endpoint.wait_idle() => {
        log::info!("h3 server endpoint is idle, shutting down");
      }
    }
  }

  Ok(())
}

pub async fn serve_tcp<S, Sig>(
  local_addr: SocketAddr,
  tcp: TcpListener,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  service: S,
  signal: Sig,
  graceful_shutdown_timeout: Option<Duration>,
  proxy_protocol_read_timeout: Duration,
) where
  S: StreamService<GracefulGuard<TcpStream>>,
  S::Error: std::error::Error,
  S::Future: Send + 'static,
  Sig: Future<Output = ()>,
{
  tokio::pin!(signal);

  let graceful = crate::graceful::GracefulShutdown::new();

  {
    let graceful = graceful.clone();
    async move {
      loop {
        tokio::select! {
          accept = tcp.accept() => {
            let (stream, remote_addr) = match accept {
              Ok(accept) => accept,
              Err(e) => {
                log::error!("error accepting tcp stream in tcp mode - sleeping for 1 second: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
              }
            };

            macro_rules! serve {
              ($stream:expr, $proxy_header:expr) => {{
                let fut = service.serve(Connection { stream: $stream, proxy_header: $proxy_header, remote_addr, local_addr, is_ssl: false });

                let connection = ConnectionItem::new(remote_addr.ip(), ConnectionKind::Tcp);
                let guard = connection_start(connection);

                tokio::spawn(async move {
                  if let Err(e) = fut.await {
                    log::warn!("error handling tcp connection - {e}: {e:?}");
                  }
                  drop(guard);
                });
              }}
            }

            let mut graceful_stream = graceful.guard(stream);
            match expect_proxy_protocol {
              None => serve!(graceful_stream, None),
              Some(version) => {
                let header = match crate::proxy_protocol::read(&mut graceful_stream, version).timeout(proxy_protocol_read_timeout).await {
                  Ok(Ok(header)) => header,
                  Ok(Err(e)) => {
                    log::warn!("error reading proxy protocol header(2): {e}");
                    continue;
                  }
                  Err(_) => {
                    log::warn!("error reading proxy protocol(2): timeout after {proxy_protocol_read_timeout:?}");
                    continue;
                  }
                };

                serve!(graceful_stream, Some(header))
              }
            }
          }

          _ = &mut signal => {
            break;
          }
        }
      }

      drop(tcp);
    }.await;
  };

  if let Some(timeout) = graceful_shutdown_timeout {
    if graceful.shutdown().timeout(timeout).await.is_err() {
      log::info!(
        "graceful shutdown timeout ({}s) reached for stream tcp server at {}",
        timeout.as_secs(),
        local_addr
      );
    };
  } else {
    graceful.shutdown().await;
  }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_ssl<S, Sig>(
  local_addr: SocketAddr,
  tcp: TcpListener,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  config: Arc<ServerConfig>,
  service: S,
  signal: Sig,
  graceful_shutdown_timeout: Option<Duration>,
  proxy_protocol_read_timeout: Duration,
) where
  S: StreamService<GracefulGuard<TlsStream<TcpStream>>>,
  S::Error: std::error::Error,
  S::Future: Send + 'static,
  Sig: Future<Output = ()>,
{
  tokio::pin!(signal);

  let (conn_sender, conn_recv) =
    kanal::bounded_async::<(TlsStream<TcpStream>, SocketAddr, Option<ProxyHeader>)>(0);

  let tls_acceptor = TlsAcceptor::from(config);

  let accept_task = async move {
    loop {
      tokio::select! {
        accept = tcp.accept() => {
          let (mut tcp_stream, remote_addr) = match accept {
            Ok(accept) => accept,
            Err(e) => {
              log::error!("error accepting tcp stream in ssl mode - sleeping for 1 second: {e}");
              tokio::time::sleep(Duration::from_secs(1)).await;
              continue;
            }
          };

          let tls_acceptor = tls_acceptor.clone();
          let conn_sender = conn_sender.clone();

          tokio::spawn(async move {
            let proxy_header = match expect_proxy_protocol {
              None => None,
              Some(version) => match crate::proxy_protocol::read(&mut tcp_stream, version).timeout(proxy_protocol_read_timeout).await {
                Ok(Ok(header)) => Some(header),
                Ok(Err(e)) => {
                  log::warn!("(error reading proxy protocol header(3): {e}");
                  return;
                }
                Err(_) => {
                  log::warn!("error reading proxy protocol(3): timeout after {proxy_protocol_read_timeout:?}");
                  return;
                }
              }
            };

            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
              Ok(tls_stream) => tls_stream,
              Err(e) => {
                log::warn!("error accepting tls stream: {e}");
                return;
              }
            };

            let _ = conn_sender.send((tls_stream, remote_addr, proxy_header)).await;
          });
        }

        _ = &mut signal => break,
      }
    }

    drop(tcp);
  };

  let handle_task = async move {
    let graceful = crate::graceful::GracefulShutdown::new();

    while let Ok((stream, remote_addr, proxy_header)) = conn_recv.recv().await {
      let graceful_stream = graceful.guard(stream);

      let fut = service.serve(Connection {
        stream: graceful_stream,
        proxy_header,
        remote_addr,
        local_addr,
        is_ssl: true,
      });

      let connection = ConnectionItem::new(remote_addr.ip(), ConnectionKind::Ssl);
      let guard = connection_start(connection);

      tokio::spawn(async move {
        if let Err(e) = fut.await {
          log::warn!("error handling tcp connection - {e}: {e:?}");
        }
        drop(guard);
      });
    }

    if let Some(timeout) = graceful_shutdown_timeout {
      if graceful.shutdown().timeout(timeout).await.is_err() {
        log::info!(
          "graceful shutdown timeout ({}s) reached for stream ssl server at {}",
          timeout.as_secs(),
          local_addr
        );
      };
    } else {
      graceful.shutdown().await;
    }
  };

  tokio::join!(accept_task, handle_task);
}
