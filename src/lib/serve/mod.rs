use hyper::{body::Incoming, Request, Response};
use hyper_util::{
  rt::{TokioExecutor, TokioIo},
  server::conn::auto,
};
use indexmap::IndexSet;
use parking_lot::Mutex;
use rustls::ServerConfig;
use std::{convert::Infallible, future::Future};
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
use tokio_rustls::{server::TlsStream, LazyConfigAcceptor, TlsAcceptor};
use tokio_util::{sync::CancellationToken, time::FutureExt};

fn service_fn<F, Fut>(f: F) -> ServiceFn<F>
where
  F: FnOnce(Request<Incoming>) -> Fut,
  F: Clone,
  Fut: Future<Output = Result<Response<crate::body::Body>, Infallible>>,
{
  ServiceFn { f }
}
struct ServiceFn<F> {
  f: F,
}

impl<F, Fut> hyper::service::Service<Request<Incoming>> for ServiceFn<F>
where
  F: FnOnce(Request<Incoming>) -> Fut,
  F: Clone,
  Fut: Future<Output = Result<Response<crate::body::Body>, Infallible>>,
{
  type Response = Response<crate::body::Body>;
  type Error = Infallible;
  type Future = Fut;

  fn call(&self, req: Request<Incoming>) -> Self::Future {
    (self.f.clone())(req)
  }
}

use crate::{
  body::map_request_body,
  config::Config,
  graceful::GracefulGuard,
  net::timeout::TimeoutIo,
  proxy::service::{serve_proxy, serve_stream_proxy, HttpBindKind},
  proxy_protocol::{ExpectProxyProtocol, ProxyHeader},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnectionKind {
  Http,
  Https,
  Ssl,
  Tcp,
}

impl Display for ConnectionKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ConnectionKind::Http => write!(f, "http"),
      ConnectionKind::Https => write!(f, "https"),
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
      uid: CONNECTION_UID.fetch_add(1, Ordering::Release),
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
  let mut total_ssl = 0;
  let mut total_tcp = 0;
  for connection in connections.iter() {
    match connection.kind {
      ConnectionKind::Http => total_http += 1,
      ConnectionKind::Https => total_https += 1,
      ConnectionKind::Ssl => total_ssl += 1,
      ConnectionKind::Tcp => total_tcp += 1,
    }
  }

  log::info!(
    "= server connections - https: {} -  http: {} - ssl: {} - tcp: {} | total: {} =",
    total_https,
    total_http,
    total_ssl,
    total_tcp,
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
pub async fn serve_http(
  config: Arc<Config>,
  local_addr: SocketAddr,
  tcp: TcpListener,
  cancel: CancellationToken,
  read_timeout: Duration,
  write_timeout: Duration,
  graceful_shutdown_timeout: Option<Duration>,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  proxy_protocol_read_timeout: Duration,
) {
  let graceful = crate::graceful::GracefulShutdown::new();

  let http = server();

  let (conn_sender, conn_recv) =
    kanal::bounded_async::<(GracefulGuard<TcpStream>, SocketAddr, Option<ProxyHeader>)>(0);

  let accept_task = {
    let graceful = graceful.clone();

    async move {
      let cancelled = cancel.cancelled();
      tokio::pin!(cancelled);

      loop {
        tokio::select! {
          accept = tcp.accept() => {
            let (stream, remote_addr) = match accept {
              Ok(accept) => accept,
              Err(e) => {
                log::error!("error accepting tcp stream (tcp) {e}, panicking");
                panic!("error accepting tcp stream (tcp) {e}");
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

          _ = &mut cancelled => {
            break;
          }
        };
      }

      drop(tcp);
    }
  };

  let connection_task = async move {
    loop {
      let config = config.clone();
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

      let service = service_fn(move |req| async move {
        let req: Request<crate::body::Body> =
          map_request_body(req, |incoming: Incoming| incoming.into());
        match serve_proxy(
          req,
          &config,
          local_addr,
          remote_addr,
          proxy_header,
          HttpBindKind::Http,
        )
        .await
        {
          Ok(response) => Ok::<_, Infallible>(response),
          Err(e) => Ok(e.to_response()),
        }
      });

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
pub async fn serve_https(
  config: Arc<Config>,
  local_addr: SocketAddr,
  tcp: TcpListener,
  tls_config: Arc<ServerConfig>,
  cancel: CancellationToken,
  read_timeout: Duration,
  write_timeout: Duration,
  graceful_shutdown_timeout: Option<Duration>,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  proxy_protocol_read_timeout: Duration,
  server_tls_handshake_timeout: Duration,
) {
  let graceful = crate::graceful::GracefulShutdown::new();

  let (conn_sender, conn_recv) = kanal::bounded_async::<(
    TlsStream<GracefulGuard<TcpStream>>,
    SocketAddr,
    Option<ProxyHeader>,
  )>(0);

  let accept_task = {
    let graceful = graceful.clone();
    async move {
      let cancelled = cancel.cancelled();
      tokio::pin!(cancelled);

      loop {
        tokio::select! {
          accept = tcp.accept() => {
            let (tcp_stream, remote_addr) = match accept {
              Ok(accept) => accept,
              Err(e) => {
                log::error!("error accepting tcp stream in https mode {e}, panicking");
                panic!("error accepting tcp stream in https mode {e}");
              }
            };

            #[cfg(feature = "server-tcp-nodelay")]
            if let Err(e) = tcp_stream.set_nodelay(true) {
              log::warn!("error setting tcp stream nodelay: {e}");
            }

            let tls_config = tls_config.clone();
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

              // accept lazily to keep the requested server name at hand when the handshake fails
              let handshake = async move {
                let start = match LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await {
                  Ok(start) => start,
                  Err(e) => return Err((e, None)),
                };

                let server_name = start.client_hello().server_name().map(String::from);

                match start.into_stream(tls_config).await {
                  Ok(tls_stream) => Ok(tls_stream),
                  Err(e) => Err((e, server_name)),
                }
              };

              let tls_stream = match handshake.timeout(server_tls_handshake_timeout).await {
                Ok(Ok(tls_stream)) => tls_stream,
                Ok(Err((e, server_name))) => {
                  let server_name = server_name.as_deref().unwrap_or("<none>");
                  log::warn!("error accepting https connection from {remote_addr} (server name: {server_name}): {e} - {e:?}");
                  return;
                }
                Err(_) => {
                  log::warn!("error accepting https connection from {remote_addr}: handshake timeout after {server_tls_handshake_timeout:?}");
                  return;
                }
              };

              let _ = conn_sender.send((tls_stream, remote_addr, proxy_header)).await;
            });
          },

          _ = &mut cancelled => {
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
      let config = config.clone();
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

      let service = service_fn(move |req| async move {
        let req: Request<crate::body::Body> =
          map_request_body(req, |incoming: Incoming| incoming.into());
        match serve_proxy(
          req,
          &config,
          local_addr,
          remote_addr,
          proxy_header,
          HttpBindKind::Https,
        )
        .await
        {
          Ok(response) => Ok::<_, Infallible>(response),
          Err(e) => Ok(e.to_response()),
        }
      });

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

pub async fn serve_tcp(
  config: Arc<Config>,
  local_addr: SocketAddr,
  tcp: TcpListener,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  signal: CancellationToken,
  graceful_shutdown_timeout: Option<Duration>,
  proxy_protocol_read_timeout: Duration,
) {
  use tokio::io::{AsyncRead, AsyncWrite};

  let graceful = crate::graceful::GracefulShutdown::new();

  let is_ssl = false;

  let graceful_clone = graceful.clone();
  let accept_task = async move {
    let cancelled = signal.cancelled();
    tokio::pin!(cancelled);

    fn serve<S>(
      config: Arc<Config>,
      stream: S,
      proxy_header: Option<ProxyHeader>,
      remote_addr: SocketAddr,
      local_addr: SocketAddr,
      is_ssl: bool,
    ) where
      S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
      let fut = serve_stream_proxy(
        config,
        stream,
        local_addr,
        remote_addr,
        is_ssl,
        proxy_header,
      );
      let connection = ConnectionItem::new(remote_addr.ip(), ConnectionKind::Tcp);
      let guard = connection_start(connection);
      tokio::spawn(async move {
        if let Err(e) = fut.await {
          log::warn!("error handling tcp connection - {e}: {e:?}");
        }
        drop(guard);
      });
    }

    loop {
      tokio::select! {
        accept = tcp.accept() => {
          let (stream, remote_addr) = match accept {
            Ok(accept) => accept,
            Err(e) => {
              log::error!("error accepting tcp stream in tcp mode {e}, panicking");
              panic!("error accepting tcp stream in tcp mode {e}");
            }
          };

          let mut graceful_stream = graceful_clone.guard(stream);
          match expect_proxy_protocol {
            None => serve(config.clone(), graceful_stream, None, remote_addr, local_addr, is_ssl),
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

              serve(config.clone(), graceful_stream, Some(header), remote_addr, local_addr, is_ssl)
            }
          }
        }

        _ = &mut cancelled => {
          break;
        }
      }
    }

    drop(tcp);
  };

  accept_task.await;

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
pub async fn serve_ssl(
  config: Arc<Config>,
  local_addr: SocketAddr,
  tcp: TcpListener,
  expect_proxy_protocol: Option<ExpectProxyProtocol>,
  tls_config: Arc<ServerConfig>,
  signal: CancellationToken,
  graceful_shutdown_timeout: Option<Duration>,
  proxy_protocol_read_timeout: Duration,
  server_tls_handshake_timeout: Duration,
) {
  tokio::pin!(signal);

  let (conn_sender, conn_recv) =
    kanal::bounded_async::<(TlsStream<TcpStream>, SocketAddr, Option<ProxyHeader>)>(0);

  let tls_acceptor = TlsAcceptor::from(tls_config);

  let accept_task = async move {
    let cancelled = signal.cancelled();
    tokio::pin!(cancelled);

    loop {
      tokio::select! {
        accept = tcp.accept() => {
          let (mut tcp_stream, remote_addr) = match accept {
            Ok(accept) => accept,
            Err(e) => {
              log::error!("error accepting tcp stream in ssl mode {e}, panicking");
              panic!("error accepting tcp stream in ssl mode {e}");
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

            let tls_stream = match tls_acceptor.accept(tcp_stream).timeout(server_tls_handshake_timeout).await {
              Ok(Ok(tls_stream)) => tls_stream,
              Ok(Err(e)) => {
                log::warn!("error accepting tls stream from {remote_addr}: {e}");
                return;
              }
              Err(_) => {
                log::warn!("error accepting tls stream from {remote_addr}: handshake timeout after {server_tls_handshake_timeout:?}");
                return;
              }
            };

            let _ = conn_sender.send((tls_stream, remote_addr, proxy_header)).await;
          });
        }

        _ = &mut cancelled => break,
      }
    }

    drop(tcp);
  };

  let handle_task = async move {
    let graceful = crate::graceful::GracefulShutdown::new();

    while let Ok((stream, remote_addr, proxy_header)) = conn_recv.recv().await {
      let graceful_stream = graceful.guard(stream);

      let fut = serve_stream_proxy(
        config.clone(),
        graceful_stream,
        local_addr,
        remote_addr,
        true,
        proxy_header,
      );

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
