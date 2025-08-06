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

#[cfg(feature = "h3-quinn")]
use crate::config::Config;
use crate::{
  graceful::GracefulGuard,
  net::timeout::TimeoutIo,
  proxy::service::MakeHttpService,
  proxy_protocol::{ExpectProxyProtocol, ProxyHeader},
  service::{Connection, StreamService},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnectionKind {
  Http,
  Https,
  Ssl,
  Tcp,
  #[cfg(feature = "h3-quinn")]
  H3Quinn,
}

impl Display for ConnectionKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ConnectionKind::Http => write!(f, "http"),
      ConnectionKind::Https => write!(f, "https"),
      ConnectionKind::Ssl => write!(f, "ssl"),
      ConnectionKind::Tcp => write!(f, "tcp"),
      #[cfg(feature = "h3-quinn")]
      ConnectionKind::H3Quinn => write!(f, "h3"),
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

#[cfg(feature = "h3-quinn")]
#[derive(Debug, thiserror::Error)]
pub enum H3QuinnBindError {
  #[error("h3 quinn bind io error: {0}")]
  Io(#[source] std::io::Error),

  #[error("h3 quinn bind error: {0}")]
  NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

  #[error("h3 quinn bind error: socket create error: {0}")]
  SocketCreate(#[source] std::io::Error),

  #[error("h3 quinn bind error: socket bind error: {0}")]
  SocketBind(#[source] std::io::Error),

  #[error("h3 quinn bind error: set socket ipv6 only error: {0}")]
  SocketSetIpv6Only(#[source] std::io::Error),

  #[error("h3 quinn bind error: socket from std error: {0}")]
  SocketFromStd(#[source] std::io::Error),

  #[error("h3 quinn bind error: no default async runtime")]
  NoDefaultRuntime,

  #[error("h3 quinn bind error: socket runtime wrap error: {0}")]
  SocketRuntimeWrap(#[source] std::io::Error),

  #[error("h3 quinn bind error: endpoint create error: {0}")]
  EndpointCreate(#[source] std::io::Error),
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
  #[cfg(feature = "h3-quinn")]
  let mut total_h3 = 0;
  for connection in connections.iter() {
    match connection.kind {
      ConnectionKind::Http => total_http += 1,
      ConnectionKind::Https => total_https += 1,
      ConnectionKind::Ssl => total_ssl += 1,
      ConnectionKind::Tcp => total_tcp += 1,
      #[cfg(feature = "h3-quinn")]
      ConnectionKind::H3Quinn => total_h3 += 1,
    }
  }

  log::info!(
    "= server connections - https: {} -  http: {} - h3: {} - ssl: {} - tcp: {} | total: {} =",
    total_https,
    total_http,
    total_h3,
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

      let service = make_service.make_service(local_addr, remote_addr, false, proxy_header);
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
                log::error!("error accepting tcp stream in https mode {e}, panicking");
                panic!("error accepting tcp stream in https mode {e}");
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

      let service = make_service.make_service(local_addr, remote_addr, true, proxy_header);
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

#[cfg(feature = "h3-quinn")]
#[allow(clippy::too_many_arguments)]
pub fn serve_h3_quinn<Sig>(
  local_addr: SocketAddr,
  config: Arc<Config>,
  tls_config: Arc<ServerConfig>,
  signal: Sig,
  // read_timeout: Duration,
  // write_timeout: Duration,
  graceful_shutdown_timeout: Option<Duration>,
) -> Result<impl Future<Output = ()>, H3QuinnBindError>
where
  Sig: Future<Output = ()>,
{
  use quinn::{crypto::rustls::QuicServerConfig, default_runtime};
  use socket2::Protocol;

  let mut tls_config = (*tls_config).clone();
  tls_config.max_early_data_size = u32::MAX;
  tls_config.alpn_protocols = vec![b"h3".to_vec()];

  let endpoint_config = quinn::EndpointConfig::default();

  let server_config =
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));

  let socket = socket2::Socket::new(
    socket2::Domain::for_address(local_addr),
    socket2::Type::DGRAM,
    Some(Protocol::UDP),
  )
  .map_err(H3QuinnBindError::SocketCreate)?;

  if local_addr.is_ipv6() {
    socket
      .set_only_v6(true)
      .map_err(H3QuinnBindError::SocketSetIpv6Only)?;
  }

  socket
    .bind(&local_addr.into())
    .map_err(H3QuinnBindError::SocketBind)?;

  let runtime = match default_runtime() {
    Some(runtime) => runtime,
    None => return Err(H3QuinnBindError::NoDefaultRuntime),
  };

  let socket = runtime
    .wrap_udp_socket(socket.into())
    .map_err(H3QuinnBindError::SocketRuntimeWrap)?;

  let endpoint = quinn::Endpoint::new_with_abstract_socket(
    endpoint_config,
    Some(server_config),
    socket,
    runtime,
  )
  .map_err(H3QuinnBindError::EndpointCreate)?;

  let graceful_task = async move {
    let accept_task = async {
      while let Some(new_conn) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
          use bytes::BytesMut;
          let remote_addr = new_conn.remote_address();

          let connection_item = ConnectionItem::new(remote_addr.ip(), ConnectionKind::H3Quinn);
          let connection_guard = connection_start(connection_item);

          let conn = match new_conn.await {
            Err(e) => {
              log::warn!("error at h3 new_conn.await - {e}: {e:?}");
              return;
            }

            Ok(conn) => conn,
          };

          let mut h3_conn: h3::server::Connection<_, BytesMut> =
            h3::server::Connection::new(h3_quinn::Connection::new(conn))
              .await
              .unwrap();

          loop {
            let resolver = match h3_conn.accept().await {
              Ok(resolver) => match resolver {
                Some(resolver) => resolver,
                None => {
                  log::debug!("h3 server connection ended");
                  break;
                }
              },

              Err(e) => {
                log::warn!("error at h3 accepted.await - {e}: {e:?}");
                break;
              }
            };

            let config = config.clone();
            tokio::spawn(async move {
              use futures::StreamExt;

              use crate::{body::map_request_body, proxy::service::serve_proxy};

              let (req, stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(e) => {
                  log::warn!("error resolving h3 request - {e}: {e:?}");
                  return;
                }
              };

              let (mut send_stream, recv_stream) = stream.split();
              let h3_body = h3_util::server_body::H3IncomingServer::new(recv_stream);
              let body = crate::body::Body::incoming_h3_quinn_server(h3_body);

              let req = map_request_body(req, |_| body);

              let res = match serve_proxy(req, &config, local_addr, remote_addr, None, true).await {
                Ok(response) => response,
                Err(e) => {
                  log::warn!("error handling h3 request - {e}: {e:?}");
                  todo!();
                }
              };

              let (res, mut body) = res.into_parts();
              let res = Response::from_parts(res, ());
              if let Err(e) = send_stream.send_response(res).await {
                log::warn!("error sending h3 response - {e}: {e:?}");
                return;
              }

              while let Some(next) = body.next().await {
                let frame = match next {
                  Ok(frame) => frame,
                  Err(e) => {
                    log::warn!("h3 error at body.next() - {e}: {e:?}");
                    return;
                  }
                };

                if frame.is_data() {
                  let data = frame.into_data().ok().unwrap();
                  if let Err(e) = send_stream.send_data(BytesMut::from(data)).await {
                    log::warn!("h3 error at send_stream.send_data() - {e}: {e:?}");
                    return;
                  };
                } else if frame.is_trailers() {
                  let trailers = frame.into_trailers().ok().unwrap();
                  if let Err(e) = send_stream.send_trailers(trailers).await {
                    log::warn!("h3 error at send_stream.send_trailers() - {e}: {e:?}");
                    return;
                  };
                }
              }

              // Close the stream gracefully.
              // This is technically only needed when not writing trailers.
              // But msquic-h3 requires stream be gracefully closed all the time.
              if let Err(e) = send_stream.finish().await {
                log::warn!("h3 error at send_stream.finish() - {e}: {e:?}");
              };
            });
          }

          drop(connection_guard)
        });
      }
    };

    tokio::select! {
      _ = accept_task => {
      }

      _ = signal => {
        match graceful_shutdown_timeout {
          None => {
            endpoint.wait_idle().await;
          }

          Some(timeout) => {
            if endpoint.wait_idle().timeout(timeout).await.is_err() {
              log::info!(
                "graceful shutdown timeout ({}s) reached for h3 server",
                timeout.as_secs()
              );
            };
          }
        }
      }
    }
  };

  Ok(graceful_task)
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
                log::error!("error accepting tcp stream in tcp mode {e}, panicking");
                panic!("error accepting tcp stream in tcp mode {e}");
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
