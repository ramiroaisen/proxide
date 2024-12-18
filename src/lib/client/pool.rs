use derivative::Derivative;
use http::StatusCode;
use http_body::Body as HttpBody;
use http_body_util::BodyExt;
use hyper::client::conn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_rustls::ConfigBuilderExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rustls::{pki_types, ClientConfig};
use tokio::io::AsyncWriteExt;
use tokio_util::time::FutureExt;
use url::Host;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::{
  collections::{HashMap, VecDeque},
  fmt::Display,
  sync::{
    atomic::AtomicUsize,
    Arc, Weak,
  }
};
use tokio::net::TcpStream;
#[cfg(feature = "stats")]
use std::sync::atomic::AtomicU64; 

use crate::body::Body;
use crate::config::{Config, HttpApp, HttpHandle, HttpUpstream, UpstreamVersion};
use crate::net::timeout::TimeoutIo;
use crate::config::defaults::{DEFAULT_HTTP_PROXY_READ_TIMEOUT, DEFAULT_HTTP_PROXY_WRITE_TIMEOUT, DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT, DEFAULT_PROXY_TCP_NODELAY};
use crate::proxy::error::{ErrorOriginator, ProxyHttpError};
use crate::proxy_protocol::{self, ProxyHeader, ProxyProtocolVersion};
use crate::serde::sni::Sni;
use crate::serde::url::HttpUpstreamScheme;
#[cfg(feature = "stats")]
use crate::stats::counters_io::CountersIo;
use crate::tls::danger_no_cert_verifier::DangerNoCertVerifier;
use crate::upgrade::response_is_keep_alive;
use crate::tls::crypto;

#[cfg(feature = "client-log")]
use crate::log::{client_log, DisplayHeader};

type Response = HyperResponse<Body>;
type Request = HyperRequest<Body>;

type SenderDeque = VecDeque<Sender>;
type SenderMap = HashMap<Key, Arc<Mutex<SenderDeque>>>;

type Http1SendRequest = conn::http1::SendRequest<Body>;
type Http2SendRequest = conn::http2::SendRequest<Body>;

static CONNECTION_UID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
  Http10,
  Http11,
  Http2,
}

impl From<UpstreamVersion> for Version {
  fn from(version: UpstreamVersion) -> Self {
    match version {
      UpstreamVersion::Http10 => Version::Http10,
      UpstreamVersion::Http11 => Version::Http11,
      UpstreamVersion::Http2 => Version::Http2,
    }
  }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
  Http,
  Https,
}

impl Protocol {
  pub fn default_port(&self) -> u16 {
    match self {
      Protocol::Http => 80,
      Protocol::Https => 443,
    }
  }
}

impl Display for Protocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Protocol::Http => write!(f, "http"),
      Protocol::Https => write!(f, "https"),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
  pub version: Version,
  pub protocol: Protocol,
  pub host: url::Host,
  pub port: u16,
  pub sni: Option<Sni>,
  pub read_timeout: Duration,
  pub write_timeout: Duration,
  pub tcp_nodelay: bool,
  pub accept_invalid_certs: bool,
  pub proxy_protocol: Option<ProxyProtocolConfig>
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyProtocolConfig {
  pub header: ProxyHeader,
  pub version: ProxyProtocolVersion,
  pub timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidUpstreamError {
  #[error("invalid upstream url: missing host")]
  NoHost,
  #[error("invalid upstream url: invalid scheme {0}")]
  InvalidScheme(String),
  #[error("invalid upstream url: invalid protocol {0}")]
  InvalidProtocol(String),
}

impl Key {
  pub fn from_config(config: &Config, app: &HttpApp, upstream: &HttpUpstream) -> Result<Self, InvalidUpstreamError> {

    let protocol = match upstream.base_url.scheme() {
      HttpUpstreamScheme::Http => Protocol::Http,
      HttpUpstreamScheme::Https => Protocol::Https,
    };
    
    let host = upstream.base_url.host().clone();

    let port = upstream.base_url.port_or_default();

    let version = upstream.version.into();

    let read_timeout =crate::option!(
      @duration
      upstream.proxy_read_timeout,
      app.proxy_read_timeout,
      config.http.proxy_read_timeout
      => DEFAULT_HTTP_PROXY_READ_TIMEOUT
    );

    let write_timeout = crate::option!(
      @duration
      upstream.proxy_write_timeout,
      app.proxy_write_timeout,
      config.http.proxy_write_timeout
      => DEFAULT_HTTP_PROXY_WRITE_TIMEOUT
    );

    let tcp_nodelay = crate::option!(
      upstream.proxy_tcp_nodelay,
      app.proxy_tcp_nodelay,
      config.http.proxy_tcp_nodelay,
      config.proxy_tcp_nodelay,
      => DEFAULT_PROXY_TCP_NODELAY
    );

    let proxy_protocol_config = match upstream.send_proxy_protocol {
      Some(version) => {
        let timeout = crate::option!(
          @duration
          upstream.proxy_protocol_write_timeout,
          match app.handle {
            HttpHandle::Proxy { proxy_protocol_write_timeout, .. } => proxy_protocol_write_timeout,
            _ => None,
          },
          config.http.proxy_protocol_write_timeout,
          config.proxy_protocol_write_timeout,
          => DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT
        );

        let header = ProxyHeader::Local;

        Some(ProxyProtocolConfig {
          header,
          version,
          timeout,
        })
      }

      None => None,
    };
    

    Ok(Key {
      version,
      protocol,
      host,
      port,
      sni: upstream.sni.clone(),
      read_timeout,
      write_timeout,
      tcp_nodelay,
      accept_invalid_certs: upstream.danger_accept_invalid_certs,
      proxy_protocol: proxy_protocol_config,
    })
  }
}

impl Display for Key {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}://{}:{}", self.protocol, self.host, self.port)
  }
}

#[derive(Debug)]
pub enum SendRequest {
  Http1(Http1SendRequest),
  Http2(Http2SendRequest),
}

impl SendRequest {
  pub fn is_ready(&self) -> bool {
    match self {
      SendRequest::Http1(send) => send.is_ready(),
      SendRequest::Http2(send) => send.is_ready(),
    }
  }

  pub fn is_closed(&self) -> bool {
    match self {
      SendRequest::Http1(send) => send.is_closed(),
      SendRequest::Http2(send) => send.is_closed(),
    }
  }

  pub async fn ready(&mut self) -> Result<(), hyper::Error> {
    match self {
      SendRequest::Http1(send) => send.ready().await,
      SendRequest::Http2(send) => send.ready().await,
    }
  }
}

pub struct Sender {
  send: SendRequest,
  uid: usize,
}

impl Sender {
  pub async fn ready(&mut self) -> Result<(), hyper::Error> {
    self.send.ready().await
  }

  pub async fn connect(
    key: Key,
    #[cfg(feature = "stats")]
    read_counter: &Arc<AtomicU64>,
    #[cfg(feature = "stats")]
    write_counter: &Arc<AtomicU64>,
    weak: Weak<RwLock<SenderMap>>
  ) -> Result<Self, ConnectError> {
    let connect = match &key.host {
      Host::Domain(domain) => TcpStream::connect((domain.as_str(), key.port)).await,
      Host::Ipv4(ipv4) => TcpStream::connect((*ipv4, key.port)).await,
      Host::Ipv6(ipv6) => TcpStream::connect((*ipv6, key.port)).await,
    };

    let tcp = connect
      .map_err(ConnectError::TcpConnect)?;
    
    if key.tcp_nodelay {
      tcp.set_nodelay(true)
        .map_err(ConnectError::SetTcpNoDelay)?;
    }
    
    #[cfg(feature = "stats")]
    let mut tcp = CountersIo::new(tcp, read_counter.clone(), write_counter.clone());

    #[cfg(not(feature = "stats"))]
    let mut tcp = tcp;

    if let Some(proxy_protocol_config) = &key.proxy_protocol {
      let buf = proxy_protocol::encode(
        &proxy_protocol_config.header,
        proxy_protocol_config.version,
      ).map_err(ConnectError::ProxyProtocolEncode)?;

      tcp.write_all(&buf)
        .timeout(proxy_protocol_config.timeout)
        .await
        .map_err(|_| ConnectError::ProxyProtocolWriteTimeout)?
        .map_err(ConnectError::ProxyProtocolWrite)?;
    }

    match key.protocol {

      Protocol::Http => {

        let io = Box::pin(TokioIo::new(TimeoutIo::new(tcp, key.read_timeout, key.write_timeout)));
        
        match key.version {
          // for version http/1.0 the weak arc will always point to None
          // so each connection will only be used by one request
          Version::Http10 | Version::Http11 => {
            let (conn_send, conn) = hyper::client::conn::http1::Builder::new()
              .handshake(io)
              .await
              .map_err(ConnectError::TcpHandshake)?;

            let uid = CONNECTION_UID.fetch_add(1, Ordering::AcqRel);
            log::debug!("tcp http1 connection {} established", uid);

            tokio::spawn(async move {
              let _ = conn.with_upgrades().await;
              log::debug!("tcp http1 connection {} closed", uid);
              connection_end(weak, &key, uid);
            });

            let send = SendRequest::Http1(conn_send);
            let sender = Sender {
              send,
              uid,
              // last_used: Instant::now(),
            };

            Ok(sender)
          }

          Version::Http2 => {

            let (conn_send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
              .handshake(io)
              .await
              .map_err(ConnectError::TcpHandshake)?;

            let uid = CONNECTION_UID.fetch_add(1, Ordering::AcqRel);
            log::debug!("tcp http2 connection {} established", uid);

            tokio::spawn(async move {
              let _ = conn.await;
              log::debug!("tcp http2 connection {} closed", uid);
              connection_end(weak, &key, uid);
            });

            let send = SendRequest::Http2(conn_send);
            let sender = Sender {
              send,
              uid,
              // last_used: Instant::now(),
            };

            Ok(sender)
          }
        }
      }

      Protocol::Https => {

        macro_rules! tls_config {
          ($($alpn:tt)*) => {{
            #[static_init::dynamic]
            static TLS_CONFIG: Arc<ClientConfig> = {
              let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("cannot build tls client config with default protocols")
                .with_native_roots()
                .expect("cannot build tls client config with native roots")
                .with_no_client_auth();

              config.enable_sni = true;
              config.alpn_protocols = vec![$($alpn.to_vec())*];
              
              Arc::new(config)
            };

            TLS_CONFIG.clone()
          }}
        }


        macro_rules! danger_no_cert_verifier_tls_config {
          ($($alpn:tt)*) => {{
            #[static_init::dynamic]
            static DANGER_NO_CERT_VERIFIER_TLS_CONFIG: Arc<ClientConfig> = {
              let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("cannot build tls client config with default protocols")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerNoCertVerifier))
                .with_no_client_auth();

              config.enable_sni = true;
              config.alpn_protocols = vec![$($alpn.to_vec())*];

              Arc::new(config)
            };

            DANGER_NO_CERT_VERIFIER_TLS_CONFIG.clone()
          }}
        }


        let tls_config = match (key.accept_invalid_certs, key.version) {
          (true, Version::Http10) => danger_no_cert_verifier_tls_config!(b"http/1.0"),
          (true, Version::Http11) => danger_no_cert_verifier_tls_config!(b"http/1.1"),
          (true, Version::Http2) => danger_no_cert_verifier_tls_config!(b"h2"),
          (false, Version::Http10) => tls_config!(b"http/1.0"),
          (false, Version::Http11) => tls_config!(b"http/1.1"),
          (false, Version::Http2) => tls_config!(b"h2"),
        };

        let tls_connector = tokio_rustls::TlsConnector::from(tls_config);
        
        let sni = match &key.sni {
          Some(sni) => sni.0.clone(),
          None => pki_types::ServerName::try_from(key.host.to_string())
            .map_err( ConnectError::InvalidUriHost)?
        };

        let tls_stream = tls_connector.connect(sni, tcp)
          .await
          .map_err(ConnectError::TlsConnect)?;

        let io = Box::pin(TimeoutIo::new(TokioIo::new(tls_stream), key.read_timeout, key.write_timeout));

        match key.version {
          Version::Http10 | Version::Http11 => {
            let (conn_send, conn) = hyper::client::conn::http1::Builder::new()
              .handshake(io)
              .await
              .map_err(ConnectError::TcpHandshake)?;

            let uid = CONNECTION_UID.fetch_add(1, Ordering::AcqRel);
            log::debug!("ssl http2 connection {} established", uid);

            tokio::spawn(async move {
              let _ = conn.with_upgrades().await;
              log::debug!("ssl http2 connection {} closed", uid);
              connection_end(weak, &key, uid);
            });

            let send = SendRequest::Http1(conn_send);
            let sender = Sender {
              send,
              uid,
              // last_used: Instant::now(),
            };

            Ok(sender)
          }

          Version::Http2 => {
            let (conn_send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
              .handshake(io)
              .await
              .map_err(ConnectError::TcpHandshake)?;

            let uid = CONNECTION_UID.fetch_add(1, Ordering::AcqRel);
            log::debug!("tls http2 connection {} established", uid);

            tokio::spawn(async move {
              let _ = conn.await;
              log::debug!("tls http2 connection {} closed", uid);
              connection_end(weak, &key, uid);
            });

            let send = SendRequest::Http2(conn_send);
            let sender = Sender { send, uid };

            Ok(sender)
          }
        }
      }
    }
  }
}


/**
 * A connection pool. \
 * The pool uses an [`Arc`] internally so it can be safely shared and cloned. \  
 */
#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct Pool {
  #[derivative(Debug = "ignore")]
  map: Arc<RwLock<SenderMap>>,
}

impl Pool {
  /**
   * Create a new connection pool.
   */
  fn new() -> Self {
    let map = Arc::new(RwLock::new(SenderMap::new()));
    Self { map }
  }

  /**
   * (re)inert a Sender into the pool. 
   */
  pub fn insert(&self, key: Key, sender: Sender) {
    let list = {
      let map_read = self.map.read();
      match map_read.get(&key) {
        Some(list) => list.clone(),
        None => {
          drop(map_read);
          let mut map_write = self.map.write();
          map_write.entry(key).or_default().clone()
        }
      }
    };

    list.lock().push_back(sender);
  }

  /**
   * Get a sender from the pool. \
   */
  pub async fn get(
    &self,
    key: &Key,
    #[cfg(feature = "stats")]
    read_counter: &Arc<AtomicU64>,
    #[cfg(feature = "stats")]
    write_counter: &Arc<AtomicU64>
  ) -> Result<Sender, ConnectError> {
    // http/1.0 uses one request per connection and does not take part in the pool
    // we only enable http/1.0 in the pool for convenience
    // we set a Weak that always returns None on upgrade
    if matches!(key.version, Version::Http10) {
      let sender = Sender::connect(
        key.clone(),
        #[cfg(feature = "stats")]
        read_counter,
        #[cfg(feature = "stats")]
        write_counter,
        Weak::default()
      ).await?;
      return Ok(sender);
    }

    'deque: {
      let deque = {
        let map = self.map.read();
        match map.get(key) {
          None => break 'deque,
          Some(deque) => deque.clone(),
        }
      };

      loop {
        let mut sender = match deque.lock().pop_front() {
          Some(sender) => sender,
          None => break 'deque,
        };
      
        match sender.ready().await {
          Ok(()) => {
            log::debug!("sender ready ok");
            return Ok(sender);
          }

          Err(e) => {
            log::warn!("sender ready err: {e} - {e:?}");
            continue;
          }
        }
      }
    };

    let weak = Arc::downgrade(&self.map);
    let sender = Sender::connect(
      key.clone(),
      #[cfg(feature = "stats")]
      read_counter,
      #[cfg(feature = "stats")]
      write_counter,
      weak
    ).await?;

    Ok(sender)
  }

  /**
   * Send a request within the pool. \
   * This will try to reuse an open connection if possible. \
   * The used connection will be reinserted into the pool after use if applicable. \
   */
  #[allow(clippy::too_many_arguments)]
  pub async fn send_request(
    &self,
    mut request: Request,
    sni: Option<Sni>,
    accept_invalid_certs: bool,
    #[cfg(feature = "stats")]
    read_counter: &Arc<AtomicU64>,
    #[cfg(feature = "stats")]
    write_counter: &Arc<AtomicU64>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
    proxy_protocol_config: Option<ProxyProtocolConfig>
  ) -> Result<Response, ClientError> {
    
    let protocol = match request.uri().scheme_str() {
      Some("https") => Protocol::Https,
      Some("http") => Protocol::Http,
      _ => return Err(ClientError::InvalidProtocol(request.uri().scheme_str().map(ToString::to_string))),
    };

    let version = match request.version() {
      hyper::Version::HTTP_10 => Version::Http10,
      hyper::Version::HTTP_11 => Version::Http11,
      hyper::Version::HTTP_2 => Version::Http2,
      _ => return Err(ClientError::InvalidVersion(request.version())),
    };

    let host = match request.uri().host() {
      Some(host) => url::Host::parse(host)?.to_owned(),
      None => return Err(ClientError::InvalidUriMissingHost),
    };


    let port = request.uri().port_u16()
      .unwrap_or_else(|| protocol.default_port());

    let read_timeout = read_timeout.unwrap_or(DEFAULT_HTTP_PROXY_READ_TIMEOUT);
    let write_timeout = write_timeout.unwrap_or(DEFAULT_HTTP_PROXY_WRITE_TIMEOUT);

    #[cfg(feature = "client-log")]
    let (
      method,
      uri,
      user_agent,
      log_host,
    ) = (
      request.method().clone(),
      request.uri().clone(),
      request.headers().get(hyper::header::USER_AGENT).cloned(),
      host.clone(),
    );

    let key = Key {
      version,
      protocol,
      host,
      port,
      sni,
      read_timeout,
      write_timeout,
      tcp_nodelay,
      accept_invalid_certs,
      proxy_protocol: proxy_protocol_config,
    };

    // we spawn here to avoid cancellation
    // if we allow cancellation the connection could be lost
    // and never reinserted into the pool
    let pool = self.clone();

    #[cfg(feature = "stats")]
    let read_counter = read_counter.clone();
    #[cfg(feature = "stats")]
    let write_counter = write_counter.clone();
    
    tokio::spawn(async move {
      let sender = match pool.get(
        &key,
        #[cfg(feature = "stats")]
        &read_counter,
        #[cfg(feature = "stats")]
        &write_counter
      ).await {
        Ok(sender) => sender,
        Err(e) => return Err(ClientError::Connect { request, source: e }),
      };

      let uid = sender.uid;
      let send_request = sender.send;


      #[cfg(feature = "client-log")]
      let start = std::time::Instant::now();

      let result = async {
        let response = match send_request {
          SendRequest::Http1(mut send) => {
            // the http1 sender expect the uri to be in non-authority form
            // except for the CONNECT method
            remove_authority(request.uri_mut())?;

            let response = send
              .send_request(request)
              .await
              .map_err(ClientError::SendRequest)?;

            if response.body().is_end_stream() {
              let sender = Sender {
                send: SendRequest::Http1(send),
                uid,
              };
              pool.insert(key, sender);
              let (parts, inconming) = response.into_parts();
              Response::from_parts(parts, Body::incoming(inconming))
            } else {

              // in http/1.0 each connection can be used only once
              // so there's no need to re-insert the sender into the pool
              let can_reuse_connection =
                key.version != Version::Http10 && response_is_keep_alive(response.version(), response.headers());

              if can_reuse_connection {
                let (parts, mut incoming) = response.into_parts();

                // opt1: channel, this seems to be very slow
                // let (body, mut sender) = Body::channel();

                // tokio::spawn(async move {
                //   loop {
                //     match incoming.frame().await {
                //       None => break,
                //       Some(Err(e)) => {
                //         let _ = sender.send(Err(e.into())).await;
                //         return;
                //       },
                //       Some(Ok(frame)) => {
                //         match sender.send(Ok(frame)).await {
                //           Ok(()) => continue,
                //           Err(_) => {
                //             return;
                //           }
                //         }
                //       },
                //     }
                //   }

                //   let sender = Sender {
                //     send: SendRequest::Http1(send),
                //     uid,
                //   };

                //   log::warn!("resinserting connection into the pool");
                //   pool.insert(key, sender);
                // });

                // Response::from_parts(parts, body)

                // opt2: reinsert on drop
                // let errored = Arc::new(std::sync::atomic::AtomicBool::new(false));

                // let reinsert = defer::defer({
                //   let errored = errored.clone();

                //   move || {
                //     if errored.load(Ordering::Acquire) {
                //       return;
                //     }

                //     let sender = Sender {
                //       send: SendRequest::Http1(send),
                //       uid,
                //     };

                //     log::debug!("resinserting connection into the pool");

                //     pool.insert(key, sender);
                //   }
                // });

                // let stream = async_stream::stream! {

                //  loop {
                //   let next = incoming.frame().await;
                //     match next {
                //       None => break ,
                //       Some(Ok(frame)) => yield Ok(frame),
                //       Some(Err(e)) => {
                //         errored.store(true, Ordering::Release);
                //         yield Err(e.into());
                //         break;
                //       }
                //     }
                //   }

                //   drop(reinsert);
                // };


                // opt3: reinsert before yielding last frame
                // seems that if the stream is ended the poll for None is not called from hyper
                let stream = async_stream::stream! {

                  use hyper::body::Body as HyperBody;

                  'stream: {
                    let last_frame = 'items: loop {
                      match incoming.frame().await {
                        None => break 'items None,
                        Some(Ok(frame)) => {
                          if incoming.is_end_stream() {
                            break 'items Some(frame)
                          } else {
                            yield Ok(frame);
                          }
                        },
                        Some(Err(e)) => {
                          yield Err(ProxyHttpError::IncomingBody(e));
                          break 'stream;
                        }
                      }
                    };

                    let sender = Sender {
                      send: SendRequest::Http1(send),
                      uid,
                    };

                    log::debug!("resinserting connection into the pool");

                    pool.insert(key, sender);

                    if let Some(frame) = last_frame {
                      yield Ok(frame);
                    }
                  }
                };

                Response::from_parts(parts, Body::stream(stream))
              } else {
                let (parts, incoming) = response.into_parts();
                Response::from_parts(parts, Body::incoming(incoming))
              }
            }
          }

          SendRequest::Http2(mut send) => {
            let sender = Sender {
              send: SendRequest::Http2(send.clone()),
              uid,
            };

            pool.insert(key, sender);
            
            let response = send
              .send_request(request)
              .await
              .map_err(ClientError::SendRequest)?;

            let (parts, incoming) = response.into_parts();

            Response::from_parts(parts, Body::incoming(incoming))
          }
        };

        Ok(response)
      }.await;

      #[cfg(feature = "client-log")]
      match &result  {
        Ok(response) => {
          client_log!(
            "{method} {uri} - {host} - {user_agent} | {status} {status_text} - {content_length} - {ms}ms",  
            method = method,
            uri = uri,
            host = log_host,
            user_agent = DisplayHeader(user_agent.as_ref()), 
            status = response.status().as_u16(),
            status_text = response.status().canonical_reason().unwrap_or(""),
            content_length = DisplayHeader(response.headers().get(hyper::header::CONTENT_LENGTH)),
            ms = start.elapsed().as_millis()
          )
        }

        Err(e) => {
          client_log!(
            "{method} {uri} - {host} - {user_agent} | {ms}ms - ERROR {error} {error:?}",  
            method = method,
            uri = uri,
            host = log_host,
            user_agent = DisplayHeader(user_agent.as_ref()),
            ms = start.elapsed().as_millis(),
            error = e
          );
        }
      }

      result
    })
    .await
    .unwrap()
  }

  #[cfg(feature = "log-state")]
  pub fn log(&self) {
    let map = self.map.read();
    for (key, list) in map.iter() {
      let n = list.lock().len();
      log::info!("{key} - {n}");
    }
  }
}

impl Default for Pool {
  fn default() -> Self {
    Self::new()
  }
}

fn connection_end(weak: Weak<RwLock<SenderMap>>, key: &Key, uid: usize) {
  let arc = match weak.upgrade() {
    Some(arc) => arc,
    None => return,
  };

  let list = {
    let lock = arc.read();
    match lock.get(key) {
      Some(list) => list.clone(),
      None => return,
    }
  };

  let mut list = list.lock();
  if let Some(i) = list.iter().position(|item| item.uid == uid) {
    list.remove(i);
  };
}

/**
 * The error returned by [`Pool::send_request`] and [`send_request`].\
 */
#[derive(Derivative, thiserror::Error)]
#[derivative(Debug)]
pub enum ClientError {
  #[error("send invalid uri: {0}")]
  InvalidUri(#[from] hyper::http::uri::InvalidUriParts),

  #[error("invalid host parse: {0}")]
  InvalidHost(#[from] url::ParseError),

  #[error("invalid protocol: {0:?}")]
  InvalidProtocol(Option<String>),

  #[error("invalid version: {0:?}")]
  InvalidVersion(hyper::Version),

  #[error("invalid uri, missing host")]
  InvalidUriMissingHost,

  /**
   * This error variant means that the connection could not be established. \
   * So the request was not sent. \
   * You may want to inspect the [`ConnectError`] associated to know if the request can be safely retryed.
   */
  #[error("connnect error: {source}")]
  Connect {
    #[derivative(Debug = "ignore")]
    request: Request,
    source: ConnectError,
  },

  #[error("error after request sent: {0}")]
  SendRequest(hyper::Error),
}

/**
 * The kind of the error, without the data associated with each kind. \
 * See [`ClientError`].
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientErrorKind {
  InvalidUri,
  InvalidHost,
  InvalidProtocol,
  InvalidVersion,
  InvalidUriMissingHost,
  Connect,
  SendRequest,
}

impl ClientErrorKind {
  pub fn originator(&self) -> ErrorOriginator {
    use ClientErrorKind as E;
    match self {
      E::InvalidUri => ErrorOriginator::Config,
      E::InvalidHost => ErrorOriginator::Config,
      E::InvalidProtocol => ErrorOriginator::Config,
      E::InvalidVersion => ErrorOriginator::Config,
      E::InvalidUriMissingHost => ErrorOriginator::Config,
      E::Connect => ErrorOriginator::Upstream,
      E::SendRequest => ErrorOriginator::Upstream,
    }
  }

  pub fn status(&self) -> StatusCode {
    use ClientErrorKind as E;
    match self {
      E::InvalidUri => StatusCode::BAD_REQUEST,
      E::InvalidHost => StatusCode::BAD_REQUEST,
      E::InvalidProtocol => StatusCode::BAD_REQUEST,
      E::InvalidVersion => StatusCode::BAD_REQUEST,
      E::InvalidUriMissingHost => StatusCode::BAD_REQUEST,
      E::Connect => StatusCode::BAD_GATEWAY,
      E::SendRequest => StatusCode::BAD_GATEWAY,
    }
  }
}

impl ClientError {
  /**
   * Get the kind of the error, without the data associated with each kind.
   */
  pub fn kind(&self) -> ClientErrorKind {
    match self {
      ClientError::InvalidHost(_) => ClientErrorKind::InvalidHost,
      ClientError::InvalidUri(_) => ClientErrorKind::InvalidUri,
      ClientError::InvalidProtocol(_) => ClientErrorKind::InvalidProtocol,
      ClientError::InvalidVersion(_) => ClientErrorKind::InvalidVersion,
      ClientError::InvalidUriMissingHost => ClientErrorKind::InvalidUriMissingHost,
      ClientError::Connect { .. } => ClientErrorKind::Connect,
      ClientError::SendRequest(_) => ClientErrorKind::SendRequest,
    }
  }

  /**
   * Get a reference to the request if it is Some.
   */
  pub fn request(&self) -> Option<&Request> {
    match &self {
      ClientError::Connect { request, .. } => Some(request),
      _ => None,
    }
  }

  /**
   * Get a mutable reference to the request if it is Some.
   */
  pub fn request_mut(&mut self) -> Option<&mut Request> {
    match self {
      ClientError::Connect { request, .. } => Some(request),
      _ => None,
    }
  }

  /**
   * Converts this error into a request if possible, consuming the error.
   */
  pub fn into_request(self) -> Option<Request> {
    match self {
      ClientError::Connect { request, .. } => Some(request),
      _ => None,
    }
  }
}
/**
 * Error returned when trying to establish a connection with an upstream.\
 */
#[derive(Derivative, thiserror::Error)]
#[derivative(Debug)]
pub enum ConnectError {
  // #[error("https tcp ready error: {0}")]
  // HttpsTcpReady(#[source] ProxyProtocolConnectorError<<HttpConnector as Service<hyper::http::Uri>>::Error>),
  // #[error("https tcp connect error: {0}")]
  // HttpsTcpConnect(#[source] ProxyProtocolConnectorError<<HttpConnector as Service<hyper::http::Uri>>::Error>),
  #[error("tcp connect error: {0}")]
  TcpConnect(#[source] std::io::Error),
  #[error("tcp handshake error: {0}")]
  TcpHandshake(#[from] hyper::Error),
  #[error("tls connect error: {0}")]
  TlsConnect(#[source] std::io::Error),
  #[error("set tcp nodelay error: {0}")]
  SetTcpNoDelay(#[source] std::io::Error),
  // #[error("tls ready error: {0}")]
  // TlsReady(Box<dyn std::error::Error + Send + Sync + 'static>),
  #[error("invalid uri: {0}")]
  UriParse(#[from] hyper::http::uri::InvalidUri),
  #[error("invalid uri host: {0}")]
  InvalidUriHost(#[from] pki_types::InvalidDnsNameError),
  #[error("proxy protocol encode error: {0}")]
  ProxyProtocolEncode(#[source] crate::proxy_protocol::ProxyProtocolError),
  #[error("proxy protocol write error: {0}")]
  ProxyProtocolWrite(#[source] std::io::Error),
  #[error("proxy protocol write timeout elapsed")]
  ProxyProtocolWriteTimeout,
}

fn remove_authority(uri: &mut hyper::Uri) -> Result<(), hyper::http::uri::InvalidUriParts> {
  let mut parts = hyper::http::uri::Parts::default();
  parts.path_and_query = uri.path_and_query().cloned();

  #[allow(unused)]
  let target = hyper::Uri::from_parts(parts)?;

  *uri = target;

  Ok(())
}

static GLOBAL_POOL: Lazy<Pool> = Lazy::new(Pool::new);

/**
 * Send a request using the global pool.\
 * On first usage, the global pool will be initialized.\
 * see [`Pool::send_request`] for more information.
 */
#[allow(clippy::too_many_arguments)]
pub async fn send_request(
  request: Request,
  sni: Option<Sni>,
  accept_invalid_certs: bool,
  #[cfg(feature = "stats")]
  read_counter: &Arc<AtomicU64>,
  #[cfg(feature = "stats")]
  write_counter: &Arc<AtomicU64>,
  read_timeout: Option<Duration>,
  write_timeout: Option<Duration>,
  tcp_nodelay: bool,
  proxy_protocol_config: Option<ProxyProtocolConfig>
) -> Result<Response, ClientError> {
  GLOBAL_POOL.send_request(
    request,
    sni,
    accept_invalid_certs,
    #[cfg(feature = "stats")]
    read_counter,
    #[cfg(feature = "stats")]
    write_counter,
    read_timeout,
    write_timeout,
    tcp_nodelay,
    proxy_protocol_config
  ).await
}

/**
 * utility function to that prints logs the internal state of the global pool 
 */
#[cfg(feature = "log-state")]
pub fn log() {
  GLOBAL_POOL.log();
}

/**
 * Check if the upstream is healthy.\
 * This will only check if the upstream is reachable and the connection and hanshake can be made.\
 * It will not send a request or check that the upstreams returns a somewhat valid response.\
 */
pub async fn healthcheck(key: Key) -> Result<(), ConnectError> {
  #[cfg(feature = "stats")]
  let read_counter = Arc::new(AtomicU64::new(0));
  #[cfg(feature = "stats")]
  let write_counter = Arc::new(AtomicU64::new(0));
  let mut sender = Sender::connect(
    key,
    #[cfg(feature = "stats")]
    &read_counter,
    #[cfg(feature = "stats")]
    &write_counter,
    Weak::default()
  ).await?;
  sender.ready().await?;
  Ok(())
}

#[cfg(test)]
mod test {
  use super::*;

  #[allow(unused)]
  trait AssertSend: Send {}
  impl AssertSend for ConnectError {}
  impl AssertSend for ClientError {}
  impl AssertSend for SendRequest {}
  impl AssertSend for Sender {}

  #[allow(unused)]
  trait AssertSync: Sync {}
  impl AssertSync for ConnectError {}
  impl AssertSync for ClientError {}
  impl AssertSync for SendRequest {}
  impl AssertSync for Sender {}
}
