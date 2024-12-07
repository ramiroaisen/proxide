#![allow(non_camel_case_types)] // silence #[dynamic] warning
#![allow(non_upper_case_globals)] // silence #[dynamic] warning
use hyper_rustls::ConfigBuilderExt;
use rustls::pki_types::ServerName;
use static_init::dynamic;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::time::FutureExt;
use url::Host;

use super::error::ProxyStreamError;
use crate::client::pool::ProxyProtocolConfig;
use crate::net::timeout::TimeoutIo;
use crate::proxy_protocol::{ProxyHeader, ProxyProtocolVersion};
#[allow(unused)]
use crate::serde::content_type::ContentTypeMatcher;
use crate::serde::sni::Sni;
use crate::serde::url::StreamUpstreamScheme;
use crate::tls::danger_no_cert_verifier::DangerNoCertVerifier;

pub async fn tcp_connect(
  host: Host,
  port: u16,
  proxy_tcp_nodelay: bool,
) -> Result<TcpStream, ProxyStreamError> {
  // unwrap: upstream origin host is checked at construction
  let connect = match host {
    Host::Domain(domain) => TcpStream::connect((domain, port)).await,
    Host::Ipv4(ipv4) => TcpStream::connect((ipv4, port)).await,
    Host::Ipv6(ipv6) => TcpStream::connect((ipv6, port)).await,
  };

  let stream = connect.map_err(ProxyStreamError::TcpConnect)?;

  if proxy_tcp_nodelay {
    stream
      .set_nodelay(true)
      .map_err(ProxyStreamError::SetTcpNoDelay)?;
  }

  Ok(stream)
}

pub async fn write_proxy_protocol<T: AsyncWrite + AsyncRead + Unpin>(
  stream: &mut T,
  config: ProxyProtocolConfig,
) -> Result<(), ProxyStreamError> {
  let ProxyProtocolConfig {
    header,
    version,
    timeout,
  } = config;

  let buf = crate::proxy_protocol::encode(&header, version)
    .map_err(ProxyStreamError::ProxyProtocolEncode)?;

  stream
    .write_all(&buf)
    .timeout(timeout)
    .await
    .map_err(|_| ProxyStreamError::ProxyProtocolWriteTimeout)?
    .map_err(ProxyStreamError::ProxyProtocolWrite)?;

  Ok(())
}

pub async fn tls_handshake<T: AsyncWrite + AsyncRead + Unpin>(
  stream: T,
  server_name: ServerName<'static>,
  danger_accept_invalid_certs: bool,
) -> Result<TlsStream<T>, ProxyStreamError> {
  let tls_connector = match danger_accept_invalid_certs {
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

  let tls_stream = tls_connector
    .connect(server_name, stream)
    .await
    .map_err(ProxyStreamError::TlsConnect)?;

  Ok(tls_stream)
}

// pub async fn healthcheck(
//   tls: bool,
//   host: Host<&str>,
//   port: u16
// ) -> Result<(), ProxyStreamError> {

#[allow(clippy::too_many_arguments)]
pub async fn healthcheck(
  scheme: StreamUpstreamScheme,
  host: Host,
  port: u16,
  proxy_tcp_nodelay: bool,
  proxy_read_timeout: Duration,
  proxy_write_timeout: Duration,
  send_proxy_protocol: Option<ProxyProtocolVersion>,
  proxy_protocol_write_timeout: Duration,
  sni: Option<Sni>,
  danger_accept_invalid_certs: bool,
) -> Result<(), ProxyStreamError> {
  let mut stream = match tcp_connect(host.clone(), port, proxy_tcp_nodelay).await {
    Ok(stream) => stream,
    Err(e) => {
      log::warn!("proxy request error: {e} {e:?}");
      return Err(e);
    }
  };

  let is_tls = match scheme {
    StreamUpstreamScheme::Tcp => false,
    StreamUpstreamScheme::Ssl | StreamUpstreamScheme::Tls => true,
  };

  if !is_tls {
    return Ok(());
  }

  if proxy_tcp_nodelay {
    stream
      .set_nodelay(true)
      .map_err(ProxyStreamError::SetTcpNoDelay)?;
  }

  if let Some(version) = send_proxy_protocol {
    let proxy_protocol_config = ProxyProtocolConfig {
      version,
      header: ProxyHeader::Local,
      timeout: proxy_protocol_write_timeout,
    };

    write_proxy_protocol(&mut stream, proxy_protocol_config).await?;
  };

  let io = TimeoutIo::new(stream, proxy_read_timeout, proxy_write_timeout);
  tokio::pin!(io);

  let server_name = match sni {
    Some(sni) => sni.0.clone(),
    None => ServerName::try_from(host.to_string())?,
  };

  tls_handshake(io, server_name, danger_accept_invalid_certs).await?;

  Ok(())
}
