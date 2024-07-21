use crate::proxy_protocol::ProxyHeader;
use hyper::{body::Incoming, service::Service, Request};
use std::future::Future;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AddrService<S: Service<Request<Incoming>>> {
  fn make_service(&self, addr: SocketAddr, proxy_header: Option<ProxyHeader>) -> S;
}

// impl<S: Service<Request<Incoming>>, F: Clone + FnOnce(SocketAddr, Option<ProxyHeader>) -> S> AddrService<S> for F {
//   fn make_service(&self, addr: SocketAddr, proxy_header: Option<ProxyHeader>) -> S {
//     let f = self.clone();
//     f(addr, proxy_header)
//   }
// }

#[derive(Debug, Clone)]
pub struct Connection<S> {
  pub stream: S,
  pub local_addr: SocketAddr,
  pub remote_addr: SocketAddr,
  pub proxy_header: Option<ProxyHeader>,
  pub is_ssl: bool,
}

pub trait StreamService<S: AsyncRead + AsyncWrite> {
  type Future: Future<Output = Result<(), Self::Error>>;
  type Error: std::error::Error;
  /**
   * takes a (Stream, remote_addr, local_addr) and returns a future that will be resolved when the stream is closed
   */
  fn serve(&self, connection: Connection<S>) -> Self::Future;
}
