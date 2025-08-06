pub mod timeout;

use socket2::{Domain, SockAddr, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub fn bind(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
  let socket = if addr.is_ipv4() {
    Socket::new(Domain::IPV4, Type::STREAM, None)?
  } else {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(true)?;
    socket
  };

  socket.set_reuse_address(true)?;

  #[cfg(unix)]
  socket.set_reuse_port(true)?;

  socket.set_nonblocking(true)?;

  socket.bind(&SockAddr::from(addr))?;

  socket.listen(128)?;

  let tcp = TcpListener::from_std(socket.into())?;

  Ok(tcp)
}

// pub fn tcp_keepalive(tcp: &TcpStream, interval: Duration, retries: u32, time: Duration) -> Result<(), std::io::Error> {
//   use socket2::{SockRef, TcpKeepalive};

//   let keepalive = TcpKeepalive::new()
//     .with_interval(interval)
//     .with_retries(retries)
//     .with_time(time);

//   let socket_ref = SockRef::from(tcp);

//   socket_ref.set_keepalive(true)?;
//   socket_ref.set_tcp_keepalive(&keepalive)?;

//   Ok(())

// }
