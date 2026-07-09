use std::time::{Duration, Instant};

use common::{block_on, get};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

mod common;

// connects to addr and stalls the tls handshake by never sending a client hello,
// then asserts the server closes the connection after the configured 1s timeout
async fn assert_stalled_handshake_is_closed(addr: &str) {
  let mut stream = TcpStream::connect(addr).await.unwrap();
  let start = Instant::now();

  let mut buf = [0u8; 16];
  // a FIN (Ok(0)) or a RST (Err) both mean the server closed the connection
  let closed = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await;
  let n = match closed {
    Ok(Ok(n)) => n,
    Ok(Err(_)) => 0,
    Err(_) => panic!("{addr}: connection was not closed after the tls handshake timeout"),
  };
  assert_eq!(n, 0, "{addr}: expected the connection to be closed without data");

  let elapsed = start.elapsed();
  assert!(
    elapsed >= Duration::from_millis(500),
    "{addr}: connection closed before the tls handshake timeout elapsed: {elapsed:?}"
  );
}

#[test]
fn server_tls_handshake_timeout() {
  launch!("server-tls-handshake-timeout.yml");

  block_on(async move {
    // sanity check: a well-behaved tls client is not affected by the handshake timeout
    let res = get("https://127.0.0.1:26100/").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "server-tls-handshake-timeout");

    // https listener and stream ssl listener close stalled handshakes
    tokio::join!(
      assert_stalled_handshake_is_closed("127.0.0.1:26100"),
      assert_stalled_handshake_is_closed("127.0.0.1:26101"),
    );
  })
}
