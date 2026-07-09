use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{block_on, get};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod common;

// delay before responding, so concurrent requests are forced to open separate connections
const RESPONSE_DELAY: Duration = Duration::from_millis(300);

// minimal keep-alive http/1.1 upstream that tracks its number of open connections
async fn start_upstream(open: Arc<AtomicUsize>) {
  let listener = TcpListener::bind("127.0.0.1:26201").await.unwrap();

  tokio::spawn(async move {
    loop {
      let (mut stream, _) = match listener.accept().await {
        Ok(accept) => accept,
        Err(_) => break,
      };

      let open = open.clone();
      tokio::spawn(async move {
        open.fetch_add(1, Ordering::AcqRel);

        let mut buf = [0u8; 4096];
        let mut acc = Vec::<u8>::new();

        'conn: loop {
          // read until the end of the request head (requests have no body)
          while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
              Ok(0) | Err(_) => break 'conn,
              Ok(n) => acc.extend_from_slice(&buf[..n]),
            }
          }
          acc.clear();

          tokio::time::sleep(RESPONSE_DELAY).await;

          let res = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok";
          if stream.write_all(res).await.is_err() {
            break 'conn;
          }
        }

        open.fetch_sub(1, Ordering::AcqRel);
      });
    }
  });
}

async fn wait_for_open(open: &Arc<AtomicUsize>, expected: usize, timeout: Duration) {
  let start = Instant::now();
  loop {
    if open.load(Ordering::Acquire) == expected {
      return;
    }
    if start.elapsed() >= timeout {
      assert_eq!(
        open.load(Ordering::Acquire),
        expected,
        "open upstream connections did not reach the expected count within {timeout:?}"
      );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
}

#[test]
fn proxy_connection_idle_timeout() {
  launch!("proxy-connection-idle-timeout.yml");

  block_on(async move {
    let open = Arc::new(AtomicUsize::new(0));
    start_upstream(open.clone()).await;

    // one request opens one pooled upstream connection
    let res = get("http://127.0.0.1:26200/").await.unwrap();
    assert_status!(res, OK);
    assert_eq!(open.load(Ordering::Acquire), 1);

    // the pooled connection stays alive while the idle timeout has not elapsed
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(open.load(Ordering::Acquire), 1);

    // and is closed once it stays idle past proxy_connection_idle_timeout
    wait_for_open(&open, 0, Duration::from_secs(5)).await;

    // two overlapping requests open two upstream connections
    let (a, b) = tokio::join!(
      get("http://127.0.0.1:26200/"),
      get("http://127.0.0.1:26200/"),
    );
    assert_status!(a.unwrap(), OK);
    assert_status!(b.unwrap(), OK);
    assert_eq!(open.load(Ordering::Acquire), 2);

    // under steady sequential traffic the pool reuses the most recently used
    // connection (LIFO), so the other one idles out and is closed while
    // requests keep being served
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
      let res = get("http://127.0.0.1:26200/").await.unwrap();
      assert_status!(res, OK);
      tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(
      open.load(Ordering::Acquire),
      1,
      "expected only the most recently used connection to stay alive"
    );
  })
}
