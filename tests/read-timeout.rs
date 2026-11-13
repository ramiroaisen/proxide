//! The read timeout of a connection is an inactivity timeout: it must only
//! close a connection when the peer is the one that is expected to send
//! something and it does not. A peer that is legitimately silent, because
//! it is receiving a response, waiting for one, or receiving the other
//! direction of a tunnel, must not be cut by it.
//!
//! Every timeout in read-timeout.yml is 1s and every exchange here takes
//! about 3s.

mod common;

use bytes::Bytes;
use futures::StreamExt;
use http::Version;
use std::{
  convert::Infallible,
  sync::OnceLock,
  time::{Duration, Instant},
};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  runtime::Runtime,
};

const HTTP: u16 = 26400;
const HTTPS: u16 = 26401;
const TCP: u16 = 26402;
const HTTP_SHORT_PROXY_READ: u16 = 26403;
const WS: u16 = 26404;
const WSS: u16 = 26405;

const UPSTREAM_HTTP: u16 = 26450;
const UPSTREAM_TCP: u16 = 26451;
const UPSTREAM_WS: u16 = 26453;

/// the configured timeouts
const TIMEOUT: Duration = Duration::from_secs(1);
/// a timeout that applies must have closed the connection by now
const CLOSED_BY: Duration = Duration::from_millis(2500);
/// and must not have closed it before this
const NOT_CLOSED_BEFORE: Duration = Duration::from_millis(700);

const TICKS: usize = 15;
const TICK: Duration = Duration::from_millis(200);

/// one proxide instance and one set of upstreams for the whole test binary
fn rt() -> &'static Runtime {
  static RT: OnceLock<&'static Runtime> = OnceLock::new();
  RT.get_or_init(|| {
    let rt: &'static Runtime = Box::leak(Box::new(common::runtime()));

    let config: proxide::config::Config =
      serde_norway::from_str(include_str!("read-timeout.yml")).expect("config parse");

    let handle = rt
      .block_on(proxide::cli::cmd::start::instance_from_config(
        Default::default(),
        config,
        tokio_util::sync::CancellationToken::new(),
      ))
      .unwrap();
    std::mem::forget(handle);

    rt.block_on(async {
      let http = TcpListener::bind(("127.0.0.1", UPSTREAM_HTTP))
        .await
        .unwrap();
      let tcp = TcpListener::bind(("127.0.0.1", UPSTREAM_TCP))
        .await
        .unwrap();
      let ws = TcpListener::bind(("127.0.0.1", UPSTREAM_WS)).await.unwrap();
      tokio::spawn(upstream_http(http));
      tokio::spawn(upstream_tcp(tcp));
      tokio::spawn(upstream_ws(ws));
    });

    rt
  })
}

// ---------------------------------------------------------------- upstreams

async fn upstream_http(listener: TcpListener) {
  use axum::routing::{get, post};

  let app = axum::Router::<()>::new()
    // a body that keeps flowing for ~3s
    .route(
      "/stream",
      get(|| async {
        axum::body::Body::from_stream(async_stream::stream! {
          for _ in 0..TICKS {
            tokio::time::sleep(TICK).await;
            yield Ok::<_, Infallible>(Bytes::from(vec![b'a'; 1000]));
          }
        })
      }),
    )
    // a response that takes ~3s to start
    .route(
      "/slow",
      get(|| async {
        tokio::time::sleep(TICK * TICKS as u32).await;
        "slow-ok"
      }),
    )
    // a body that starts right away and then stays silent for ~3s
    .route(
      "/gap",
      get(|| async {
        axum::body::Body::from_stream(async_stream::stream! {
          yield Ok::<_, Infallible>(Bytes::from_static(b"a"));
          tokio::time::sleep(TICK * TICKS as u32).await;
          yield Ok::<_, Infallible>(Bytes::from_static(b"b"));
        })
      }),
    )
    // a body that never ends
    .route(
      "/flood",
      get(|| async {
        axum::body::Body::from_stream(async_stream::stream! {
          loop {
            yield Ok::<_, Infallible>(Bytes::from(vec![b'f'; 64 * 1024]));
          }
        })
      }),
    )
    // silent until the whole request body arrived
    .route(
      "/upload",
      post(|body: Bytes| async move { body.len().to_string() }),
    );

  axum::serve(listener, app.into_make_service())
    .await
    .unwrap();
}

/// the first byte of the client selects what the upstream does:
/// - `p`: push one byte every tick, the client stays silent
/// - `t`: stay silent while the client talks, answer with the count at `.`
/// - anything else: stay silent forever
async fn upstream_tcp(listener: TcpListener) {
  loop {
    let (mut stream, _) = listener.accept().await.unwrap();
    tokio::spawn(async move {
      let mut mode = [0u8; 1];
      if stream.read_exact(&mut mode).await.is_err() {
        return;
      }

      match mode[0] {
        b'p' => {
          for _ in 0..TICKS {
            tokio::time::sleep(TICK).await;
            if stream.write_all(b"x").await.is_err() {
              return;
            }
          }
        }

        b't' => {
          let mut count = 0usize;
          let mut byte = [0u8; 1];
          loop {
            match stream.read(&mut byte).await {
              Ok(1) if byte[0] == b'.' => break,
              Ok(1) => count += 1,
              _ => return,
            }
          }
          let _ = stream.write_all(count.to_string().as_bytes()).await;
        }

        _ => {
          let mut buf = [0u8; 64];
          while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
        }
      }
    });
  }
}

/// pushes one message every tick and then closes, never expects a message
async fn upstream_ws(listener: TcpListener) {
  loop {
    let (stream, _) = listener.accept().await.unwrap();
    tokio::spawn(async move {
      let mut ws = match async_tungstenite::tokio::accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => return,
      };

      for i in 0..TICKS {
        tokio::time::sleep(TICK).await;
        if ws.send(i.to_string().into()).await.is_err() {
          return;
        }
      }

      let _ = ws.close(None).await;
    });
  }
}

// ------------------------------------------------------------------ helpers

const VARIANTS: [(Version, &str, u16); 4] = [
  (Version::HTTP_11, "http", HTTP),
  (Version::HTTP_2, "http", HTTP),
  (Version::HTTP_11, "https", HTTPS),
  (Version::HTTP_2, "https", HTTPS),
];

async fn get(version: Version, scheme: &str, port: u16, path: &str) -> reqwest::Response {
  let uri = format!("{scheme}://127.0.0.1:{port}{path}");
  let mut req = reqwest::Request::new("GET".parse().unwrap(), uri.parse().unwrap());
  *req.version_mut() = version;
  common::request(req)
    .await
    .unwrap_or_else(|e| panic!("{version:?} {scheme} {path}: {e:?}"))
}

async fn connect(port: u16) -> TcpStream {
  TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

/// reads one http/1.1 response with a content-length from a raw connection
async fn read_response(stream: &mut TcpStream) -> (u16, Vec<u8>) {
  let mut acc = Vec::<u8>::new();
  let mut buf = [0u8; 4096];

  let head_end = loop {
    if let Some(i) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
      break i + 4;
    }
    let n = stream.read(&mut buf).await.expect("read response head");
    assert_ne!(n, 0, "connection closed before the response head");
    acc.extend_from_slice(&buf[..n]);
  };

  let head = String::from_utf8_lossy(&acc[..head_end]).to_ascii_lowercase();
  let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
  let len: usize = head
    .lines()
    .find_map(|line| line.strip_prefix("content-length:"))
    .expect("content-length")
    .trim()
    .parse()
    .unwrap();

  while acc.len() < head_end + len {
    let n = stream.read(&mut buf).await.expect("read response body");
    assert_ne!(
      n, 0,
      "connection closed before the end of the response body"
    );
    acc.extend_from_slice(&buf[..n]);
  }

  (status, acc[head_end..head_end + len].to_vec())
}

/// waits until the peer closes the connection, discarding what it sends,
/// returns None if it is still open after `limit`
async fn closed_within(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
  let start = Instant::now();
  let mut buf = vec![0u8; 64 * 1024];
  let wait = async {
    loop {
      match stream.read(&mut buf).await {
        Ok(0) | Err(_) => break,
        Ok(_) => {}
      }
    }
  };

  match tokio::time::timeout(limit, wait).await {
    Ok(()) => Some(start.elapsed()),
    Err(_) => None,
  }
}

/// asserts that an idle connection is closed by the read timeout, on time
async fn assert_closed_by_timeout(stream: &mut TcpStream, what: &str) {
  let elapsed = closed_within(stream, CLOSED_BY)
    .await
    .unwrap_or_else(|| panic!("{what}: connection still open after {CLOSED_BY:?}"));

  assert!(
    elapsed >= NOT_CLOSED_BEFORE,
    "{what}: connection closed after {elapsed:?}, before the {TIMEOUT:?} timeout"
  );
}

// ------------------------------------------- must survive the read timeout

/// a response body that is still being written when the read timeout
/// elapses, the client has nothing to send in the meantime
#[test]
fn response_longer_than_read_timeout() {
  rt().block_on(async {
    let all = VARIANTS.map(|(version, scheme, port)| async move {
      let res = get(version, scheme, port, "/stream").await;
      assert_status!(res, 200);
      let body = res
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("{version:?} {scheme}: body cut: {e:?}"));
      assert_eq!(body.len(), TICKS * 1000, "{version:?} {scheme}");
    });

    futures::future::join_all(all).await;
  })
}

/// an upstream that takes longer than the server read timeout to answer,
/// the wait is bounded by proxy_read_timeout and not by server_read_timeout
#[test]
fn slow_upstream_response() {
  rt().block_on(async {
    let all = VARIANTS.map(|(version, scheme, port)| async move {
      let res = get(version, scheme, port, "/slow").await;
      assert_status!(res, 200);
      assert_body!(res, "slow-ok");
    });

    futures::future::join_all(all).await;
  })
}

/// a response body that goes silent for longer than the read timeout
/// because the upstream has nothing to send yet
#[test]
fn silent_gap_in_response_body() {
  rt().block_on(async {
    let all = VARIANTS.map(|(version, scheme, port)| async move {
      let res = get(version, scheme, port, "/gap").await;
      assert_status!(res, 200);
      let body = res
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("{version:?} {scheme}: body cut: {e:?}"));
      assert_eq!(body.as_ref(), b"ab", "{version:?} {scheme}");
    });

    futures::future::join_all(all).await;
  })
}

/// a websocket where only the server talks
#[test]
fn websocket_server_push() {
  rt().block_on(async {
    for (scheme, port) in [("ws", WS), ("wss", WSS)] {
      let mut ws = common::ws(&format!("{scheme}://127.0.0.1:{port}/"))
        .await
        .unwrap();

      let mut received = 0;
      while let Some(msg) = ws.next().await {
        match msg {
          Ok(reqwest_websocket::Message::Text(_)) => received += 1,
          Ok(reqwest_websocket::Message::Close { .. }) => break,
          Ok(_) => {}
          Err(e) => panic!("{scheme}: websocket cut after {received} messages: {e:?}"),
        }
      }

      assert_eq!(received, TICKS, "{scheme}");
    }
  })
}

/// a tcp tunnel where only the upstream talks
#[test]
fn tcp_upstream_push() {
  rt().block_on(async {
    let mut stream = connect(TCP).await;
    stream.write_all(b"p").await.unwrap();

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), TICKS);
  })
}

/// a tcp tunnel where only the client talks
#[test]
fn tcp_client_push() {
  rt().block_on(async {
    let mut stream = connect(TCP).await;
    stream.write_all(b"t").await.unwrap();

    for _ in 0..TICKS {
      tokio::time::sleep(TICK).await;
      stream
        .write_all(b"x")
        .await
        .expect("tunnel closed while the client was sending");
    }
    stream.write_all(b".").await.unwrap();

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&received), TICKS.to_string());
  })
}

/// a request body that takes longer than the upstream read timeout to
/// upload, the upstream has nothing to send until it is complete
#[test]
fn upload_longer_than_proxy_read_timeout() {
  rt().block_on(async {
    let mut stream = connect(HTTP_SHORT_PROXY_READ).await;

    let head = format!(
      "POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n\r\n",
      TICKS * 100
    );
    stream.write_all(head.as_bytes()).await.unwrap();

    for _ in 0..TICKS {
      tokio::time::sleep(TICK).await;
      stream
        .write_all(&[b'u'; 100])
        .await
        .expect("connection closed during the upload");
    }

    let (status, body) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), (TICKS * 100).to_string());
  })
}

/// a keep-alive connection is still usable after a slow response, and the
/// read timeout starts counting again once the response is complete
#[test]
fn keep_alive_after_slow_response() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;

    for _ in 0..2 {
      stream
        .write_all(b"GET /slow HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .unwrap();
      let (status, body) = read_response(&mut stream).await;
      assert_eq!(status, 200);
      assert_eq!(body, b"slow-ok");
    }

    assert_closed_by_timeout(&mut stream, "idle after slow response").await;
  })
}

// --------------------------------------------- must still be cut on time

/// a connection that never sends a request
#[test]
fn idle_connection_is_closed() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;
    assert_closed_by_timeout(&mut stream, "idle connection").await;
  })
}

/// a request head that never completes
#[test]
fn stalled_request_head_is_closed() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;
    stream
      .write_all(b"GET /slow HTTP/1.1\r\nhost: localhost\r\n")
      .await
      .unwrap();
    assert_closed_by_timeout(&mut stream, "stalled request head").await;
  })
}

/// a request body that never completes
#[test]
fn stalled_request_body_is_closed() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;
    stream
      .write_all(
        b"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: 100\r\n\r\n0123456789",
      )
      .await
      .unwrap();
    assert_closed_by_timeout(&mut stream, "stalled request body").await;
  })
}

/// a keep-alive connection that goes idle after a response
#[test]
fn idle_keep_alive_connection_is_closed() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;
    stream
      .write_all(b"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: 3\r\n\r\nabc")
      .await
      .unwrap();
    let (status, body) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"3");

    assert_closed_by_timeout(&mut stream, "idle keep-alive connection").await;
  })
}

/// a tcp tunnel where nobody talks
#[test]
fn idle_tcp_tunnel_is_closed() {
  rt().block_on(async {
    let mut stream = connect(TCP).await;
    stream.write_all(b"i").await.unwrap();
    assert_closed_by_timeout(&mut stream, "idle tcp tunnel").await;
  })
}

/// an upstream that stays silent for longer than proxy_read_timeout while
/// it is the one expected to answer
#[test]
fn silent_upstream_hits_proxy_read_timeout() {
  rt().block_on(async {
    let start = Instant::now();
    let res = get(Version::HTTP_11, "http", HTTP_SHORT_PROXY_READ, "/slow").await;
    let elapsed = start.elapsed();

    assert!(res.status().is_server_error(), "status {}", res.status());
    assert!(
      (NOT_CLOSED_BEFORE..CLOSED_BY).contains(&elapsed),
      "proxy read timeout after {elapsed:?}"
    );
  })
}

/// an http/1.1 client that stops reading the response: the socket fills
/// up and the write timeout closes the connection
#[test]
fn stalled_reader_is_closed_h1() {
  rt().block_on(async {
    let mut stream = connect(HTTP).await;
    stream
      .write_all(b"GET /flood HTTP/1.1\r\nhost: localhost\r\n\r\n")
      .await
      .unwrap();

    // not reading: give the write timeout time to fire
    tokio::time::sleep(TIMEOUT * 3).await;

    // /flood never ends by itself, so reaching the end means it was cut
    assert!(
      closed_within(&mut stream, Duration::from_secs(10))
        .await
        .is_some(),
      "connection of a stalled reader was never closed"
    );
  })
}

/// an http/2 client that stops reading the response: flow control stalls
/// the stream without ever blocking a socket write, so only the read
/// timeout can close the connection
#[test]
fn stalled_reader_is_closed_h2() {
  rt().block_on(async {
    let mut res = get(Version::HTTP_2, "http", HTTP, "/flood").await;
    assert_status!(res, 200);

    // not reading: give the timeout time to fire
    tokio::time::sleep(TIMEOUT * 3).await;

    let drain = async { while let Ok(Some(_)) = res.chunk().await {} };

    // /flood never ends by itself, so reaching the end means it was cut
    assert!(
      tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_ok(),
      "connection of a stalled reader was never closed"
    );
  })
}

/// an http/2 client that opens its streams with an empty flow control
/// window and never opens it: the response is there to be taken from the
/// first moment, nothing of its body is ever asked for
#[test]
fn zero_window_reader_is_closed_h2() {
  rt().block_on(async {
    let tcp = connect(HTTP).await;
    let (mut send_request, connection) = h2::client::Builder::new()
      .initial_window_size(0)
      .handshake::<_, Bytes>(tcp)
      .await
      .unwrap();

    let start = Instant::now();
    let closed = tokio::spawn(async move {
      let _ = connection.await;
      start.elapsed()
    });

    let request = http::Request::get("http://127.0.0.1/stream")
      .body(())
      .unwrap();
    let (response, _) = send_request.send_request(request, true).unwrap();
    // only the head arrives, then proxide can not send anything else
    let _response = tokio::time::timeout(CLOSED_BY, response).await;

    let elapsed = tokio::time::timeout(CLOSED_BY, closed)
      .await
      .unwrap_or_else(|_| panic!("zero window connection still open after {CLOSED_BY:?}"))
      .unwrap();

    assert!(
      elapsed >= NOT_CLOSED_BEFORE,
      "connection closed after {elapsed:?}, before the {TIMEOUT:?} timeout"
    );
  })
}
