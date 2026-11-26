//! After a config reload (SIGUSR1), a connection still busy on the previous
//! instance — a live stream — keeps running for its app's
//! `reload_drain_timeout` (default from `http`), then it is cut. Before this,
//! nothing ever cut it: its task outlived the instance in the same process.
//! A `reload_drain_timeout` above 6 h is a config error that leaves the
//! running instance serving.
mod common;
use std::time::{Duration, Instant};

use clap::Parser;
use common::{block_on, dir};
use proxide::cli::{self, args::Args};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PORT: u16 = 25643;
const UPSTREAM: u16 = 25644;

/// An upstream that answers every request with an endless chunked body.
async fn endless_upstream() {
  let listener = tokio::net::TcpListener::bind(("127.0.0.1", UPSTREAM))
    .await
    .unwrap();
  loop {
    let (mut s, _) = listener.accept().await.unwrap();
    tokio::spawn(async move {
      let mut buf = [0u8; 4096];
      let _ = s.read(&mut buf).await;
      let _ = s
        .write_all(
          b"HTTP/1.1 200 OK\r\ncontent-type: audio/mpeg\r\ntransfer-encoding: chunked\r\n\r\n",
        )
        .await;
      loop {
        if s.write_all(b"400\r\n").await.is_err() {
          return;
        }
        if s.write_all(&[b'x'; 1024]).await.is_err() {
          return;
        }
        if s.write_all(b"\r\n").await.is_err() {
          return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    });
  }
}

/// Stream from proxide as `host`; resolves with the instant the stream ended.
async fn stream(host: &'static str) -> Instant {
  let mut s = tokio::net::TcpStream::connect(("127.0.0.1", PORT))
    .await
    .unwrap();
  s.write_all(format!("GET /live HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let mut buf = [0u8; 8192];
  loop {
    match s.read(&mut buf).await {
      Ok(0) | Err(_) => return Instant::now(),
      Ok(_) => {}
    }
  }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn reload_drains_busy_connections_per_app() {
  block_on(async move {
    let dir = dir();
    let cfg_path = dir.file("config.yml");
    let signal_cfg = dir.file("signal.yml");
    let pidfile = dir.file("proxide.pid");
    let config = |proxy_drain: &str| {
      include_str!("reload-drain.yml")
        .replace("%PIDFILE%", &pidfile)
        .replace("%PROXY_DRAIN%", proxy_drain)
    };
    std::fs::write(&cfg_path, config("4s")).unwrap();
    std::fs::write(&signal_cfg, config("4s")).unwrap();

    tokio::spawn(endless_upstream());
    let args = Args::try_parse_from(["proxide", "start", "--config", &cfg_path]).unwrap();
    std::thread::spawn(move || {
      cli::run(args).unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let signal = || {
      let args = Args::try_parse_from([
        "proxide",
        "signal",
        "--config",
        &signal_cfg,
        "--signal",
        "reload",
      ])
      .unwrap();
      cli::run(args).unwrap();
    };

    let proxy = tokio::spawn(stream("proxy.test"));
    let site = tokio::spawn(stream("site.test"));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // above 6 h: rejected, nothing is cut
    std::fs::write(&cfg_path, config("7h")).unwrap();
    signal();
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(
      !proxy.is_finished() && !site.is_finished(),
      "a rejected reload cut a stream"
    );

    // a valid reload: site.test drains for the http default (2 s), proxy.test
    // for its own 4 s
    std::fs::write(&cfg_path, config("4s")).unwrap();
    let reloaded = Instant::now();
    signal();
    let site_end = site.await.unwrap().duration_since(reloaded);
    let proxy_end = proxy.await.unwrap().duration_since(reloaded);
    assert!(
      site_end >= Duration::from_millis(1500) && site_end <= Duration::from_millis(3500),
      "site.test cut after {site_end:?}, expected ~2 s"
    );
    assert!(
      proxy_end >= Duration::from_millis(3500) && proxy_end <= Duration::from_millis(5500),
      "proxy.test cut after {proxy_end:?}, expected ~4 s"
    );
  })
}
