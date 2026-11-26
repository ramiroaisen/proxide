//! A reload must reach the connections that are already open, at once.
//!
//! Regression (2026-11-26): on SIGUSR1 the previous instance stopped
//! accepting, but only shut its keep-alive connections down once every
//! pending TLS handshake had finished or timed out (60 s by default) — so a
//! single client that opened a TCP connection and never sent a ClientHello
//! kept every keep-alive connection answering with the OLD config. Seen in
//! production behind Cloudflare, which reuses its origin connections.
//!
//! Also: a reload to a config that binds nothing used to panic the whole
//! process (`start.send(()).unwrap()`); it must be an error that leaves the
//! running instance serving.
mod common;
use std::time::Duration;

use clap::Parser;
use common::{block_on, dir};
use proxide::cli::{self, args::Args};
use reqwest::ClientBuilder;

const PORT: u16 = 25543;

#[cfg(not(target_os = "windows"))]
#[test]
fn reload_reaches_open_keepalive_connections() {
  block_on(async move {
    let dir = dir();
    let cfg_path = dir.file("config.yml");
    let pidfile = dir.file("proxide.pid");
    let config = |version: &str| {
      include_str!("reload-keepalive.yml")
        .replace("%PIDFILE%", &pidfile)
        .replace("%VERSION%", version)
    };
    std::fs::write(&cfg_path, config("1")).unwrap();

    let args = Args::try_parse_from(["proxide", "start", "--config", &cfg_path]).unwrap();
    std::thread::spawn(move || {
      cli::run(args).unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // reqwest keeps the connection alive and reuses it
    let client = ClientBuilder::new()
      .danger_accept_invalid_certs(true)
      .pool_idle_timeout(Duration::from_secs(120))
      .build()
      .unwrap();
    let url = format!("https://127.0.0.1:{PORT}/");
    let version = |res: &reqwest::Response| {
      res
        .headers()
        .get("x-version")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
    };
    let res = client.get(&url).send().await.unwrap();
    assert_eq!(version(&res), "1");

    // a client stuck before its TLS handshake, like the scanners in production
    let _stuck = tokio::net::TcpStream::connect(("127.0.0.1", PORT))
      .await
      .unwrap();

    let signal = |cfg_path: &str| {
      let args = Args::try_parse_from([
        "proxide", "signal", "--config", cfg_path, "--signal", "reload",
      ])
      .unwrap();
      cli::run(args).unwrap();
    };

    std::fs::write(&cfg_path, config("2")).unwrap();
    signal(&cfg_path);
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // the kept-alive connection must have been closed: the request goes to
    // the new instance on a fresh connection
    for _ in 0..20 {
      let res = client.get(&url).send().await.unwrap();
      assert_eq!(
        version(&res),
        "2",
        "a kept-alive connection still serves the old config"
      );
    }

    // a reload to a config that binds nothing is an error, not a panic, and
    // the running instance keeps serving
    // (`proxide signal` reads the pidfile from a config, so it gets a copy of
    // the last good one while the instance reloads the empty file)
    let signal_cfg = dir.file("signal.yml");
    std::fs::write(&signal_cfg, config("2")).unwrap();
    std::fs::write(&cfg_path, "").unwrap();
    signal(&signal_cfg);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let res = ClientBuilder::new()
      .danger_accept_invalid_certs(true)
      .build()
      .unwrap()
      .get(&url)
      .send()
      .await
      .expect("proxide must still be serving after a reload to an empty config");
    assert_eq!(version(&res), "2");
  })
}
