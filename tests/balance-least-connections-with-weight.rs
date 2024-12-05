mod common;
use common::{block_on, ws};
use futures::{SinkExt, StreamExt};
use reqwest_websocket::Message;
use std::{
  sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  },
  thread,
  time::Duration,
};
use tokio::net::TcpListener;

#[test]
fn balance_least_connections_with_weight() {
  launch!("balance-least-connections-with-weight.yml");

  block_on(async move {
    for p in [0, 1] {
      if p == 0 {
        log::info!("starting test for http");
      } else {
        log::info!("starting test for stream");
      }

      let s0 = Arc::new(AtomicUsize::new(0));
      let s1 = Arc::new(AtomicUsize::new(0));
      let s2 = Arc::new(AtomicUsize::new(0));
      let s3 = Arc::new(AtomicUsize::new(0));

      // servers
      for i in 0..4 {
        let (s0, s1, s2, s3) = (s0.clone(), s1.clone(), s2.clone(), s3.clone());
        let server = TcpListener::bind(format!("127.0.0.1:66{d}{i}", d = 5 + p))
          .await
          .unwrap();

        tokio::spawn(async move {
          loop {
            let (stream, _) = server.accept().await.unwrap();
            let (s0, s1, s2, s3) = (s0.clone(), s1.clone(), s2.clone(), s3.clone());
            tokio::spawn(async move {
              let mut ws = match async_tungstenite::tokio::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                  log::warn!("error accepting ws stream: {e}");
                  return;
                }
              };

              ws.next().await.unwrap().unwrap();

              match i {
                0 => s0.fetch_add(1, Ordering::SeqCst),
                1 => s1.fetch_add(1, Ordering::SeqCst),
                2 => s2.fetch_add(1, Ordering::SeqCst),
                3 => s3.fetch_add(1, Ordering::SeqCst),
                _ => unreachable!(),
              };

              tokio::time::sleep(Duration::from_millis(60_000)).await;
            });
          }
        });
      }

      tokio::time::sleep(Duration::from_millis(100)).await;

      // clients
      for _ in 1..=100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut ws = ws(&format!("ws://127.0.0.1:660{p}/")).await.unwrap();
        ws.send(Message::Text(String::from("hello"))).await.unwrap();
        tokio::spawn(async move {
          tokio::time::sleep(Duration::from_millis(120_000)).await;
          drop(ws);
        });
      }

      thread::sleep(Duration::from_millis(100));

      macro_rules! check {
        ($e:ident, $n:expr) => {
          let v = $e.load(Ordering::SeqCst);
          assert_eq!(v, $n, "{} is {v}", stringify!($e));
        };
      }

      dbg!(s0.load(Ordering::SeqCst));
      dbg!(s1.load(Ordering::SeqCst));
      dbg!(s2.load(Ordering::SeqCst));
      dbg!(s3.load(Ordering::SeqCst));

      check!(s0, 10);
      check!(s1, 20);
      check!(s2, 30);
      check!(s3, 40);
    }
  })
}
