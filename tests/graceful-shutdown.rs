mod common;
use common::{block_on, ws};
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;

#[test]
fn graceful_shutdown() {
  for port in 0..4_u16 {
    let (abort, abort_recv) = tokio::sync::oneshot::channel::<()>();

    launch!(handle, "graceful-shutdown.yml", async move {
      abort_recv.await.unwrap();
    });

    block_on(async move {
      let scheme = match port {
        0 | 2 => "ws",
        1 | 3 => "wss",
        _ => unreachable!(),
      };

      let server = TcpListener::bind(&format!("127.0.0.1:2175{port}"))
        .await
        .unwrap();

      tokio::spawn(async move {
        loop {
          let (stream, _) = server.accept().await.unwrap();
          tokio::spawn(async move {
            let mut ws = match async_tungstenite::tokio::accept_async(stream).await {
              Ok(ws) => ws,
              Err(e) => {
                log::warn!("error accepting websocket: {e} - {e:?}");
                return;
              }
            };

            loop {
              let msg = match ws.next().await {
                Some(Ok(msg)) => msg,
                _ => return,
              };

              if msg.is_binary() || msg.is_text() {
                ws.send(msg).await.unwrap()
              }
            }
          });
        }
      });

      tokio::time::sleep(Duration::from_millis(100)).await;

      let mut ws = ws(&format!("{scheme}://127.0.0.1:2170{port}/"))
        .await
        .unwrap();

      tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(750)).await;
        ws.send("message".into()).await.unwrap();
        ws.next().await.unwrap().unwrap();
      });

      tokio::time::sleep(Duration::from_millis(100)).await;

      abort.send(()).unwrap();

      tokio::select! {
        _ = &mut handle => panic!("handle should not return first"),
        _ = tokio::time::sleep(Duration::from_millis(300)) => {
          tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(1000)) => panic!("handle should return first after second timeout"),
            _ = &mut handle => {}
          }
        }
      }
    });
  }
}
