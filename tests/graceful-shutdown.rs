mod common;
use std::{net::TcpListener, thread, time::Duration};
use common::{block_on, ws};
use futures::{SinkExt, StreamExt};
use tungstenite::accept;

#[test]
fn graceful_shutdown() {

  for port in 0..4_u16 {
    
    let scheme = match port {
      0 => "ws",
      1 => "wss",
      2 => "ws",
      3 => "wss",
      _ => unreachable!()
    };
    
    let (abort, abort_recv) = tokio::sync::oneshot::channel::<()>();

    let server = TcpListener::bind(&format!("127.0.0.1:2175{port}")).unwrap();  
    
    thread::spawn(move || {
      for stream in server.incoming() {
        let stream = stream.unwrap();
        thread::spawn(move || {
          let mut ws = match accept(stream) {
            Ok(ws) => ws,
            Err(_) => return,
          };

          loop {
            let msg = match ws.read() {
              Ok(msg) => msg,
              Err(_) => return,
            };

            if msg.is_binary() || msg.is_text() {
              ws.send(msg).unwrap();
            }
          }
        });
      }
    });

    launch!(handle, "graceful-shutdown.yml", async move {
      abort_recv.await.unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    thread::spawn(move || {
      block_on(async {
        
        let mut ws = ws(&format!("{scheme}://127.0.0.1:2170{port}/")).await.unwrap();

        tokio::spawn(async move {
          tokio::time::sleep(Duration::from_millis(900)).await;
          ws.send("message".into()).await.unwrap();
          ws.next().await.unwrap().unwrap();
        });

        thread::sleep(Duration::from_millis(100));
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
      })
    }).join().unwrap();
  }
}