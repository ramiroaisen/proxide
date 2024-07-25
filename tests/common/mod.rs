#![allow(unused)]

use hyper::body::Incoming;
use hyper_util::{
  client::legacy::{connect::HttpConnector, Client},
  rt::TokioExecutor,
};
use proxide::body::Body;
use tokio::runtime::{Builder, Runtime};

use reqwest_websocket::{RequestBuilderExt, WebSocket};
use tower::{Service, ServiceExt};

pub fn runtime() -> Runtime {
  Builder::new_multi_thread().enable_all().build().unwrap()
}

pub fn client() -> Client<HttpConnector, Body> {
  hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http()
}

pub async fn send(
  req: hyper::Request<Body>,
) -> Result<hyper::Response<Incoming>, hyper_util::client::legacy::Error> {
  client().request(req).await
}

pub async fn get(
  uri: &str,
) -> Result<hyper::Response<Incoming>, hyper_util::client::legacy::Error> {
  let request = hyper::Request::builder()
    .method("GET")
    .uri(uri)
    .body(Body::empty())
    .unwrap();

  client().request(request).await
}

pub async fn https_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()
    .unwrap()
    .get(url)
    .send()
    .await
}

pub async fn https_request(request: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
  let mut client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()
    .unwrap();

  client.ready().await.unwrap();
  client.call(request).await
}

pub async fn ws(uri: &str) -> Result<WebSocket, reqwest_websocket::Error> {
  let ws = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()
    .unwrap()
    .get(uri)
    .upgrade()
    .send()
    .await?
    .into_websocket()
    .await?;

  Ok(ws)
}

pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
  runtime().block_on(f)
}

static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub fn lock() -> parking_lot::MutexGuard<'static, ()> {
  LOCK.lock()
}

#[macro_export]
macro_rules! lock {
  () => {
    let _lock = $crate::common::lock();
  };

  ($path:literal) => {
    $crate::lock!();
    $crate::launch!($path);
  };
}

#[macro_export]
macro_rules! launch {
  ($name:ident, $path:literal, $abort:expr) => {
    let config = include_str!($path);
    let config: proxide::config::Config = serde_yaml::from_str(config).expect("config parse");

    let rt = $crate::common::runtime();
    #[allow(unused_mut)]
    let mut $name = rt.block_on(
      proxide::cli::cmd::start::instance_from_config(
        Default::default(),
        config,
        $abort,
      )
    ).unwrap();
  };

  ($name:ident, $path:literal) => {
    $crate::launch!($name, $path, futures_util::future::pending());
  };

  ($path:literal, $abort:expr) => {
    $crate::launch!(_handle, $path, $abort);
  };

  ($path:literal) => {
    $crate::launch!(_handle, $path, futures_util::future::pending());
  };

  (@parsed $name:ident, $config:expr, $abort:expr) => {
    let rt = $crate::common::runtime();
    #[allow(unused_mut)]
    let mut $name = rt.block_on(
      proxide::cli::cmd::start::instance_from_config(
        Default::default(),
        $config,
        $abort,
      )
    ).unwrap();
  };

  (@parsed $config:expr, $abort:expr) => {
    $crate::launch!(@parsed _handle, $config, $abort);
  };

  (@parsed $name:ident, $config:expr) => {
    $crate::launch!(@parsed $name, $config, futures_util::future::pending());
  };

  (@parsed $config:expr) => {
    $crate::launch!(@parsed _handle, $config, futures_util::future::pending());
  };
}

#[macro_export]
macro_rules! assert_status {
  ($response:expr, $status:ident) => {
    assert_eq!($response.status(), hyper::StatusCode::$status);
  };

  ($response:expr, $status:ident, $($tt:tt)*) => {
    assert_eq!($response.status(), hyper::StatusCode::$status, $($tt)*);
  };

  ($response:expr, $status:expr) => {
    assert_eq!($response.status(), $status);
  };

  ($response:expr, $status:expr, $($tt:tt)*) => {
    assert_eq!($response.status(), $status, $($tt)*);
  };

  ($response:expr, $status:literal) => {
    assert_eq!($response.status().as_u16(), $status);
  };

  ($response:expr, $status:literal, $($tt:tt)*) => {
    assert_eq!($response.status().as_u16(), $status, $($tt)*);
  };
}

#[macro_export]
macro_rules! assert_header {
  ($response:expr, $header:expr, $value:expr) => {
    assert_eq!($response.headers().get($header).unwrap(), $value);
  };

  ($response:expr, $header:expr, $value:expr, $($tt:tt)*) => {
    assert_eq!($response.headers().get($header).unwrap(), $value, $($tt)*);
  };
}

#[macro_export]
macro_rules! assert_body {
  ($response:expr, $value:expr) => {
    let bytes = $response.into_body().collect().await.unwrap().to_bytes();
    let content = String::from_utf8_lossy(&bytes);
    assert_eq!(content, $value);
  };

  ($response:expr, $value:expr, $($tt:tt)*) => {
    let bytes = $response.into_body().collect().await.unwrap().to_bytes();
    let content = String::from_utf8_lossy(&bytes);
    assert_eq!(content, $value, $($tt)*);
  };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dir(String);

impl Dir {
  pub fn file(&self, name: &str) -> String {
    format!("{}/{}", self.0, name)
  }
}

// impl std::fmt::Display for Dir {
//   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//     write!(f, "{}", self.0)
//   }
// }

impl std::ops::Deref for Dir {
  type Target = String;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl Drop for Dir {
  fn drop(&mut self) {
    std::fs::remove_dir_all(&self.0).unwrap();
  }
}

pub fn dir() -> Dir {
  let tmp = std::env::temp_dir();
  let rand: u64 = rand::random();
  let dir = tmp.join(format!("proxide-test-{rand}"));
  std::fs::create_dir_all(&dir).unwrap();

  let path = dir.to_str().unwrap();

  #[cfg(not(windows))]
  {
    Dir(path.to_string())
  }

  #[cfg(windows)]
  {
    Dir(path.replace('\\', "/"))
  }
}
