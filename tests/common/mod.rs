#![allow(unused)]

use http::Version;
use hyper::body::Incoming;
use hyper_util::{
  client::legacy::{connect::HttpConnector, Client},
  rt::TokioExecutor,
};
use proxide::body::Body;
use reqwest::redirect::Policy;
use tokio::runtime::{Builder, Runtime};

use reqwest_websocket::{RequestBuilderExt, WebSocket};
use tower::{Service, ServiceExt};

pub fn runtime() -> Runtime {
  Builder::new_multi_thread().enable_all().build().unwrap()
}

pub fn client() -> reqwest::Client {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
}

pub async fn get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(url)
    .send()
    .await
}

pub async fn h10_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(url)
    .version(reqwest::Version::HTTP_10)
    .send()
    .await
}

pub async fn h11_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(url)
    .version(reqwest::Version::HTTP_11)
    .send()
    .await
}

pub async fn h2_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(url)
    .version(reqwest::Version::HTTP_2)
    .send()
    .await
}

pub async fn h3_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .http3_prior_knowledge()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(url)
    .version(reqwest::Version::HTTP_3)
    .send()
    .await
}

pub async fn request(req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
  let mut client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none());

  match req.version() {
    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
      client = client.http1_only();
    }

    Version::HTTP_2 => {
      client = client.http2_prior_knowledge();
    }

    Version::HTTP_3 => {
      client = client.http3_prior_knowledge();
    }

    _ => unreachable!(),
  }

  client.build().unwrap().execute(req).await
}

pub async fn ws(uri: &str) -> Result<WebSocket, reqwest_websocket::Error> {
  let ws = reqwest::Client::builder()
    .http1_only()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .redirect(Policy::none())
    .build()
    .unwrap()
    .get(uri)
    .upgrade()
    .send()
    .await
    .unwrap()
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
  ($res:expr, $value:expr) => {
    let content = $res.text().await.unwrap();
    assert_eq!(content, $value);
  };

  ($res:expr, $value:expr, $($tt:tt)*) => {
    let content = $res.text().await.unwrap();
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
