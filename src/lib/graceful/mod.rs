//! Utility to gracefully shutdown a server.
//!
//! This module provides a [`GracefulShutdown`] type,
//! which can be used to gracefully shutdown a server.
//!
//! See <https://github.com/hyperium/hyper-util/blob/master/examples/server_graceful.rs>
//! for an example of how to use this.

use std::{
  fmt::{self, Debug},
  future::Future,
  pin::Pin,
  task::{self, Context, Poll},
};

use hyper::rt::{Read, Write};
use pin_project::pin_project;
use tokio::{
  io::{AsyncRead, AsyncWrite},
  sync::watch,
};

/// A graceful shutdown utility
#[derive(Clone)]
pub struct GracefulShutdown {
  tx: watch::Sender<()>,
  // we keep the receiver alive to avoid the watch channel to be closed
  _rx: watch::Receiver<()>,
}

impl GracefulShutdown {
  /// Create a new graceful shutdown helper.
  pub fn new() -> Self {
    let (tx, rx) = watch::channel(());
    Self { tx, _rx: rx }
  }

  /// Wrap a future for graceful shutdown watching.
  pub fn watch<C: GracefulConnection>(&self, conn: C) -> impl Future<Output = C::Output> {
    let mut rx = self.tx.subscribe();
    GracefulConnectionFuture::new(conn, async move {
      let _ = rx.changed().await;
      // hold onto the rx until the watched future is completed
      rx
    })
  }

  pub fn guard<T>(&self, inner: T) -> GracefulGuard<T> {
    GracefulGuard {
      inner,
      guard: self.tx.subscribe(),
    }
  }

  /// Signal shutdown for all watched connections.
  ///
  /// This returns a `Future` which will complete once all watched
  /// connections have shutdown.
  pub async fn shutdown(self) {
    // drop the rx immediately, or else it will hold us up
    let Self { tx, _rx } = self;
    drop(_rx);

    // signal all the watched futures about the change
    let _ = tx.send(());
    // and then wait for all of them to complete
    tx.closed().await;
  }
}

impl Debug for GracefulShutdown {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("GracefulShutdown").finish()
  }
}

impl Default for GracefulShutdown {
  fn default() -> Self {
    Self::new()
  }
}

#[pin_project]
struct GracefulConnectionFuture<C, F: Future> {
  #[pin]
  conn: C,
  #[pin]
  cancel: F,
  #[pin]
  // If cancelled, this is held until the inner conn is done.
  cancelled_guard: Option<F::Output>,
}

impl<C, F: Future> GracefulConnectionFuture<C, F> {
  fn new(conn: C, cancel: F) -> Self {
    Self {
      conn,
      cancel,
      cancelled_guard: None,
    }
  }
}

impl<C, F: Future> Debug for GracefulConnectionFuture<C, F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("GracefulConnectionFuture").finish()
  }
}

impl<C, F> Future for GracefulConnectionFuture<C, F>
where
  C: GracefulConnection,
  F: Future,
{
  type Output = C::Output;

  fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
    let mut this = self.project();
    if this.cancelled_guard.is_none() {
      if let Poll::Ready(guard) = this.cancel.poll(cx) {
        this.cancelled_guard.set(Some(guard));
        this.conn.as_mut().graceful_shutdown();
      }
    }

    this.conn.poll(cx)
  }
}

/// An internal utility trait as an umbrella target for all (hyper) connection
/// types that the [`GracefulShutdown`] can watch.
pub trait GracefulConnection: Future<Output = Result<(), Self::Error>> + private::Sealed {
  /// The error type returned by the connection when used as a future.
  type Error;

  /// Start a graceful shutdown process for this connection.
  fn graceful_shutdown(self: Pin<&mut Self>);
}

impl<I, B, S> GracefulConnection for hyper::server::conn::http1::Connection<I, S>
where
  S: hyper::service::HttpService<hyper::body::Incoming, ResBody = B>,
  S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
  B: hyper::body::Body + 'static,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  type Error = hyper::Error;

  fn graceful_shutdown(self: Pin<&mut Self>) {
    hyper::server::conn::http1::Connection::graceful_shutdown(self);
  }
}

impl<I, B, S, E> GracefulConnection for hyper::server::conn::http2::Connection<I, S, E>
where
  S: hyper::service::HttpService<hyper::body::Incoming, ResBody = B>,
  S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
  B: hyper::body::Body + 'static,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
{
  type Error = hyper::Error;

  fn graceful_shutdown(self: Pin<&mut Self>) {
    hyper::server::conn::http2::Connection::graceful_shutdown(self);
  }
}

impl<I, B, S, E> GracefulConnection for hyper_util::server::conn::auto::Connection<'_, I, S, E>
where
  S: hyper::service::Service<http::Request<hyper::body::Incoming>, Response = http::Response<B>>,
  S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  S::Future: 'static,
  I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
  B: hyper::body::Body + 'static,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
{
  type Error = Box<dyn std::error::Error + Send + Sync>;

  fn graceful_shutdown(self: Pin<&mut Self>) {
    hyper_util::server::conn::auto::Connection::graceful_shutdown(self);
  }
}

impl<I, B, S, E> GracefulConnection
  for hyper_util::server::conn::auto::UpgradeableConnection<'_, I, S, E>
where
  S: hyper::service::Service<http::Request<hyper::body::Incoming>, Response = http::Response<B>>,
  S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  S::Future: 'static,
  I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
  B: hyper::body::Body + 'static,
  B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
{
  type Error = Box<dyn std::error::Error + Send + Sync>;

  fn graceful_shutdown(self: Pin<&mut Self>) {
    hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown(self);
  }
}

mod private {
  pub trait Sealed {}

  impl<I, B, S> Sealed for hyper::server::conn::http1::Connection<I, S>
  where
    S: hyper::service::HttpService<hyper::body::Incoming, ResBody = B>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: hyper::body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  {
  }

  impl<I, B, S> Sealed for hyper::server::conn::http1::UpgradeableConnection<I, S>
  where
    S: hyper::service::HttpService<hyper::body::Incoming, ResBody = B>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: hyper::body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
  {
  }

  impl<I, B, S, E> Sealed for hyper::server::conn::http2::Connection<I, S, E>
  where
    S: hyper::service::HttpService<hyper::body::Incoming, ResBody = B>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: hyper::body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
  {
  }

  impl<I, B, S, E> Sealed for hyper_util::server::conn::auto::Connection<'_, I, S, E>
  where
    S: hyper::service::Service<http::Request<hyper::body::Incoming>, Response = http::Response<B>>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: 'static,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: hyper::body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
  {
  }

  impl<I, B, S, E> Sealed for hyper_util::server::conn::auto::UpgradeableConnection<'_, I, S, E>
  where
    S: hyper::service::Service<http::Request<hyper::body::Incoming>, Response = http::Response<B>>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: 'static,
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: hyper::body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: hyper::rt::bounds::Http2ServerConnExec<S::Future, B>,
  {
  }
}

#[pin_project]
pub struct GracefulGuard<T> {
  #[pin]
  inner: T,
  guard: watch::Receiver<()>,
}

impl<T: Future> Future for GracefulGuard<T> {
  type Output = T::Output;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.project().inner.poll(cx)
  }
}

impl<T: AsyncRead> AsyncRead for GracefulGuard<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.project().inner.poll_read(cx, buf)
  }
}

impl<T: AsyncWrite> AsyncWrite for GracefulGuard<T> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    self.project().inner.poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    self.project().inner.poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    self.project().inner.poll_shutdown(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write_vectored(cx, bufs)
  }
}

impl<T: Read> Read for GracefulGuard<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_read(cx, buf)
  }
}

impl<T: Write> Write for GracefulGuard<T> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_flush(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_shutdown(cx)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, std::io::Error>> {
    self.project().inner.poll_write_vectored(cx, bufs)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use pin_project::pin_project;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Arc;

  #[pin_project]
  #[derive(Debug)]
  struct DummyConnection<F> {
    #[pin]
    future: F,
    shutdown_counter: Arc<AtomicUsize>,
  }

  impl<F> private::Sealed for DummyConnection<F> {}

  impl<F: Future> GracefulConnection for DummyConnection<F> {
    type Error = ();

    fn graceful_shutdown(self: Pin<&mut Self>) {
      self.shutdown_counter.fetch_add(1, Ordering::SeqCst);
    }
  }

  impl<F: Future> Future for DummyConnection<F> {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
      match self.project().future.poll(cx) {
        Poll::Ready(_) => Poll::Ready(Ok(())),
        Poll::Pending => Poll::Pending,
      }
    }
  }

  #[cfg(not(miri))]
  #[tokio::test]
  async fn test_graceful_shutdown_ok() {
    let graceful = GracefulShutdown::new();
    let shutdown_counter = Arc::new(AtomicUsize::new(0));
    let (dummy_tx, _) = tokio::sync::broadcast::channel(1);

    for i in 1..=3 {
      let mut dummy_rx = dummy_tx.subscribe();
      let shutdown_counter = shutdown_counter.clone();

      let future = async move {
        tokio::time::sleep(std::time::Duration::from_millis(i * 10)).await;
        let _ = dummy_rx.recv().await;
      };
      let dummy_conn = DummyConnection {
        future,
        shutdown_counter,
      };
      let conn = graceful.watch(dummy_conn);
      tokio::spawn(async move {
        conn.await.unwrap();
      });
    }

    assert_eq!(shutdown_counter.load(Ordering::SeqCst), 0);
    let _ = dummy_tx.send(());

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
            panic!("timeout")
        },
        _ = graceful.shutdown() => {
            assert_eq!(shutdown_counter.load(Ordering::SeqCst), 3);
        }
    }
  }

  #[cfg(not(miri))]
  #[tokio::test]
  async fn test_graceful_shutdown_delayed_ok() {
    let graceful = GracefulShutdown::new();
    let shutdown_counter = Arc::new(AtomicUsize::new(0));

    for i in 1..=3 {
      let shutdown_counter = shutdown_counter.clone();

      //tokio::time::sleep(std::time::Duration::from_millis(i * 5)).await;
      let future = async move {
        tokio::time::sleep(std::time::Duration::from_millis(i * 50)).await;
      };
      let dummy_conn = DummyConnection {
        future,
        shutdown_counter,
      };
      let conn = graceful.watch(dummy_conn);
      tokio::spawn(async move {
        conn.await.unwrap();
      });
    }

    assert_eq!(shutdown_counter.load(Ordering::SeqCst), 0);

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
            panic!("timeout")
        },
        _ = graceful.shutdown() => {
            assert_eq!(shutdown_counter.load(Ordering::SeqCst), 3);
        }
    }
  }

  #[cfg(not(miri))]
  #[tokio::test]
  async fn test_graceful_shutdown_multi_per_watcher_ok() {
    let graceful = GracefulShutdown::new();
    let shutdown_counter = Arc::new(AtomicUsize::new(0));

    for i in 1..=3 {
      let shutdown_counter = shutdown_counter.clone();

      let mut futures = Vec::new();
      for u in 1..=i {
        let future = tokio::time::sleep(std::time::Duration::from_millis(u * 50));
        let dummy_conn = DummyConnection {
          future,
          shutdown_counter: shutdown_counter.clone(),
        };
        let conn = graceful.watch(dummy_conn);
        futures.push(conn);
      }
      tokio::spawn(async move {
        futures_util::future::join_all(futures).await;
      });
    }

    assert_eq!(shutdown_counter.load(Ordering::SeqCst), 0);

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
            panic!("timeout")
        },
        _ = graceful.shutdown() => {
            assert_eq!(shutdown_counter.load(Ordering::SeqCst), 6);
        }
    }
  }

  #[cfg(not(miri))]
  #[tokio::test]
  async fn test_graceful_shutdown_timeout() {
    let graceful = GracefulShutdown::new();
    let shutdown_counter = Arc::new(AtomicUsize::new(0));

    for i in 1..=3 {
      let shutdown_counter = shutdown_counter.clone();

      let future = async move {
        if i == 1 {
          std::future::pending::<()>().await
        } else {
          std::future::ready(()).await
        }
      };
      let dummy_conn = DummyConnection {
        future,
        shutdown_counter,
      };
      let conn = graceful.watch(dummy_conn);
      tokio::spawn(async move {
        conn.await.unwrap();
      });
    }

    assert_eq!(shutdown_counter.load(Ordering::SeqCst), 0);

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
            assert_eq!(shutdown_counter.load(Ordering::SeqCst), 3);
        },
        _ = graceful.shutdown() => {
            panic!("shutdown should not be completed: as not all our conns finish")
        }
    }
  }
}
