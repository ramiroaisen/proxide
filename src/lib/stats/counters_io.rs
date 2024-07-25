use pin_project::pin_project;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[pin_project]
pub struct CountersIo<T> {
  #[pin]
  inner: T,
  read_counter: Arc<AtomicU64>,
  write_counter: Arc<AtomicU64>,
}

impl<T> CountersIo<T> {
  pub fn new(io: T, read: Arc<AtomicU64>, write: Arc<AtomicU64>) -> Self {
    Self {
      inner: io,
      read_counter: read,
      write_counter: write,
    }
  }
}

impl<T: AsyncRead> AsyncRead for CountersIo<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.project();
    let filled_start = buf.filled().len();

    match this.inner.poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        let n = buf.filled().len() - filled_start;
        this.read_counter.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(()))
      }

      other => other,
    }
  }
}

impl<T: AsyncWrite> AsyncWrite for CountersIo<T> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    let this = self.project();
    match this.inner.poll_write(cx, buf) {
      Poll::Ready(Ok(n)) => {
        this.write_counter.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
      }

      other => other,
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    self.project().inner.poll_shutdown(cx)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<Result<usize, std::io::Error>> {
    let this = self.project();
    match this.inner.poll_write_vectored(cx, bufs) {
      Poll::Ready(Ok(n)) => {
        this.write_counter.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
      }

      other => other,
    }
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }
}
