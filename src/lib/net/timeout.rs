use pin_project::pin_project;
use std::future::Future;
use std::{
  pin::Pin,
  task::{Context, Poll},
  time::Duration,
};
use tokio::{
  io::{AsyncRead, AsyncWrite},
  time::Sleep,
};

#[pin_project]
pub struct TimeoutIo<T> {
  #[pin]
  inner: T,
  read_timeout: Duration,
  write_timeout: Duration,
  #[pin]
  read_timer: Option<Sleep>,
  #[pin]
  write_timer: Option<Sleep>,
}

impl<T> TimeoutIo<T> {
  pub fn new(inner: T, read_timeout: Duration, write_timeout: Duration) -> Self {
    Self {
      inner,
      read_timeout,
      write_timeout,
      read_timer: None,
      write_timer: None,
    }
  }

  // pub fn into_inner(self) -> T {
  //   self.inner
  // }

  // pub fn inner(&self) -> &T {
  //   &self.inner
  // }

  // pub fn inner_mut(&mut self) -> &mut T {
  //   &mut self.inner
  // }

  // pub fn read_timeout(&self) -> Duration {
  //   self.read_timeout
  // }

  // pub fn write_timeout(&self) -> Duration {
  //   self.write_timeout
  // }
}

macro_rules! with_timeout {
  ($me:ident, $timer:ident, $timeout:ident, $cx:ident, $action:expr) => {
    match $action {
      Poll::Ready(r) => {
        $me.$timer.set(None);
        Poll::Ready(r)
      }

      Poll::Pending => {
        if $me.$timer.is_none() {
          $me.$timer.set(Some(tokio::time::sleep(*$me.$timeout)));
        }

        match $me.$timer.as_mut().as_pin_mut().unwrap().poll($cx) {
          Poll::Ready(_) => {
            $me.$timer.set(None);
            Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
          }
          Poll::Pending => Poll::Pending,
        }
      }
    }
  };
}

macro_rules! impl_read {
  ($trait:path, $($buf:tt)*) => {
    impl<T: $trait> $trait for TimeoutIo<T> {
      fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: $($buf)*) -> Poll<std::io::Result<()>> {
        let mut me = self.project();
        with_timeout!(me, read_timer, read_timeout, cx, me.inner.poll_read(cx, buf))
      }
    }
  }
}

macro_rules! impl_write {
  ($trait:path) => {
    impl<T: $trait> $trait for TimeoutIo<T> {
      fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
      ) -> Poll<Result<usize, std::io::Error>> {
        let mut me = self.project();
        with_timeout!(
          me,
          write_timer,
          write_timeout,
          cx,
          me.inner.poll_write(cx, buf)
        )
      }

      fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        let mut me = self.project();
        with_timeout!(me, write_timer, write_timeout, cx, me.inner.poll_flush(cx))
      }

      fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        let mut me = self.project();
        with_timeout!(
          me,
          write_timer,
          write_timeout,
          cx,
          me.inner.poll_shutdown(cx)
        )
      }

      fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
      ) -> Poll<Result<usize, std::io::Error>> {
        let mut me = self.project();
        with_timeout!(
          me,
          write_timer,
          write_timeout,
          cx,
          me.inner.poll_write_vectored(cx, bufs)
        )
      }

      fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
      }
    }
  };
}

impl_write!(AsyncWrite);
impl_write!(hyper::rt::Write);

impl_read!(AsyncRead, &mut tokio::io::ReadBuf<'_>);
impl_read!(hyper::rt::Read, hyper::rt::ReadBufCursor<'_>);
