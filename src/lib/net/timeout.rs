use pin_project::pin_project;
use std::future::Future;
use std::{
  pin::Pin,
  sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
  },
  task::{Context, Poll},
  time::Duration,
};
use tokio::{
  io::{AsyncRead, AsyncWrite},
  time::{Instant, Sleep},
};

/// Shared between a connection and the requests it carries, tells the
/// read timeout of the connection when the peer is not the one that is
/// expected to send something.
///
/// While at least one hold is active the read timeout does not run, and
/// when the last one is released it starts counting again from that moment.
#[derive(Debug)]
pub struct ReadGate {
  holds: AtomicUsize,
  /// nanoseconds from `base` to the last release, 0 if there was none
  released_at: AtomicU64,
  base: Instant,
}

impl ReadGate {
  pub fn new() -> Arc<Self> {
    Arc::new(Self {
      holds: AtomicUsize::new(0),
      released_at: AtomicU64::new(0),
      base: Instant::now(),
    })
  }

  /// suspend the read timeout, must be paired with one [`Self::release`]
  pub fn hold(&self) {
    self.holds.fetch_add(1, Ordering::AcqRel);
  }

  pub fn release(&self) {
    // stamp before decrementing: whoever sees no holds also sees the stamp
    let nanos = Instant::now().duration_since(self.base).as_nanos() as u64;
    self.released_at.fetch_max(nanos.max(1), Ordering::AcqRel);
    self.holds.fetch_sub(1, Ordering::AcqRel);
  }

  pub(crate) fn is_held(&self) -> bool {
    self.holds.load(Ordering::Acquire) != 0
  }

  fn released_at(&self) -> Option<Instant> {
    match self.released_at.load(Ordering::Acquire) {
      0 => None,
      nanos => Some(self.base + Duration::from_nanos(nanos)),
    }
  }
}

/// Applies a read and a write timeout to an io.
///
/// Both are inactivity timeouts:
///
/// - the write timeout elapses when a write stays blocked for
///   `write_timeout`, that is, when the peer stops accepting data.
///
/// - the read timeout elapses when a read stays blocked for `read_timeout`
///   and in that time nothing was written to the peer either. A peer that
///   is receiving data has no reason to send any, so writes that make
///   progress count as activity of the connection. A [`ReadGate`] suspends
///   it for the periods where there is nothing to write yet but it is
///   still not the turn of the peer.
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
  /// last write that made progress while a read was blocked
  last_write: Option<Instant>,
  read_gate: Option<Arc<ReadGate>>,
}

impl<T> TimeoutIo<T> {
  pub fn new(inner: T, read_timeout: Duration, write_timeout: Duration) -> Self {
    Self {
      inner,
      read_timeout,
      write_timeout,
      read_timer: None,
      write_timer: None,
      last_write: None,
      read_gate: None,
    }
  }

  pub fn with_read_gate(mut self, gate: Arc<ReadGate>) -> Self {
    self.read_gate = Some(gate);
    self
  }
}

/// The moment a read timer that has just elapsed has to be extended to,
/// None if the read did time out.
fn read_deadline(
  now: Instant,
  timeout: Duration,
  last_write: Option<Instant>,
  gate: Option<&ReadGate>,
) -> Option<Instant> {
  if gate.is_some_and(ReadGate::is_held) {
    return Some(now + timeout);
  }

  let last_activity = last_write.max(gate.and_then(ReadGate::released_at))?;
  let deadline = last_activity + timeout;
  (deadline > now).then_some(deadline)
}

macro_rules! with_write_timeout {
  ($me:ident, $cx:ident, $action:expr) => {
    match $action {
      Poll::Ready(r) => {
        $me.write_timer.set(None);
        Poll::Ready(r)
      }

      Poll::Pending => {
        if $me.write_timer.is_none() {
          $me
            .write_timer
            .set(Some(tokio::time::sleep(*$me.write_timeout)));
        }

        match $me.write_timer.as_mut().as_pin_mut().unwrap().poll($cx) {
          Poll::Ready(_) => {
            $me.write_timer.set(None);
            Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
          }
          Poll::Pending => Poll::Pending,
        }
      }
    }
  };
}

/// like `with_write_timeout` for the writes that report how much they
/// wrote, a write that made progress counts as activity for the read timer
macro_rules! with_write_timeout_and_progress {
  ($me:ident, $cx:ident, $action:expr) => {{
    let poll = with_write_timeout!($me, $cx, $action);
    if $me.read_timer.is_some() && matches!(poll, Poll::Ready(Ok(n)) if n != 0) {
      *$me.last_write = Some(Instant::now());
    }
    poll
  }};
}

macro_rules! impl_read {
  ($trait:path, $($buf:tt)*) => {
    impl<T: $trait> $trait for TimeoutIo<T> {
      fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: $($buf)*) -> Poll<std::io::Result<()>> {
        let mut me = self.project();

        match me.inner.poll_read(cx, buf) {
          Poll::Ready(r) => {
            me.read_timer.set(None);
            *me.last_write = None;
            Poll::Ready(r)
          }

          Poll::Pending => {
            if me.read_timer.is_none() {
              me.read_timer.set(Some(tokio::time::sleep(*me.read_timeout)));
            }

            loop {
              let mut timer = me.read_timer.as_mut().as_pin_mut().unwrap();
              if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
              }

              // the timer elapsed: this is a timeout only if in the meantime
              // nothing was written and it was the turn of the peer
              match read_deadline(Instant::now(), *me.read_timeout, *me.last_write, me.read_gate.as_deref()) {
                // and poll again to register the waker for the new deadline
                Some(deadline) => timer.reset(deadline),
                None => {
                  me.read_timer.set(None);
                  *me.last_write = None;
                  return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
                }
              }
            }
          }
        }
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
        with_write_timeout_and_progress!(me, cx, me.inner.poll_write(cx, buf))
      }

      fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        let mut me = self.project();
        with_write_timeout!(me, cx, me.inner.poll_flush(cx))
      }

      fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        let mut me = self.project();
        with_write_timeout!(me, cx, me.inner.poll_shutdown(cx))
      }

      fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
      ) -> Poll<Result<usize, std::io::Error>> {
        let mut me = self.project();
        with_write_timeout_and_progress!(me, cx, me.inner.poll_write_vectored(cx, bufs))
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

#[cfg(test)]
mod test {
  use super::*;
  use std::io::ErrorKind;
  use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream};
  use tokio::time::{sleep, timeout};

  const READ: Duration = Duration::from_secs(10);
  const WRITE: Duration = Duration::from_secs(3);

  // TimeoutIo holds its timers inline, it is used pinned
  type Io = Pin<Box<TimeoutIo<DuplexStream>>>;

  fn pair() -> (Io, DuplexStream) {
    let (io, peer) = duplex(1024);
    (Box::pin(TimeoutIo::new(io, READ, WRITE)), peer)
  }

  fn gated_pair() -> (Io, DuplexStream, Arc<ReadGate>) {
    let (io, peer) = duplex(1024);
    let gate = ReadGate::new();
    let io = TimeoutIo::new(io, READ, WRITE).with_read_gate(gate.clone());
    (Box::pin(io), peer, gate)
  }

  /// reads one byte, returns the kind of the error and when it happened
  async fn read_error<R: AsyncRead + Unpin>(io: &mut R, start: Instant) -> (ErrorKind, Duration) {
    let e = io.read_u8().await.unwrap_err();
    (e.kind(), start.elapsed())
  }

  #[tokio::test(start_paused = true)]
  async fn read_times_out_without_activity() {
    let (mut io, _peer) = pair();
    let start = Instant::now();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn read_timeout_restarts_after_each_read() {
    let (mut io, mut peer) = pair();
    let start = Instant::now();

    tokio::spawn(async move {
      for _ in 0..3 {
        sleep(READ - Duration::from_secs(1)).await;
        peer.write_u8(1).await.unwrap();
      }
      // keep the peer open and silent
      sleep(READ * 10).await;
    });

    for _ in 0..3 {
      assert_eq!(io.read_u8().await.unwrap(), 1);
    }

    let last_read = start.elapsed();
    assert_eq!(last_read, (READ - Duration::from_secs(1)) * 3);
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, last_read + READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn read_reaches_eof_without_timeout() {
    let (mut io, peer) = pair();
    drop(peer);
    let mut buf = Vec::new();
    assert_eq!(io.read_to_end(&mut buf).await.unwrap(), 0);
  }

  /// the bug this module had: a peer that is receiving data is not idle,
  /// even if it has nothing to say
  #[tokio::test(start_paused = true)]
  async fn writes_that_progress_keep_a_blocked_read_alive() {
    let (io, mut peer) = pair();
    let (mut reader, mut writer) = split(io);
    let start = Instant::now();

    // the peer takes everything it is sent and never sends anything
    tokio::spawn(async move {
      let mut buf = [0u8; 64];
      while matches!(peer.read(&mut buf).await, Ok(n) if n != 0) {}
    });

    let read = tokio::spawn(async move { read_error(&mut reader, start).await });

    // write for 5 times the read timeout
    let step = READ / 2;
    for _ in 0..10 {
      sleep(step).await;
      writer.write_all(b"data").await.unwrap();
    }
    let last_write = start.elapsed();
    assert_eq!(last_write, READ * 5);
    assert!(!read.is_finished());

    // and once the writes stop the timeout counts from the last one
    assert_eq!(
      read.await.unwrap(),
      (ErrorKind::TimedOut, last_write + READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn flushes_are_not_activity() {
    let (io, _peer) = pair();
    let (mut reader, mut writer) = split(io);
    let start = Instant::now();

    let read = tokio::spawn(async move { read_error(&mut reader, start).await });

    for _ in 0..10 {
      sleep(READ / 2).await;
      // nothing to write for the peer, a flush or an empty write say nothing
      let _ = writer.flush().await;
      let _ = writer.write(&[]).await;
    }

    assert_eq!(read.await.unwrap(), (ErrorKind::TimedOut, READ));
  }

  /// writes from before the read blocked do not extend its timeout
  #[tokio::test(start_paused = true)]
  async fn earlier_writes_do_not_extend_a_later_read() {
    let (mut io, mut peer) = pair();

    io.write_all(b"data").await.unwrap();
    sleep(READ / 2).await;
    peer.write_u8(1).await.unwrap();
    assert_eq!(io.read_u8().await.unwrap(), 1);

    let start = Instant::now();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn blocked_write_times_out() {
    // the peer never reads and its buffer only fits 4 bytes
    let (io, _peer) = duplex(4);
    let mut io = Box::pin(TimeoutIo::new(io, READ, WRITE));
    let start = Instant::now();

    let e = io.write_all(&[0u8; 64]).await.unwrap_err();
    assert_eq!((e.kind(), start.elapsed()), (ErrorKind::TimedOut, WRITE));
  }

  /// the write timeout is about the peer taking data, what it sends does
  /// not make up for it
  #[tokio::test(start_paused = true)]
  async fn reads_do_not_keep_a_blocked_write_alive() {
    let (io, peer) = duplex(4);
    let (mut reader, mut writer) = split(Box::pin(TimeoutIo::new(io, READ, WRITE)));
    let (_peer_reader, mut peer_writer) = split(peer);
    let start = Instant::now();

    tokio::spawn(async move {
      loop {
        sleep(WRITE / 10).await;
        if peer_writer.write_u8(1).await.is_err() {
          break;
        }
      }
    });

    tokio::spawn(async move { while reader.read_u8().await.is_ok() {} });

    let e = writer.write_all(&[0u8; 64]).await.unwrap_err();
    assert_eq!((e.kind(), start.elapsed()), (ErrorKind::TimedOut, WRITE));
  }

  #[tokio::test(start_paused = true)]
  async fn write_timeout_restarts_after_each_write() {
    let (io, mut peer) = duplex(4);
    let mut io = Box::pin(TimeoutIo::new(io, READ, WRITE));
    let start = Instant::now();

    // a slow peer, but never slower than the timeout
    let step = WRITE - Duration::from_secs(1);
    tokio::spawn(async move {
      let mut buf = [0u8; 4];
      loop {
        sleep(step).await;
        if peer.read_exact(&mut buf).await.is_err() {
          break;
        }
      }
    });

    io.write_all(&[0u8; 64]).await.unwrap();
    assert!(start.elapsed() > WRITE * 5);
  }

  #[tokio::test(start_paused = true)]
  async fn gate_without_holds_changes_nothing() {
    let (mut io, _peer, _gate) = gated_pair();
    let start = Instant::now();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn held_gate_suspends_the_read_timeout() {
    let (mut io, _peer, gate) = gated_pair();

    gate.hold();
    assert!(timeout(READ * 20, io.read_u8()).await.is_err());

    // and it counts again, in full, from the release
    let start = Instant::now();
    gate.release();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  /// a hold that starts and ends while the read is already blocked
  #[tokio::test(start_paused = true)]
  async fn read_timeout_counts_from_the_release() {
    let (mut io, _peer, gate) = gated_pair();
    let start = Instant::now();

    tokio::spawn(async move {
      sleep(READ / 2).await;
      gate.hold();
      sleep(READ * 3).await;
      gate.release();
    });

    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ / 2 + READ * 3 + READ)
    );
  }

  /// a hold shorter than the timeout still postpones it
  #[tokio::test(start_paused = true)]
  async fn short_hold_postpones_the_read_timeout() {
    let (mut io, _peer, gate) = gated_pair();
    let start = Instant::now();

    tokio::spawn(async move {
      sleep(READ / 5).await;
      gate.hold();
      sleep(READ / 5).await;
      gate.release();
    });

    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ / 5 * 2 + READ)
    );
  }

  #[tokio::test(start_paused = true)]
  async fn gate_stays_held_until_the_last_release() {
    let (mut io, _peer, gate) = gated_pair();

    gate.hold();
    gate.hold();
    gate.release();
    assert!(timeout(READ * 20, io.read_u8()).await.is_err());

    let start = Instant::now();
    gate.release();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  /// a release from before the read blocked does not shorten its timeout
  #[tokio::test(start_paused = true)]
  async fn earlier_release_does_not_shorten_a_later_read() {
    let (mut io, _peer, gate) = gated_pair();

    gate.hold();
    gate.release();
    sleep(READ * 2).await;

    let start = Instant::now();
    assert_eq!(
      read_error(&mut io, start).await,
      (ErrorKind::TimedOut, READ)
    );
  }

  /// data that arrives while the gate is held is read as usual
  #[tokio::test(start_paused = true)]
  async fn held_gate_does_not_block_reads() {
    let (mut io, mut peer, gate) = gated_pair();

    gate.hold();
    tokio::spawn(async move {
      sleep(READ * 3).await;
      peer.write_u8(7).await.unwrap();
      sleep(READ * 100).await;
    });

    assert_eq!(io.read_u8().await.unwrap(), 7);
  }
}
