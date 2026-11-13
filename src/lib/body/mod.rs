use crate::channel::spsc;
use bytes::Bytes;
use futures::Stream;
use http_body::Frame;
use http_body::SizeHint;
use hyper::body::Body as HyperBody;
use hyper::body::Incoming;
use pin_project::{pin_project, pinned_drop};
use std::fmt::Debug;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::proxy::error::ProxyHttpError;

type FrameStream =
  Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, ProxyHttpError>> + Send + Sync + 'static>>;

#[pin_project(project = BodyKindProjection)]
pub enum BodyKind {
  Empty,
  Full(Option<Bytes>),
  Incoming(#[pin] Incoming),
  Stream(FrameStream),
}

impl Debug for BodyKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let name = match self {
      BodyKind::Empty => "BodyKind::Empty",
      BodyKind::Full(_) => "BodyKind::Full",
      BodyKind::Incoming(_) => "BodyKind::Incoming",
      BodyKind::Stream(_) => "BodyKind::Stream",
    };

    f.debug_struct(name).finish()
  }
}

#[pin_project(PinnedDrop)]
pub struct Body {
  #[pin]
  pub(crate) kind: BodyKind,
  pub(crate) on_drop: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
  pub(crate) on_end: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

impl Debug for Body {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Body").field("kind", &self.kind).finish()
  }
}

impl From<()> for Body {
  fn from(_: ()) -> Self {
    Body::empty()
  }
}

impl From<Bytes> for Body {
  fn from(data: Bytes) -> Self {
    Body::full(data)
  }
}

impl From<Incoming> for Body {
  fn from(incoming: Incoming) -> Self {
    Body::incoming(incoming)
  }
}

#[pinned_drop]
impl PinnedDrop for Body {
  fn drop(self: Pin<&mut Self>) {
    let me = self.project();
    for fun in me.on_end.drain(..).chain(me.on_drop.drain(..)) {
      fun();
    }
  }
}

impl Body {
  pub fn empty() -> Self {
    Self {
      kind: BodyKind::empty(),
      on_drop: vec![],
      on_end: vec![],
    }
  }

  pub fn full<B: Into<Bytes> + Send + Sync + 'static>(data: B) -> Self {
    Self {
      kind: BodyKind::full(data),
      on_drop: vec![],
      on_end: vec![],
    }
  }

  pub fn incoming(incoming: Incoming) -> Self {
    Self {
      kind: BodyKind::incoming(incoming),
      on_drop: vec![],
      on_end: vec![],
    }
  }

  pub fn stream<S: Stream<Item = Result<Frame<Bytes>, ProxyHttpError>> + Send + Sync + 'static>(
    stream: S,
  ) -> Self {
    Self {
      kind: BodyKind::stream(stream),
      on_drop: vec![],
      on_end: vec![],
    }
  }

  pub fn channel() -> (Self, spsc::Sender<Result<Frame<Bytes>, ProxyHttpError>>) {
    let (kind, sender) = BodyKind::channel();
    let body = Self {
      kind,
      on_drop: vec![],
      on_end: vec![],
    };

    (body, sender)
  }

  pub fn on_drop<F: FnOnce() + Send + Sync + 'static>(&mut self, fun: F) {
    self.on_drop.push(Box::new(fun));
  }

  /// Runs `fun` once, as soon as the body has nothing more to yield: when
  /// it yields its last frame, when it fails, or when it is dropped,
  /// whatever happens first. A body that is already at its end runs it
  /// right away.
  pub fn on_end<F: FnOnce() + Send + Sync + 'static>(&mut self, fun: F) {
    if self.kind.is_end_stream() {
      fun();
    } else {
      self.on_end.push(Box::new(fun));
    }
  }
}

impl BodyKind {
  pub fn empty() -> Self {
    Self::Empty
  }

  pub fn full<B: Into<Bytes> + Send + Sync + 'static>(data: B) -> Self {
    Self::Full(Some(data.into()))
  }

  pub fn incoming(incoming: Incoming) -> Self {
    Self::Incoming(incoming)
  }

  pub fn stream<S: Stream<Item = Result<Frame<Bytes>, ProxyHttpError>> + Send + Sync + 'static>(
    stream: S,
  ) -> Self {
    Self::Stream(Box::pin(stream))
  }

  // kanal channel is not Sync
  pub fn channel() -> (Self, spsc::Sender<Result<Frame<Bytes>, ProxyHttpError>>) {
    let (sender, receiver) = spsc::channel();
    let body = BodyKind::stream(receiver);
    (body, sender)
  }
}

impl HyperBody for BodyKind {
  type Data = Bytes;
  type Error = ProxyHttpError;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match self.project() {
      BodyKindProjection::Empty => Poll::Ready(None),
      BodyKindProjection::Full(opt) => match opt.take() {
        None => Poll::Ready(None),
        Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
      },
      BodyKindProjection::Incoming(mut incoming) => match incoming.as_mut().poll_frame(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(None) => Poll::Ready(None),
        Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
        Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(ProxyHttpError::IncomingBody(e)))),
      },

      BodyKindProjection::Stream(stream) => stream.as_mut().poll_next(cx),
    }
  }

  fn is_end_stream(&self) -> bool {
    match self {
      BodyKind::Empty => true,
      BodyKind::Full(opt) => opt.is_none(),
      BodyKind::Incoming(incoming) => incoming.is_end_stream(),
      // we could use Stream::size_hint() here but its said in the declaration of the trait that it should not be trusted to be correct
      BodyKind::Stream(_) => false,
    }
  }

  fn size_hint(&self) -> http_body::SizeHint {
    match self {
      BodyKind::Empty => http_body::SizeHint::with_exact(0),
      BodyKind::Full(opt) => match opt {
        None => SizeHint::with_exact(0),
        Some(data) => SizeHint::with_exact(data.len() as u64),
      },
      BodyKind::Incoming(incoming) => incoming.size_hint(),
      // we could use Stream::size_hint() here but its said in the declaration of the trait that it should not trusted to be correct
      BodyKind::Stream(_) => SizeHint::default(),
    }
  }
}

impl Stream for BodyKind {
  type Item = Result<Frame<Bytes>, ProxyHttpError>;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    self.poll_frame(cx)
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    match self {
      BodyKind::Empty => (0, Some(0)),
      BodyKind::Full(opt) => match opt {
        None => (0, Some(0)),
        Some(data) => (data.len(), Some(data.len())),
      },
      BodyKind::Incoming(incoming) => {
        // size hint of body is in bytes but size hint of stream is in items
        let hint = incoming.size_hint();
        match (hint.lower(), hint.upper()) {
          (0, Some(0)) => (0, Some(0)),
          _ => (0, None),
        }
      }

      BodyKind::Stream(stream) => stream.size_hint(),
    }
  }
}

impl HyperBody for Body {
  type Data = <BodyKind as HyperBody>::Data;
  type Error = <BodyKind as HyperBody>::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let mut me = self.project();
    let poll = me.kind.as_mut().poll_frame(cx);

    if !me.on_end.is_empty() {
      let ended = match &poll {
        Poll::Pending => false,
        Poll::Ready(Some(Ok(_))) => me.kind.is_end_stream(),
        Poll::Ready(Some(Err(_))) | Poll::Ready(None) => true,
      };

      if ended {
        for fun in me.on_end.drain(..) {
          fun();
        }
      }
    }

    poll
  }

  fn is_end_stream(&self) -> bool {
    self.kind.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    HyperBody::size_hint(&self.kind)
  }
}

impl Stream for Body {
  type Item = <BodyKind as Stream>::Item;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    HyperBody::poll_frame(self, cx)
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    Stream::size_hint(&self.kind)
  }
}

pub fn map_request_body<S, T>(
  request: hyper::Request<S>,
  f: impl FnOnce(S) -> T,
) -> hyper::Request<T> {
  let (parts, source) = request.into_parts();
  let target = f(source);
  hyper::Request::from_parts(parts, target)
}

#[cfg(test)]
mod test {
  use super::*;
  use http_body_util::BodyExt;
  use hyper::body::{Body as HyperBody, Bytes};

  macro_rules! assert_size_hint {
    ($body:ident, $lower:expr, $upper:expr) => {{
      let hint = hyper::body::Body::size_hint(&$body);
      assert_eq!(hint.lower(), $lower);
      assert_eq!(hint.upper(), $upper.into());
    }};
  }

  macro_rules! assert_contents {
    ($body:ident, $expected:expr) => {{
      let buf = $body.collect().await.unwrap().to_bytes();
      assert_eq!(buf.as_ref(), $expected.as_ref());
    }};
  }

  macro_rules! assert_stream_collect {
    ($body:ident, $expected:expr) => {{
      let mut body = $body;
      let mut buf = Vec::new();
      while let Some(item) = futures::StreamExt::next(&mut body)
        .await
        .transpose()
        .unwrap()
      {
        match item.into_data() {
          Ok(data) => buf.extend_from_slice(data.as_ref()),
          Err(_) => {}
        }
      }
      assert_eq!(buf, $expected.as_ref());
    }};
  }

  #[tokio::test]
  async fn empty() {
    let body = Body::empty();
    assert_size_hint!(body, 0, 0);
    assert!(body.is_end_stream());
    assert_contents!(body, Bytes::new());
  }

  #[tokio::test]
  async fn stream_empty() {
    let body = Body::empty();
    assert_stream_collect!(body, Bytes::new());
  }

  #[tokio::test]
  async fn full() {
    let body = Body::full(Bytes::from_static(b"hello world"));
    assert_size_hint!(body, 11, Some(11));
    assert!(!body.is_end_stream());
    assert_contents!(body, Bytes::from_static(b"hello world"));
  }

  #[tokio::test]
  async fn stream_full() {
    let body = Body::full(Bytes::from_static(b"hello world"));
    assert_stream_collect!(body, Bytes::from_static(b"hello world"));
  }

  #[tokio::test]
  async fn stream() {
    let body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
      yield Ok(Frame::data(Bytes::from_static(b" ")));
      yield Ok(Frame::data(Bytes::from_static(b"world")));
    });

    assert_contents!(body, Bytes::from_static(b"hello world"));
  }

  #[tokio::test]
  async fn stream_empty_trailers() {
    let body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
      yield Ok(Frame::trailers(hyper::HeaderMap::new()));
    });

    assert_stream_collect!(body, Bytes::from_static(b"hello"));
  }

  #[tokio::test]
  async fn channel() {
    let (body, mut sender) = Body::channel();

    tokio::spawn(async move {
      sender
        .send(Ok(Frame::data(Bytes::from_static(b"hello"))))
        .await
        .unwrap();
      sender
        .send(Ok(Frame::data(Bytes::from_static(b" "))))
        .await
        .unwrap();
      sender
        .send(Ok(Frame::data(Bytes::from_static(b"world"))))
        .await
        .unwrap();
      sender
        .send(Ok(Frame::trailers(hyper::HeaderMap::new())))
        .await
        .unwrap();
    });

    assert_contents!(body, Bytes::from_static(b"hello world"));
  }

  /// counts how many times an `on_end` / `on_drop` hook ran
  fn counter() -> (
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    impl FnOnce() + Send + Sync + 'static,
  ) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let hook = {
      let count = count.clone();
      move || {
        count.fetch_add(1, Ordering::SeqCst);
      }
    };
    (count, hook)
  }

  macro_rules! assert_count {
    ($count:ident, $expected:expr) => {
      assert_eq!($count.load(std::sync::atomic::Ordering::SeqCst), $expected)
    };
  }

  #[tokio::test]
  async fn on_end_runs_right_away_for_an_ended_body() {
    let (count, hook) = counter();
    let mut body = Body::empty();
    body.on_end(hook);
    assert_count!(count, 1);
    drop(body);
    assert_count!(count, 1);
  }

  #[tokio::test]
  async fn on_end_runs_at_the_last_frame_and_only_once() {
    let (count, hook) = counter();
    let mut body = Body::full(Bytes::from_static(b"hello"));
    body.on_end(hook);
    assert_count!(count, 0);

    // the only frame is also the last one, there is no need to poll again
    let frame = body.frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap().as_ref(), b"hello");
    assert_count!(count, 1);

    assert!(body.frame().await.is_none());
    drop(body);
    assert_count!(count, 1);
  }

  #[tokio::test]
  async fn on_end_runs_at_the_end_of_a_stream() {
    let (count, hook) = counter();
    let mut body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
      yield Ok(Frame::data(Bytes::from_static(b"world")));
    });
    body.on_end(hook);

    assert!(body.frame().await.is_some());
    assert!(body.frame().await.is_some());
    // a stream is only known to have ended when it says so
    assert_count!(count, 0);
    assert!(body.frame().await.is_none());
    assert_count!(count, 1);
  }

  #[tokio::test]
  async fn on_end_runs_when_polled_as_a_stream() {
    let (count, hook) = counter();
    let mut body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
    });
    body.on_end(hook);

    assert!(futures::StreamExt::next(&mut body).await.is_some());
    assert_count!(count, 0);
    assert!(futures::StreamExt::next(&mut body).await.is_none());
    assert_count!(count, 1);
  }

  #[tokio::test]
  async fn on_end_runs_on_error() {
    let (count, hook) = counter();
    let mut body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
      yield Err(ProxyHttpError::NoHost);
      yield Ok(Frame::data(Bytes::from_static(b"unreachable")));
    });
    body.on_end(hook);

    assert!(body.frame().await.unwrap().is_ok());
    assert_count!(count, 0);
    assert!(body.frame().await.unwrap().is_err());
    assert_count!(count, 1);
  }

  #[tokio::test]
  async fn on_end_runs_on_drop_before_on_drop() {
    let order = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let mut body = Body::stream(async_stream::stream! {
      yield Ok(Frame::data(Bytes::from_static(b"hello")));
      yield Ok(Frame::data(Bytes::from_static(b"world")));
    });

    let o = order.clone();
    body.on_drop(move || o.lock().push("drop"));
    let o = order.clone();
    body.on_end(move || o.lock().push("end"));

    assert!(body.frame().await.is_some());
    assert!(order.lock().is_empty());
    drop(body);
    assert_eq!(*order.lock(), ["end", "drop"]);
  }

  #[tokio::test]
  async fn stream_channel() {
    let (body, mut sender) = Body::channel();

    tokio::spawn(async move {
      sender
        .send(Ok(Frame::data(Bytes::from_static(b"hello"))))
        .await
        .unwrap();
      sender
        .send(Ok(Frame::trailers(hyper::HeaderMap::new())))
        .await
        .unwrap();
    });

    assert_stream_collect!(body, Bytes::from_static(b"hello"));
  }
}
