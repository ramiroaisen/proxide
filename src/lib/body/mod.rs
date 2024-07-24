use crate::channel::spsc;
use bytes::Bytes;
use futures::Stream;
use http_body::Frame;
use http_body::SizeHint;
use hyper::body::Body as HyperBody;
use hyper::body::Incoming;
use pin_project::{pin_project, pinned_drop};
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

#[pin_project(PinnedDrop)]
pub struct Body {
  #[pin]
  pub(crate) kind: BodyKind,
  pub(crate) on_drop: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

#[pinned_drop]
impl PinnedDrop for Body {
  fn drop(self: Pin<&mut Self>) {
    for fun in self.project().on_drop.drain(..) {
      fun();
    }
  }
}

impl Body {
  pub fn empty() -> Self {
    Self {
      kind: BodyKind::empty(),
      on_drop: vec![],
    }
  }

  pub fn full<B: Into<Bytes> + Send + Sync + 'static>(data: B) -> Self {
    Self {
      kind: BodyKind::full(data),
      on_drop: vec![],
    }
  }

  pub fn incoming(incoming: Incoming) -> Self {
    Self {
      kind: BodyKind::incoming(incoming),
      on_drop: vec![],
    }
  }

  pub fn stream<S: Stream<Item = Result<Frame<Bytes>, ProxyHttpError>> + Send + Sync + 'static>(
    stream: S,
  ) -> Self {
    Self {
      kind: BodyKind::stream(stream),
      on_drop: vec![],
    }
  }

  pub fn channel() -> (Self, spsc::Sender<Result<Frame<Bytes>, ProxyHttpError>>) {
    let (kind, sender) = BodyKind::channel();
    let body = Self {
      kind,
      on_drop: vec![],
    };

    (body, sender)
  }

  pub fn on_drop<F: FnOnce() + Send + Sync + 'static>(&mut self, fun: F) {
    self.on_drop.push(Box::new(fun));
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
      // we could use Stream::size_hint() here but its said in the declaration of the trait that it should not trusted to be correct
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
    self.project().kind.poll_frame(cx)
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
    self.project().kind.poll_next(cx)
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
