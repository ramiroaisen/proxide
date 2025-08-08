// this was extracted from scuffle-http
// see https://docs.rs/scuffle-http/0.3.2/src/scuffle_http/backend/h3/body.rs.html#35-38
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::error::StreamError;
use http::HeaderMap;
use http_body::Frame;
use pin_project::pin_project;

/// Error type for [`QuicIncomingBody`].
#[derive(thiserror::Error, Debug)]
pub enum Http3BodyError {
  #[error("h3 stream error getting data frame: {0}")]
  StreamErrorData(#[from] h3::error::StreamError),

  #[error("h3 stream error getting trailers frame: {0}")]
  StreamErrorTrailers(#[source] h3::error::StreamError),

  #[error("size hint exceeded")]
  SizeHintExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  Data(Option<u64>),
  Trailers,
  Done,
}

pub trait BodyStream: Unpin + Send + Sync + 'static {
  fn poll_recv_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>>;
  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<HeaderMap>, StreamError>>;
}

impl BodyStream for h3::server::RequestStream<h3_quinn::RecvStream, Bytes> {
  fn poll_recv_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
    match self.poll_recv_data(cx) {
      Poll::Ready(Ok(Some(mut buf))) => Poll::Ready(Ok(Some(buf.copy_to_bytes(buf.remaining())))),
      Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
      Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
      Poll::Pending => Poll::Pending,
    }
  }

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
    self.poll_recv_trailers(cx)
  }
}

impl BodyStream for h3::client::RequestStream<h3_quinn::RecvStream, Bytes> {
  fn poll_recv_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
    match self.poll_recv_data(cx) {
      Poll::Ready(Ok(Some(mut buf))) => Poll::Ready(Ok(Some(buf.copy_to_bytes(buf.remaining())))),
      Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
      Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
      Poll::Pending => Poll::Pending,
    }
  }

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
    self.poll_recv_trailers(cx)
  }
}

/// An incoming HTTP/3 body.
///
/// Implements [`http_body::Body`].
#[pin_project]
pub struct Incoming<S> {
  #[pin]
  stream: S,
  state: State,
}

impl<S> Incoming<S> {
  /// Create a new incoming HTTP/3 body.
  pub fn new(stream: S, size_hint: Option<u64>) -> Self
  where
    S: BodyStream,
  {
    Self {
      stream,
      state: State::Data(size_hint),
    }
  }
}

impl<S: BodyStream> http_body::Body for Incoming<S> {
  type Data = Bytes;
  type Error = Http3BodyError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
    loop {
      match self.state {
        State::Data(remaining) => {
          match futures::ready!(self.as_mut().project().stream.poll_recv_data(cx)) {
            Ok(Some(buf)) => {
              let buf_size = buf.len() as u64;

              if let Some(remaining) = remaining {
                if buf_size > remaining {
                  self.state = State::Done;
                  return Poll::Ready(Some(Err(Http3BodyError::SizeHintExceeded)));
                }

                self.state = State::Data(Some(remaining - buf_size));
              }

              return Poll::Ready(Some(Ok(Frame::data(buf))));
            }

            Ok(None) => {
              self.state = State::Trailers;
              continue;
            }

            Err(err) => {
              self.state = State::Done;
              return Poll::Ready(Some(Err(Http3BodyError::StreamErrorData(err))));
            }
          }
        }

        State::Trailers => {
          match futures::ready!(self.as_mut().project().stream.poll_recv_trailers(cx)) {
            Ok(Some(trailers)) => {
              self.state = State::Done;
              return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            Ok(None) => {
              self.state = State::Done;
              return Poll::Ready(None);
            }
            Err(err) => {
              self.state = State::Done;
              return Poll::Ready(Some(Err(Http3BodyError::StreamErrorTrailers(err))));
            }
          }
        }

        State::Done => {
          return Poll::Ready(None);
        }
      }
    }
  }

  fn size_hint(&self) -> http_body::SizeHint {
    match self.state {
      State::Data(Some(remaining)) => http_body::SizeHint::with_exact(remaining),
      State::Data(None) => http_body::SizeHint::default(),
      State::Trailers | State::Done => http_body::SizeHint::with_exact(0),
    }
  }

  fn is_end_stream(&self) -> bool {
    match self.state {
      State::Data(Some(0)) | State::Trailers | State::Done => true,
      State::Data(_) => false,
    }
  }
}
