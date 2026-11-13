//! Whose turn it is on a server connection.
//!
//! The read timeout of a server connection closes it when the client is
//! expected to send something and does not. Once a request was received
//! completely, and while its response has nothing to send, the client is
//! only waiting for us (and for the upstream behind us): that wait is
//! bounded by the timeouts of the upstream, not by the read timeout of the
//! client. For those periods the request holds the [`ReadGate`] of its
//! connection:
//!
//! - from the end of the request until the handler produces a response
//! - every time the response body is asked for a frame and has none yet
//!
//! A response head or a frame that is ready and is not being taken, because
//! the client stopped reading, is the client's turn again: on http/1 the
//! write timeout sees the blocked socket, but on http/2 a stalled flow
//! control window blocks no write, and the read timeout is the only one
//! left to close the connection.

use crate::{body::Body, net::timeout::ReadGate, proxy::error::ProxyHttpError};
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use hyper::{
  body::{Body as HyperBody, Incoming},
  Request, Response,
};
use parking_lot::Mutex;
use pin_project::pin_project;
use std::{
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
};

struct Turn {
  gate: Arc<ReadGate>,
  state: Mutex<State>,
}

struct State {
  /// the request, body included, was received (or will not be read anymore)
  request_ended: bool,
  /// the response has nothing to send yet
  response_pending: bool,
  holding: bool,
}

impl Turn {
  fn update(&self, f: impl FnOnce(&mut State)) {
    let mut state = self.state.lock();
    f(&mut state);

    let hold = state.request_ended && state.response_pending;
    if hold != state.holding {
      state.holding = hold;
      if hold {
        self.gate.hold();
      } else {
        self.gate.release();
      }
    }
  }
}

/// The response side of a request in flight, from the moment the request
/// arrives until its response ends or is abandoned.
pub struct ResponseTurn {
  turn: Arc<Turn>,
}

impl ResponseTurn {
  fn set_pending(&self, pending: bool) {
    self.turn.update(|state| state.response_pending = pending);
  }

  /// The handler produced a response: follow its body until it ends.
  ///
  /// From here on the turn is only ours while the body is asked for a
  /// frame and has none. Until it is polled there is a response head
  /// ready to be taken, and a client that does not take it (http/2 can
  /// open a stream with an empty window) is not waiting for us.
  pub fn track(self, response: Response<Body>) -> Response<TrackedBody> {
    self.set_pending(false);

    response.map(|inner| {
      // a body that is already over (empty responses, upgrades) may never
      // be polled, there is nothing left to follow
      let turn = (!inner.is_end_stream()).then_some(self);
      TrackedBody {
        inner,
        turn,
        pending: false,
      }
    })
  }
}

impl Drop for ResponseTurn {
  fn drop(&mut self) {
    self.set_pending(false);
  }
}

/// Start following a request that just arrived on the connection that
/// `gate` belongs to. The returned [`ResponseTurn`] has to be kept until
/// there is a response, and then handed to it with [`ResponseTurn::track`].
pub fn track(gate: &Arc<ReadGate>, request: Request<Incoming>) -> (Request<Body>, ResponseTurn) {
  let (parts, incoming) = request.into_parts();
  let (body, turn) = track_body(gate, Body::from(incoming));
  (Request::from_parts(parts, body), turn)
}

fn track_body(gate: &Arc<ReadGate>, mut request_body: Body) -> (Body, ResponseTurn) {
  let turn = Arc::new(Turn {
    gate: gate.clone(),
    state: Mutex::new(State {
      request_ended: false,
      response_pending: true,
      holding: false,
    }),
  });

  {
    let turn = turn.clone();
    // runs right away for a request without body
    request_body.on_end(move || turn.update(|state| state.request_ended = true));
  }

  (request_body, ResponseTurn { turn })
}

/// A response body that reports to the connection whether it is waiting
/// for something to send.
#[pin_project]
pub struct TrackedBody {
  #[pin]
  inner: Body,
  turn: Option<ResponseTurn>,
  /// what the turn was last told, to only tell it about changes
  pending: bool,
}

impl HyperBody for TrackedBody {
  type Data = Bytes;
  type Error = ProxyHttpError;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let me = self.project();
    let mut inner = me.inner;
    let poll = inner.as_mut().poll_frame(cx);

    if me.turn.is_some() {
      let pending = match &poll {
        Poll::Pending => Some(true),
        Poll::Ready(Some(Ok(_))) if !inner.is_end_stream() => Some(false),
        // last frame, end or error
        Poll::Ready(_) => None,
      };

      match pending {
        None => *me.turn = None,
        Some(pending) => {
          if pending != *me.pending {
            *me.pending = pending;
            me.turn.as_ref().unwrap().set_pending(pending);
          }
        }
      }
    }

    poll
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    HyperBody::size_hint(&self.inner)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use futures::FutureExt;
  use http_body_util::BodyExt;

  /// feeds a body without waiting for it to be polled
  struct Sender(futures::channel::mpsc::UnboundedSender<Result<Frame<Bytes>, ProxyHttpError>>);

  impl Sender {
    fn send(&mut self, item: Result<Frame<Bytes>, ProxyHttpError>) {
      self.0.unbounded_send(item).unwrap();
    }
  }

  fn channel() -> (Body, Sender) {
    let (sender, receiver) = futures::channel::mpsc::unbounded();
    (Body::stream(receiver), Sender(sender))
  }

  fn data(data: &'static str) -> Result<Frame<Bytes>, ProxyHttpError> {
    Ok(Frame::data(Bytes::from_static(data.as_bytes())))
  }

  /// polls the body once, None if it has nothing to yield yet
  fn poll<B: HyperBody<Data = Bytes> + Unpin>(body: &mut B) -> Option<Option<String>> {
    body.frame().now_or_never().map(|frame| {
      frame.map(|frame| {
        let data = frame.ok().unwrap().into_data().unwrap();
        String::from_utf8(data.to_vec()).unwrap()
      })
    })
  }

  /// a request that was received completely, and the gate of its connection
  fn request_without_body() -> (Arc<ReadGate>, ResponseTurn) {
    let gate = ReadGate::new();
    let (_body, turn) = track_body(&gate, Body::empty());
    (gate, turn)
  }

  fn response(turn: ResponseTurn, body: Body) -> Pin<Box<TrackedBody>> {
    Box::pin(turn.track(Response::new(body)).into_body())
  }

  fn streamed_response(turn: ResponseTurn) -> (Pin<Box<TrackedBody>>, Sender) {
    let (body, sender) = channel();
    (response(turn, body), sender)
  }

  #[tokio::test]
  async fn holds_from_a_request_without_body_until_the_response() {
    let (gate, turn) = request_without_body();
    // waiting for the handler
    assert!(gate.is_held());

    // there is a response to take, and nobody asked for its body yet
    let mut body = response(turn, Body::full("hello"));
    assert!(!gate.is_held());

    assert_eq!(poll(&mut body), Some(Some("hello".into())));
    assert!(!gate.is_held());
  }

  /// a response whose body is never asked for: the client is not taking
  /// the response, it is not waiting for us
  #[tokio::test]
  async fn does_not_hold_for_a_response_body_that_is_never_polled() {
    let (gate, turn) = request_without_body();
    let (body, _sender) = streamed_response(turn);
    assert!(!gate.is_held());
    drop(body);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn does_not_hold_while_the_request_body_is_being_received() {
    let gate = ReadGate::new();
    let (request_body, mut sender) = channel();
    let (request_body, turn) = track_body(&gate, request_body);
    let mut request_body = Box::pin(request_body);

    // the client is the one that has to send
    assert!(!gate.is_held());
    assert_eq!(poll(&mut request_body), None);
    assert!(!gate.is_held());

    sender.send(data("part"));
    assert_eq!(poll(&mut request_body), Some(Some("part".into())));
    assert!(!gate.is_held());

    drop(sender);
    assert_eq!(poll(&mut request_body), Some(None));
    // the request is complete, now the client waits for us
    assert!(gate.is_held());

    drop(turn);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn holds_when_the_request_body_is_abandoned() {
    let gate = ReadGate::new();
    let (request_body, _sender) = channel();
    let (request_body, turn) = track_body(&gate, request_body);
    assert!(!gate.is_held());

    // nobody is going to read the rest of it
    drop(request_body);
    assert!(gate.is_held());

    drop(turn);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn holds_only_while_the_response_body_has_nothing_to_yield() {
    let (gate, turn) = request_without_body();
    let (mut body, mut sender) = streamed_response(turn);

    for part in ["a", "b", "c"] {
      // waiting for the upstream
      assert_eq!(poll(&mut body), None);
      assert!(gate.is_held());

      // a frame was handed over: if the next one is not asked for, it is
      // because the client is not taking it
      sender.send(data(part));
      assert_eq!(poll(&mut body), Some(Some(part.into())));
      assert!(!gate.is_held());
    }

    assert_eq!(poll(&mut body), None);
    assert!(gate.is_held());

    drop(sender);
    assert_eq!(poll(&mut body), Some(None));
    assert!(!gate.is_held());

    // nothing changes after the end
    assert_eq!(poll(&mut body), Some(None));
    drop(body);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn releases_when_the_response_body_fails() {
    let (gate, turn) = request_without_body();
    let (mut body, mut sender) = streamed_response(turn);

    assert_eq!(poll(&mut body), None);
    assert!(gate.is_held());

    sender.send(Err(ProxyHttpError::NoHost));
    assert!(body.frame().await.unwrap().is_err());
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn releases_when_the_response_body_is_dropped() {
    let (gate, turn) = request_without_body();
    let (mut body, _sender) = streamed_response(turn);

    assert_eq!(poll(&mut body), None);
    assert!(gate.is_held());

    drop(body);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn releases_when_there_is_never_a_response() {
    let (gate, turn) = request_without_body();
    assert!(gate.is_held());

    // the handler was cancelled
    drop(turn);
    assert!(!gate.is_held());
  }

  /// empty responses and upgrades: hyper never polls a body that is
  /// already over, and after an upgrade the connection is a tunnel
  #[tokio::test]
  async fn releases_at_once_for_a_response_without_body() {
    let (gate, turn) = request_without_body();
    assert!(gate.is_held());

    let body = response(turn, Body::empty());
    assert!(!gate.is_held());
    drop(body);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn response_that_ends_before_the_request_never_holds() {
    let gate = ReadGate::new();
    let (request_body, mut sender) = channel();
    let (request_body, turn) = track_body(&gate, request_body);
    let mut request_body = Box::pin(request_body);

    // answered without waiting for the request body
    let mut body = response(turn, Body::full("early"));
    assert_eq!(poll(&mut body), Some(Some("early".into())));
    assert!(!gate.is_held());

    sender.send(data("late"));
    drop(sender);
    assert_eq!(poll(&mut request_body), Some(Some("late".into())));
    assert_eq!(poll(&mut request_body), Some(None));
    assert!(!gate.is_held());
  }

  /// the requests of an http/2 connection share its gate
  #[tokio::test]
  async fn concurrent_requests_hold_independently() {
    let gate = ReadGate::new();
    let (_a, turn_a) = track_body(&gate, Body::empty());
    let (_b, turn_b) = track_body(&gate, Body::empty());
    assert!(gate.is_held());

    drop(turn_a);
    assert!(gate.is_held());

    drop(turn_b);
    assert!(!gate.is_held());
  }

  #[tokio::test]
  async fn tracked_body_keeps_the_size_of_the_body() {
    let (_gate, turn) = request_without_body();
    let body = response(turn, Body::full("hello"));
    assert_eq!(HyperBody::size_hint(&*body).exact(), Some(5));
    assert!(!body.is_end_stream());

    let (_gate, turn) = request_without_body();
    let body = response(turn, Body::empty());
    assert_eq!(HyperBody::size_hint(&*body).exact(), Some(0));
    assert!(body.is_end_stream());
  }
}
