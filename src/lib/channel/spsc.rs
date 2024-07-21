use derivative::Derivative;
use futures::{Future, Stream};
use parking_lot::Mutex;
use pin_project::pin_project;
use std::{
  pin::Pin,
  sync::Arc,
  task::{Context, Poll, Waker},
};

#[inline(always)]
fn set_waker(prev: &mut Option<Waker>, waker: &Waker) {
  *prev = Some(waker.clone());
  // if let Some(prev) = prev {
  //   prev.clone_from(waker);
  // } else {
  //   *prev = Some(waker.clone());
  // }
}

/**
 * The sender half of the [`channel`].
 */
pub struct Sender<T> {
  state: Arc<Mutex<State<T>>>,
}

impl<T> Sender<T> {
  /**
   * the same as:
   * ```rust
   * # use proxide::channel::spsc::SendError;
   * # struct S<T>(T);
   * # impl<T> S<T> {
   * async fn send(&mut self) -> Result<T, SendError<T>> 
   * # { todo!() }
   * # }
   * # fn main() {}
   * `````
   * Send a value to the other side.\
   * This function will wait for the other side to receive to value to return.\
   * If the other side is dropped before receiving the value, an error will be returned.
   * */ 
  pub fn send(&mut self, item: T) -> SendFuture<T> {
    SendFuture {
      n: None,
      item: Some(item),
      state: &self.state,
    }
  }

  /**
   * Try to send the item without waiting.\
   * If the channel already have a pending value or if the other side was dropped, an error will be returned.\
   * Note that this funtion only puts the value in the channel as the a pending value,
   * it does not guarantee that the other side will receive the value.\
   */
  pub fn try_send(&mut self, item: T) -> Result<(), TrySendError<T>> {
    let mut state = self.state.lock();
    if state.item.is_some() {
      Err(TrySendError::Full(item))
    } else if state.receiver_dropped {
      Err(TrySendError::Closed(item))
    } else {
      state.item = Some(item);
      if let Some(waker) = state.recv_waker.take() {
        waker.wake();
      }
      Ok(())
    }
  }
}

impl<T> Drop for Sender<T> {
  fn drop(&mut self) {
    let mut state = self.state.lock();
    state.sender_dropped = true;
    if let Some(waker) = state.recv_waker.take() {
      waker.wake();
    }
  }
}

/**
 * The receiver half of the [`channel`].
 */
pub struct Receiver<T> {
  state: Arc<Mutex<State<T>>>,
}

impl<T> Receiver<T> {
  /**
   * the same as:
   * ```rust
   * # struct R<T>(T);
   * # impl<T> R<T> {
   * async fn recv(&mut self) -> Option<T> 
   * # { todo!() }
   * # }
   * # fn main() {}
   * `````
   * Receive a value from the other side.\   * 
   * This function will wait for the other side to send a value to return,\   * 
   * if the other side is dropped before sending the value, an error will be returned.\
   */
  pub fn recv(&mut self) -> RecvFuture<T> {
    RecvFuture {
      state: &*self.state,
    }
  }

  /**
   * Similar to [`Self::try_recv`] but accepts an async context to be awaken when progress was made.\
   */
  pub fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
    let mut state = self.state.lock();
    match state.item.take() {
      Some(item) => {
        if let Some(waker) = state.send_waker.take() {
          waker.wake();
        }
        Poll::Ready(Some(item))
      }

      None => {
        if state.sender_dropped {
          Poll::Ready(None)
        } else {
          set_waker(&mut state.recv_waker, cx.waker());
          Poll::Pending
        }
      }
    }
  }

  /** 
   * Try to receive the inflight value without waiting.\
   * This will only return Some if there are a current inflight value that was not alredy received.\
   */
  pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
    let mut state = self.state.lock();
    match state.item.take() {
      None => {
        if state.sender_dropped {
          Err(TryRecvError::Closed)
        } else {
          Err(TryRecvError::Empty)
        }
      }
      Some(item) => {
        if let Some(waker) = state.send_waker.take() {
          waker.wake();
        }
        Ok(item)
      }
    }
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    let mut state = self.state.lock();
    state.receiver_dropped = true;
    if let Some(waker) = state.send_waker.take() {
      waker.wake();
    }
  }
}

pub(crate) struct State<T> {
  sender_dropped: bool,
  receiver_dropped: bool,
  send_waker: Option<Waker>,
  recv_waker: Option<Waker>,
  item: Option<T>,
}

/**
 * The future returned by [`Sender::send`]. \
 * Same as [`Future<Output = Result<T, SendError<T>>>`](std::future::Future).
 */
#[pin_project]
pub struct SendFuture<'a, T> {
  state: &'a Arc<Mutex<State<T>>>,
  n: Option<usize>,
  item: Option<T>,
}

impl<T> Future for SendFuture<'_, T> {
  type Output = Result<(), SendError<T>>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut state = self.state.lock();

    match (&self.item, &state.item) {
      (Some(_), None) => {
        let item = self.item.take().unwrap();
        if state.receiver_dropped {
          Poll::Ready(Err(SendError(item)))
        } else {
          state.item = Some(item);
          set_waker(&mut state.send_waker, cx.waker()); 
          if let Some(waker) = state.recv_waker.take() {
            waker.wake();
          }
          Poll::Pending
        }
      }

      (None, None) => Poll::Ready(Ok(())),

      (_, Some(_)) => {
        if state.receiver_dropped {
          let item = self
            .item
            .take()
            .unwrap_or_else(|| state.item.take().unwrap());
          Poll::Ready(Err(SendError(item)))
        } else {
          set_waker(&mut state.send_waker, cx.waker());
          Poll::Pending
        }
      }
    }
  }
}

/**
 * The future returned by [`Receiver::recv`]. \
 * Same as [`Future<Output = Result<T, RecvErro>>`](std::future::Future).
 */
pub struct RecvFuture<'a, T> {
  state: &'a Mutex<State<T>>,
}

impl<T> Future for RecvFuture<'_, T> {
  type Output = Option<T>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut state = self.state.lock();

    match state.item.take() {
      Some(item) => {
        if let Some(waker) = state.send_waker.take() {
          waker.wake();
        }

        Poll::Ready(Some(item))
      }

      None => {
        if state.sender_dropped {
          Poll::Ready(None)
        } else {
          set_waker(&mut state.recv_waker, cx.waker());
          Poll::Pending
        }
      }
    }
  }
}

/**
 * Error retuned from [`Sender::send`] if the other side was dropped before receiving the value. \ * 
 * The error contains the value that was being sent.
 */
#[derive(Derivative, Eq, PartialEq, thiserror::Error)]
#[derivative(Debug)]
#[error("channel closed")]
pub struct SendError<T>(#[derivative(Debug = "ignore")] pub T);

/**
 * Error retuned from [`Sender::try_send`] if the other side was dropped before receiving the value or if there are no pending value available.\
 * The error contains the value that was being sent.
 */

#[derive(thiserror::Error, Eq, PartialEq, Derivative)]
#[derivative(Debug)]
pub enum TrySendError<T> {
  /**
   * The are already a pending value in this channel.
   */
  #[error("channel is full")]
  Full(#[derivative(Debug = "ignore")] T),
  /**
   * The other side was dropped.
   */
  #[error("channel is closed")]
  Closed(#[derivative(Debug = "ignore")] T),
}

impl<T> TrySendError<T> {
  /**
   * Get a reference to the value that could not be sent.
   */
  pub fn value(&self) -> &T {
    match self {
      TrySendError::Full(value) => value, 
      TrySendError::Closed(value) => value,
    }
  }

  /**
   * Get the value that could not be sent, consuming the error.
   */
  pub fn into_value(self) -> T {
    match self {
      TrySendError::Full(value) => value,
      TrySendError::Closed(value) => value,
    }
  }
}

/**
 * Error retuned from [`Receiver::try_recv`] if the channel is closed and/or the are no pending values 
 */
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum TryRecvError {
  /**
   * There are no pending values to be received.
   */
  #[error("channel is empty")]
  Empty,
  /**
   * The other side was dropped.
   */
  #[error("channel is closed")]
  Closed,
}

/**
 * A single producer, single consumer channel, without buffering.\
 * Ideal to send values between different tasks that can be running in different threads.
 * ````rust
 * # #[tokio::main]
 * # async fn main() {
 * # use proxide::channel::spsc::channel;
 * let (mut sender, mut receiver) = channel::<u8>();
 * 
 * let send = tokio::spawn(async move {
 *   sender.send(1).await.unwrap();
 * });
 * 
 * assert_eq!(receiver.recv().await, Some(1));
 * assert_eq!(receiver.recv().await, None);
 * # }
 * `````
 */
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
  let state = Arc::new(Mutex::new(State {
    sender_dropped: false,
    receiver_dropped: false,
    recv_waker: None,
    send_waker: None,
    item: None,
  }));

  let sender = Sender {
    state: state.clone(),
  };

  let receiver = Receiver { state };

  (sender, receiver)
}

impl<T> Stream for Receiver<T> {
  type Item = T;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    self.poll_recv(cx)
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    let state = self.state.lock();
    let down = if state.item.is_some() {
      1
    } else {
      0
    };

    let up = if state.sender_dropped {
      if state.item.is_some() {
        Some(1)
      } else {
        Some(0)
      }
    } else {
      None
    };

    (down, up)    
  }
}

#[cfg(test)]
mod test {

  use super::*;
  use futures::StreamExt;
  use std::time::Duration;

  #[allow(unused)]
  trait AssertSend: Send {}
  impl<T: Send> AssertSend for Sender<T> {}
  impl<T: Send> AssertSend for Receiver<T> {}
  impl<T: Send> AssertSend for SendFuture<'_, T> {}
  impl<T: Send> AssertSend for RecvFuture<'_, T> {}

  #[allow(unused)]
  trait AssertSync: Sync {}
  impl<T: Send + Sync> AssertSync for Sender<T> {}
  impl<T: Send + Sync> AssertSync for Receiver<T> {}
  impl<T: Send + Sync> AssertSync for SendFuture<'_, T> {}
  impl<T: Send + Sync> AssertSync for RecvFuture<'_, T> {}

  #[allow(unused)]
  trait AssertUnpin: Unpin {}
  impl<T> AssertUnpin for SendFuture<'_, T> {}
  impl<T> AssertUnpin for RecvFuture<'_, T> {}

  #[pin_project]
  struct DoubleWaker<I> {
    #[pin]
    inner: I,
  }

  impl<I: Future> Future for DoubleWaker<I> {
    type Output = I::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
      cx.waker().wake_by_ref();
      self.project().inner.poll(cx)
    }
  }

  fn double<I: Future>(inner: I) -> impl Future<Output = I::Output> {
    DoubleWaker { inner }
  }

  #[tokio::test]
  async fn should_send_recv() {
    let (mut sender, mut receiver) = channel::<u8>();

    tokio::spawn(async move {
      sender.send(1).await.unwrap();
      sender.send(2).await.unwrap();
      sender.send(3).await.unwrap();
    });

    assert_eq!(receiver.recv().await.unwrap(), 1);
    assert_eq!(receiver.recv().await.unwrap(), 2);
    assert_eq!(receiver.recv().await.unwrap(), 3);
  }

  #[tokio::test]
  async fn should_send_recv_after_close() {
    let (mut sender, mut receiver) = channel::<u8>();

    let send = async {
      sender.send(1).await.unwrap();
    };

    let recv = async {
      assert_eq!(receiver.recv().await.unwrap(), 1);
    };

    tokio::join!(send, recv);

    drop(sender);

    assert!(receiver.recv().await.is_none());
  }

  #[tokio::test]
  async fn should_err_on_send_after_close() {
    let (mut sender, receiver) = channel::<u8>();
    drop(receiver);
    assert!(sender.send(1).await.is_err());
  }

  #[tokio::test]
  async fn should_err_on_recv_after_close() {
    let (sender, mut receiver) = channel::<u8>();
    drop(sender);
    assert!(receiver.recv().await.is_none());
  }

  #[tokio::test]
  async fn should_err_on_recv_after_delayed_close() {
    tokio::time::pause();
    let (sender, mut receiver) = channel::<()>();
    let handle = tokio::spawn(async move {
      tokio::time::sleep(std::time::Duration::from_secs(1)).await;
      drop(sender);
    });
    assert!(receiver.recv().await.is_none());
    handle.await.unwrap();
  }

  #[tokio::test]
  async fn should_err_on_send_after_delayed_close() {
    tokio::time::pause();
    let (mut sender, receiver) = channel::<()>();
    let handle = tokio::spawn(async move {
      tokio::time::sleep(std::time::Duration::from_secs(1)).await;
      drop(receiver);
    });
    assert!(sender.send(()).await.is_err());
    handle.await.unwrap();
  }

  #[tokio::test]
  async fn should_err_on_recv_after_send_and_close() {
    let (mut sender, mut receiver) = channel::<u8>();

    let handle = tokio::spawn(async move {
      sender.send(1).await.unwrap();
      sender.send(2).await.unwrap();
      sender.send(3).await.unwrap();
    });

    assert_eq!(receiver.recv().await.unwrap(), 1);
    assert_eq!(receiver.recv().await.unwrap(), 2);
    assert_eq!(receiver.recv().await.unwrap(), 3);
    assert!(receiver.recv().await.is_none());

    handle.await.unwrap();
  }

  #[tokio::test]
  async fn should_err_on_send_after_recv_and_close() {
    let (mut sender, mut receiver) = channel::<()>();

    let handle = tokio::spawn(async move {
      receiver.recv().await.unwrap();
      receiver.recv().await.unwrap();
      receiver.recv().await.unwrap();
    });

    sender.send(()).await.unwrap();
    sender.send(()).await.unwrap();
    sender.send(()).await.unwrap();
    assert!(sender.send(()).await.is_err());

    handle.await.unwrap()
  }

  #[tokio::test]
  async fn stream_collect() {
    let (mut sender, receiver) = channel::<u8>();

    let handle = tokio::spawn(async move {
      sender.send(1).await.unwrap();
      sender.send(2).await.unwrap();
      sender.send(3).await.unwrap();
    });

    assert_eq!(receiver.collect::<Vec<_>>().await, vec![1, 2, 3]);

    handle.await.unwrap();
  }

  #[tokio::test]
  async fn stream_size_hint() {
    tokio::time::pause();
    let (mut sender, mut receiver) = channel::<u8>();

    let handle = tokio::spawn(async move {
      tokio::time::sleep(Duration::from_secs(1)).await;
      sender.send(1).await.unwrap();
      sender.send(2).await.unwrap();
      sender.send(3).await.unwrap();
    });

    assert_eq!(receiver.size_hint(), (0, None));
    assert_eq!(receiver.next().await.unwrap(), 1);

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(receiver.size_hint(), (1, None));

    assert_eq!(receiver.next().await.unwrap(), 2);
    assert_eq!(receiver.next().await.unwrap(), 3);

    handle.await.unwrap();    

    assert_eq!(receiver.size_hint(), (0, Some(0)));

    assert_eq!(receiver.next().await, None);
  }

  #[tokio::test]
  async fn stream_should_collect_values_with_take() {
    let (mut sender, receiver) = channel::<u8>();

    let handle = tokio::spawn(async move {
      let vec = receiver.take(3).collect::<Vec<_>>().await;
      assert_eq!(vec, vec![1, 2, 3]);
    });

    sender.send(1).await.unwrap();
    sender.send(2).await.unwrap();
    sender.send(3).await.unwrap();
    assert!(sender.send(4).await.is_err());

    handle.await.unwrap();
  }

  #[tokio::test]
  async fn send_double_wake() {
    let (mut sender, mut receiver) = channel::<u8>();

    let send = async {
      double(sender.send(1)).await.unwrap();
      double(sender.send(2)).await.unwrap();
      double(sender.send(3)).await.unwrap();
    };

    let recv = async {
      assert_eq!(receiver.recv().await.unwrap(), 1);
      assert_eq!(receiver.recv().await.unwrap(), 2);
      assert_eq!(receiver.recv().await.unwrap(), 3);
    };

    tokio::join!(send, recv);

    drop(sender);

    assert!(receiver.recv().await.is_none());
  }

  #[tokio::test]
  async fn recv_double_wake() {
    let (mut sender, mut receiver) = channel::<u8>();

    let send = async {
      sender.send(1).await.unwrap();
      sender.send(2).await.unwrap();
      sender.send(3).await.unwrap();
    };

    let recv = async {
      assert_eq!(double(receiver.recv()).await.unwrap(), 1);
      assert_eq!(double(receiver.recv()).await.unwrap(), 2);
      assert_eq!(double(receiver.recv()).await.unwrap(), 3);
    };

    tokio::join!(send, recv);

    drop(receiver);

    assert!(sender.send(4).await.is_err());
  }

  #[tokio::test]
  async fn try_recv() {
    tokio::time::pause();
    let (mut sender, mut receiver) = channel::<u8>();

    let send = async {
      sender.send(1).await.unwrap();
    };

    let recv = async {
      tokio::time::sleep(Duration::from_secs(1)).await;
      assert_eq!(receiver.try_recv().unwrap(), 1);
    };

    tokio::join!(send, recv);

    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));

    drop(sender);

    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
  }

  #[tokio::test]
  async fn try_send() {
    tokio::time::pause();
    let (mut sender, mut receiver) = channel::<u8>();

    let send = async {
      sender.try_send(1).unwrap();
    };

    let recv = async {
      tokio::time::sleep(Duration::from_secs(1)).await;
      assert_eq!(receiver.try_recv().unwrap(), 1);
    };

    tokio::join!(send, recv);

    assert_eq!(sender.try_send(2), Ok(()));
    assert_eq!(sender.try_send(3), Err(TrySendError::Full(3))); 

    assert_eq!(receiver.recv().await.unwrap(), 2);
    drop(receiver);

    assert_eq!(sender.try_send(4), Err(TrySendError::Closed(4)));
  }
}