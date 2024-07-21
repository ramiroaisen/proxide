/// A reader that first reads from a pre-allocated buffer and then
/// reads from the inner reader
#[pin_project]
struct PreBufReader<R> {
  buf: Vec<u8>,
  #[pin]
  inner: R,
}

#[allow(unused)]
impl<R: AsyncRead> PreBufReader<R> {
  pub fn new(inner: R, buf: Vec<u8>) -> Self {
    Self { inner, buf }
  }

  // pub fn into_inner(self) -> R {
  //   self.inner
  // }

  // pub fn inner(&self) -> &R {
  //   &self.inner
  // }

  // pub fn inner_mut(&mut self) -> &mut R {
  //   &mut self.inner
  // }

  // pub fn buf(&self) -> &[u8] {
  //   &self.buf
  // }

  // pub fn inner_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
  //   self.project().inner
  // }
}

impl<S: AsyncRead> AsyncRead for PreBufReader<S> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.project();
    if !this.buf.is_empty() {
      if this.buf.len() <= buf.remaining() {
        buf.put_slice(this.buf);
        this.buf.clear();
      } else {
        buf.put_slice(&this.buf[..buf.remaining()]);
        this.buf.drain(..buf.remaining());
      }
      Poll::Ready(Ok(()))
    } else {
      this.inner.poll_read(cx, buf)
    }
  }
}

impl<S: AsyncWrite> AsyncWrite for PreBufReader<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    self.project().inner.poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    self.project().inner.poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    self.project().inner.poll_shutdown(cx)
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    self.project().inner.poll_write_vectored(cx, bufs)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::io::Cursor;
  use tokio::io::AsyncReadExt;

  #[tokio::test]
  async fn pre_buf_reader() {
    let pre_buf = vec![0u8, 1, 2, 3];
    let reader_buf = vec![4u8, 5, 6, 7];
    let reader = Cursor::new(reader_buf);
    let mut pre_buf_reader = PreBufReader::new(reader, pre_buf);
    let mut target_buf = vec![];
    pre_buf_reader.read_to_end(&mut target_buf).await.unwrap();
    assert_eq!(target_buf, vec![0, 1, 2, 3, 4, 5, 6, 7]);
  }

  #[tokio::test]
  async fn pre_buf_reader_pre_buf_empty() {
    let pre_buf = vec![];
    let reader_buf = vec![4u8, 5, 6, 7];
    let reader = Cursor::new(reader_buf);
    let mut pre_buf_reader = PreBufReader::new(reader, pre_buf);
    let mut target_buf = vec![];
    pre_buf_reader.read_to_end(&mut target_buf).await.unwrap();
    assert_eq!(target_buf, vec![4, 5, 6, 7]);
  }

  #[tokio::test]
  async fn pre_buf_reader_reader_empty() {
    let pre_buf = vec![0u8, 1, 2, 3];
    let reader_buf = vec![];
    let reader = Cursor::new(reader_buf);
    let mut pre_buf_reader = PreBufReader::new(reader, pre_buf);
    let mut target_buf = vec![];
    pre_buf_reader.read_to_end(&mut target_buf).await.unwrap();
    assert_eq!(target_buf, vec![0, 1, 2, 3]);
  }

  #[tokio::test]
  async fn pre_buf_reader_one_by_one() {
    let pre_buf = vec![0u8, 1, 2, 3];
    let reader_buf = vec![4u8, 5, 6, 7];
    let reader = Cursor::new(reader_buf);
    let mut pre_buf_reader = PreBufReader::new(reader, pre_buf);

    for n in 0..8u8 {
      let byte = pre_buf_reader.read_u8().await.unwrap();
      assert_eq!(byte, n);
    }
  }
}
