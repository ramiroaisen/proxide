mod common;
use common::{block_on, get, https_request};

#[test]
fn sni_stream() {
  crate::lock!("sni.yml");
  block_on(async move {
    let mut request = reqwest::Request::new(
      reqwest::Method::GET,
      "http://127.0.0.1:23200/".parse().unwrap(),
    );
    request
      .headers_mut()
      .insert(reqwest::header::HOST, "example.com".parse().unwrap());

    let res = https_request(request).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "sni-stream");
  });
}

#[test]
fn sni_http() {
  crate::lock!("sni.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:23201/").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "sni-stream");
  });
}
