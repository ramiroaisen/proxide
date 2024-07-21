mod common;
use common::{block_on, get};
use http_body_util::BodyExt;

#[test]
fn return_200() {
  crate::lock!("return.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:20200/return-200").await.expect("error making request (return 200)");
    assert_status!(res, OK);
    assert_header!(res, "content-type", "text/plain");
  });
}

#[test]
fn return_301() {
  crate::lock!("return.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:20200/return-301").await.expect("error making request (return 301)");
    assert_status!(res, MOVED_PERMANENTLY);
    assert_header!(res, "location", "https://example.com");
  })
}

#[test]
fn return_body() {
  crate::lock!("return.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:20200/return-body").await.expect("error making request (return body)");
    assert_status!(res, OK);
    assert_header!(res, hyper::header::CONTENT_TYPE, "text/plain");
    assert_body!(res, "example test body");
  })
}

#[test]
fn return_vars() {
  crate::lock!("return.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:20200/return-vars").await.expect("error making request (return vars)");

    assert_status!(res, OK);
    assert_header!(res, "content-type", "text/plain");

    assert_header!(res, "x-method", "GET");
    assert_header!(res, "x-scheme", "http");
    assert_header!(res, "x-host", "127.0.0.1");
    assert_header!(res, "x-port", ":20200");
    assert_header!(res, "x-request-uri", "/return-vars");
    assert_header!(res, "x-remote-ip", "127.0.0.1");
    
    assert_body!(res, "GET http://127.0.0.1:20200/return-vars from 127.0.0.1");

  })
}