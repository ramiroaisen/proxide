use common::{block_on, get, send};
use proxide::body::Body;

mod common;

fn header(user: &str, password: &str) -> String {
  use base64::prelude::{Engine, BASE64_STANDARD};
  let base64 = BASE64_STANDARD.encode(format!("{}:{}", user, password));
  format!("Basic {}", base64)
}

#[test]
fn basic_auth() {
  launch!("basic-auth.yml");

  block_on(async move {
    let req = hyper::Request::builder()
      .method("GET")
      .uri("http://127.0.0.1:21500/")
      .header("authorization", header("user", "password"))
      .body(Body::empty())
      .unwrap();

    let res = send(req).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-user", "user");
    assert_header!(res, "x-test", "basic-auth");

    
    let req = hyper::Request::builder()
      .method("GET")
      .uri("http://127.0.0.1:21500/")
      .header("authorization", header("u", "p"))
      .body(Body::empty())
      .unwrap();
    
    let res = send(req).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-user", "u");
    assert_header!(res, "x-test", "basic-auth");

    let req = hyper::Request::builder()
      .method("GET")
      .uri("http://127.0.0.1:21500/")
      .header("authorization", header("user", "bad"))
      .body(Body::empty())
      .unwrap();
    
    let res = send(req).await.unwrap();

    assert_status!(res, UNAUTHORIZED);
    assert_header!(res, "x-test", "basic-auth");

    let res = get("http://127.0.0.1:21500/").await.unwrap();
    assert_status!(res, UNAUTHORIZED);
    assert_header!(res, "x-test", "basic-auth");
  })
}