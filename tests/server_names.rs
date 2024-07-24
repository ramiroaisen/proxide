mod common;
use common::{block_on, send};
use proxide::body::Body;

#[test]
fn server_names() {
  crate::lock!("server_names.yml");
  block_on(async move {
    let cases = [
      ("name-1", "single-name"),
      ("name-2", "several-names"),
      ("name-3", "several-names"),
      ("name-4-123", "several-names"),
      ("name-4-asd", "several-names"),
      ("other-name", "no-name"),
      ("other-name-123", "no-name"),
    ];

    for (name, server) in cases {
      let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:24000/{name}"))
        .header("host", name)
        .body(Body::empty())
        .unwrap();
      let res = send(req)
        .await
        .expect("error making request (server names)");
      assert_status!(res, OK);
      assert_header!(res, "content-type", "text/plain");
      assert_header!(res, "x-test", "server-names");
      assert_header!(res, "x-server", server);
    }
  });
}
