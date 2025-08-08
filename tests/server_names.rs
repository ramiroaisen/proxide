mod common;
use common::block_on;

use crate::common::client;

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
      let res = client()
        .get(&format!("http://127.0.0.1:24000/{name}"))
        .header("host", name)
        .send()
        .await
        .unwrap();

      assert_status!(res, OK);
      assert_header!(res, "content-type", "text/plain");
      assert_header!(res, "x-test", "server-names");
      assert_header!(res, "x-server", server);
    }
  });
}
