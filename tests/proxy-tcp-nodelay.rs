mod common;

use common::{block_on, get};

#[test]
fn proxy_tcp_nodelay() {
  for port in [0, 1] {
    crate::lock!("proxy-tcp-nodelay.yml");
    block_on(async move {
      let res = get(&format!("http://127.0.0.1:1350{port}")).await.unwrap();
      assert_status!(res, OK);
      assert_header!(res, "x-test", "proxy-tcp-nodelay");
    });
  }
}
