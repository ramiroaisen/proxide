use common::{block_on, get};

mod common;

#[test]
fn upstream_down() {
  launch!("upstream-down.yml");

  block_on(async move {
    for balance in ["round-robin", "random", "ip-hash", "least-connections"] {
      for _ in 0..50 {
        let res = get(&format!("http://127.0.0.1:21605/balance-{balance}"))
          .await
          .unwrap();
        assert_status!(res, OK);
        assert_header!(res, "x-test", "upstream-down");
        assert_header!(res, "x-balance", balance);
      }
    }
  })
}
