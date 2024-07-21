mod common;

use common::get;

#[test]
fn balance_round_robin() {
  lock!("balance-round-robin.yml");

  for p in [0, 1] {
    common::block_on(async move {
      for _ in 0..50 {
        for j in 0..4 {
          let res = get(&format!("http://127.0.0.1:2030{p}/")).await.unwrap();
          assert_status!(res, OK);
          assert_header!(res, "x-upstream", &format!("{}", j));
        }
      }
    })
  }
}
