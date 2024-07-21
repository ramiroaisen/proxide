mod common;
use common::get;

#[test]
fn balance_ip_hash() {
  lock!("balance-ip-hash.yml");
  common::block_on(async move {
    for p in [0, 1] {
      let mut r0: usize = 0;
      let mut r1: usize = 0;

      for _ in 0..100 {
        let res = get(&format!("http://127.0.0.1:2050{p}/")).await.unwrap();

        assert_status!(res, OK);

        let upstream = res.headers().get("x-upstream").unwrap().to_str().unwrap();

        match upstream {
          "0" => r0 += 1,
          "1" => r1 += 1,
          n => panic!("x-ip-hash header not 0 or 1: {n}"),
        }
      }

      assert!(
        (r0 == 100 && r1 == 0) || (r0 == 0 && r1 == 100),
        "r0 is {r0}, r1 is {r1}"
      );
    }
  })
}
