mod common;
use common::get;

#[test]
fn balance_random() {
  lock!("balance-random.yml");
  common::block_on(async move {
    for p in [0, 1] {
      let mut r0: usize = 0;
      let mut r1: usize = 0;

      for _ in 0..1000 {
        let res = get(&format!("http://127.0.0.1:2040{p}/")).await.unwrap();

        assert_status!(res, OK);

        let random = res.headers().get("x-upstream").unwrap().to_str().unwrap();

        match random {
          "0" => r0 += 1,
          "1" => r1 += 1,
          n => panic!("x-upstream header not 0 or 1: {n}"),
        }
      }

      dbg!(r0);
      dbg!(r1);

      assert!(r0 >= 400, "r0 is {r0}");
      assert!(r0 <= 600, "r0 is {r0}");
      assert!(r1 >= 400, "r1 is {r1}");
      assert!(r1 <= 600, "r1 is {r1}");
    }
  })
}

#[test]
fn balance_random_with_weight() {
  lock!("balance-random.yml");
  common::block_on(async move {
    for p in [2, 3] {
      let mut r0: usize = 0;
      let mut r1: usize = 0;

      for _ in 0..1000 {
        let res = get(&format!("http://127.0.0.1:2040{p}/")).await.unwrap();

        assert_status!(res, OK);

        let random = res.headers().get("x-upstream").unwrap().to_str().unwrap();

        match random {
          "0" => r0 += 1,
          "1" => r1 += 1,
          n => panic!("x-upstream header not 0 or 1: {n}"),
        }
      }

      dbg!(r0);
      dbg!(r1);

      assert!(r0 >= 650, "r0 is {r0}");
      assert!(r0 <= 850, "r0 is {r0}");
      assert!(r1 >= 150, "r1 is {r1}");
      assert!(r1 <= 350, "r1 is {r1}");
    }
  })
}
