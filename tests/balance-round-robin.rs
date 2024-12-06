mod common;

use std::time::Duration;

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

#[test]
fn balance_round_robin_with_weight() {
  lock!("balance-round-robin.yml");

  for p in [0, 1] {
    common::block_on(async move {
      for _ in 0..50 {
        for j in 0..6 {
          let target = match j {
            0 => 2,
            1 => 1,
            2 => 0,
            3 => 2,
            4 => 1,
            5 => 2,
            _ => unreachable!(),
          };

          let res = get(&format!("http://127.0.0.1:2031{p}/")).await.unwrap();
          assert_status!(res, OK);
          assert_header!(res, "x-upstream", &format!("{}", target));
        }
      }
    })
  }
}

#[test]
fn balance_round_robin_with_weight_and_unhealthy_upstreams() {
  lock!("balance-round-robin.yml");

  std::thread::sleep(Duration::from_millis(200));

  for p in [0] {
    common::block_on(async move {
      for _ in 0..50 {
        for j in 0..6 {
          let target = match j {
            0 => 2,
            1 => 1,
            2 => 0,
            3 => 2,
            4 => 1,
            5 => 2,
            _ => unreachable!(),
          };

          let res = get(&format!("http://127.0.0.1:2032{p}/")).await.unwrap();

          // dbg!(
          //   p,
          //   i,
          //   j,
          //   target,
          //   res.headers().get("x-upstream").unwrap().to_str().unwrap()
          // );

          assert_status!(res, OK);
          assert_header!(res, "x-upstream", &format!("{}", target));
        }
      }
    })
  }
}
