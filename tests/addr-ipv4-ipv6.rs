mod common;

use common::{block_on, get};

#[test]
fn addr_ipv4() {
  crate::lock!("addr-ipv4-ipv6.yml");
  block_on(async move {
    let res = get("http://127.0.0.1:23900").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "addr-ipv4");

    get("http://[::1]:23900").await.unwrap_err();
  });
}

#[test]
fn addr_ipv6() {
  crate::lock!("addr-ipv4-ipv6.yml");
  block_on(async move {
    let res = get("http://[::1]:23901").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "addr-ipv6");

    get("http://127.0.0.1:23901").await.unwrap_err();
  })
}
