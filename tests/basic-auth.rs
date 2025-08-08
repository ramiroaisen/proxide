mod common;
use common::{block_on, client, get};

#[test]
fn basic_auth() {
  launch!("basic-auth.yml");

  block_on(async move {
    let res = client()
      .get("http://127.0.0.1:21500/")
      .basic_auth("user", "password".into())
      .send()
      .await
      .unwrap();

    assert_status!(res, OK);
    assert_header!(res, "x-user", "user");
    assert_header!(res, "x-test", "basic-auth");

    let res = client()
      .get("http://127.0.0.1:21500/")
      .basic_auth("u", "p".into())
      .send()
      .await
      .unwrap();

    assert_status!(res, OK);
    assert_header!(res, "x-user", "u");
    assert_header!(res, "x-test", "basic-auth");

    let res = client()
      .get("http://127.0.0.1:21500/")
      .basic_auth("user", "bad".into())
      .send()
      .await
      .unwrap();

    assert_status!(res, UNAUTHORIZED);
    assert_header!(res, "x-test", "basic-auth");

    let res = get("http://127.0.0.1:21500/").await.unwrap();
    assert_status!(res, UNAUTHORIZED);
    assert_header!(res, "x-test", "basic-auth");
  })
}
