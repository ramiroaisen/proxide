mod common;

#[test]
fn base_url_path() {
  lock!("base-url-path.yml");
  common::block_on(async move {
    let res = common::get("http://127.0.0.1:21100/").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-front-request-uri", "/");
    assert_header!(res, "x-upstream-request-uri", "/prefix/");

    let res = common::get("http://127.0.0.1:21100/suffix").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-front-request-uri", "/suffix");
    assert_header!(res, "x-upstream-request-uri", "/prefix/suffix");
  })
}