use common::{https_get, block_on};

mod common;

#[test]
fn https() {
  lock!("https.yml");

  block_on(async move {

    for front_scheme in ["http", "https"] {
      for upstream_scheme in ["http", "https"] {
        let port = if front_scheme == "http" { 20800 } else { 20801 };
        let res = https_get(&format!("{front_scheme}://127.0.0.1:{port}/upstream-{upstream_scheme}")).await.unwrap();
        assert_status!(res, 200, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
        assert_header!(res, "x-scheme", front_scheme, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
        assert_header!(res, "x-upstream-scheme", upstream_scheme, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
      }
    }
  })
}