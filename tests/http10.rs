use common::{block_on, https_request};

mod common;

#[test]
fn http10() {
  lock!("http10.yml");

  block_on(async move {

    for front_scheme in ["http", "https"] {
      for upstream_scheme in ["http", "https"] {
        let port = if front_scheme == "http" { 23010 } else { 23011 }; 
        let url = format!("{front_scheme}://127.0.0.1:{port}/upstream-{upstream_scheme}");
        let mut request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
        *request.version_mut() = hyper::Version::HTTP_11; 
        let res = https_request(request).await.unwrap();
        assert_status!(res, 200, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
        assert_header!(res, "x-scheme", front_scheme, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
        assert_header!(res, "x-upstream-scheme", upstream_scheme, "fail for upstream scheme {upstream_scheme} and front scheme {front_scheme}");
        assert_header!(res, "x-version", "1.1");
        assert_header!(res, "x-upstream-version", "1.0");
      }
    }
  })
}