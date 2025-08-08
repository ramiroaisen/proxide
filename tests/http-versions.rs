mod common;
use common::{block_on, request};

use http::{Method, Version};

#[test]
fn http_versions() {
  lock!("http-versions.yml");

  block_on(async move {
    let fronts = [
      // (Version::HTTP_10, "http"),
      // (Version::HTTP_11, "http"),
      // (Version::HTTP_2, "http"),
      // (Version::HTTP_10, "https"),
      // (Version::HTTP_11, "https"),
      (Version::HTTP_2, "https"),
      // (Version::HTTP_3, "https"),
    ];

    let upstreams = [
      // ("http", "1.0"),
      // ("http", "1.1"),
      // ("http", "2.0"),
      // ("https", "1.0"),
      // ("https", "1.1"),
      // ("https", "2.0"),
      ("https", "3.0"),
    ];

    for (front_version, front_scheme) in fronts {
      for (upstream_scheme, upstream_version) in upstreams {
        let port = match (front_scheme, front_version) {
          ("http", _) => 23000,
          ("https", Version::HTTP_3) => 23002,
          ("https", _) => 23001,
          _ => unreachable!(),
        };

        let uri = format!("{front_scheme}://127.0.0.1:{port}/{upstream_scheme}-{upstream_version}");
        log::info!("testing {front_version:?} {front_scheme} - {uri}");

        let mut req = reqwest::Request::new(Method::GET, uri.parse().unwrap());
        *req.version_mut() = front_version;

        let res = request(req).await.unwrap();

        assert_status!(res, 200);
        assert_header!(res, "x-scheme", front_scheme);
        assert_header!(res, "x-upstream-scheme", upstream_scheme);
        assert_header!(res, "x-upstream-version", upstream_version);
        assert_body!(
          res,
          format!("upstream-scheme: {upstream_scheme}\nupstream-version: {upstream_version}\n")
        );
      }
    }
  })
}
