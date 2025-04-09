mod common;

#[test]
fn stream() {
  lock!("stream.yml");
  common::block_on(async move {
    for front_scheme in ["http", "https"] {
      for upstream_scheme in ["http", "https"] {
        let port = match (front_scheme, upstream_scheme) {
          ("http", "http") => 21200,
          ("http", "https") => 21201,
          ("https", "http") => 21202,
          ("https", "https") => 21203,
          _ => unreachable!(),
        };

        let client = reqwest::Client::builder()
          .danger_accept_invalid_certs(true)
          .build()
          .unwrap();

        for _ in 0..1000 {
          let res = client
            .get(format!("{front_scheme}://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap();

          assert_status!(res, OK);
          assert_header!(res, "x-scheme", upstream_scheme);
        }
      }
    }
  })
}
