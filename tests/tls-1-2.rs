use reqwest::tls::Version;

mod common;

fn client(version: reqwest::tls::Version) -> reqwest::Client {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .min_tls_version(version)
    .max_tls_version(version)
    .build()
    .unwrap()
}

#[test]
fn tls_version_1_2() {
  lock!("tls-1-2.yml");
  common::block_on(async move {
    let res = client(Version::TLS_1_2)
      .get("https://127.0.0.1:23970")
      .send()
      .await
      .unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "tls-version");
  })
}
