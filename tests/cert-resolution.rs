mod common;
use common::block_on;

// requests https://{domain}:{port}/ resolving the domain to 127.0.0.1,
// so the domain is sent as the SNI server name in the tls handshake
async fn get_with_sni(domain: &str, port: u16) -> Result<reqwest::Response, reqwest::Error> {
  reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .resolve(domain, format!("127.0.0.1:{port}").parse().unwrap())
    .build()
    .unwrap()
    .get(format!("https://{domain}:{port}/"))
    .send()
    .await
}

#[test]
fn cert_resolution_matched_sni() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    let res = get_with_sni("example.com", 24300).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-app", "named");
  });
}

#[test]
fn cert_resolution_unmatched_sni_is_rejected() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    let err = get_with_sni("unknown.com", 24300).await.unwrap_err();
    assert!(
      format!("{err:?}").contains("AccessDenied"),
      "expected an access denied tls alert, got: {err:?}"
    );
  });
}

#[test]
fn cert_resolution_no_sni_is_rejected() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    // an ip address host sends no SNI in the tls handshake
    let err = common::get("https://127.0.0.1:24300/").await.unwrap_err();
    assert!(
      format!("{err:?}").contains("AccessDenied"),
      "expected an access denied tls alert, got: {err:?}"
    );
  });
}

#[test]
fn cert_resolution_matched_sni_with_catch_all() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    let res = get_with_sni("example.com", 24301).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-app", "named");
  });
}

#[test]
fn cert_resolution_unmatched_sni_falls_back_to_catch_all() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    let res = get_with_sni("unknown.com", 24301).await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-app", "catch-all");
  });
}

#[test]
fn cert_resolution_no_sni_falls_back_to_catch_all() {
  crate::lock!("cert-resolution.yml");
  block_on(async move {
    let res = common::get("https://127.0.0.1:24301/").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-app", "catch-all");
  });
}
