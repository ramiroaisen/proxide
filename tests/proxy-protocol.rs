mod common;
use common::{block_on, get, https_get};
use local_ip_address::local_ip;

#[test]
fn proxy_protocol() {
  crate::lock!("proxy-protocol.yml");
  block_on(async move {
    let local_ip = local_ip().expect("get local ip address");

    let cases = [
      format!("http://{local_ip}:22500/"), // tcp => tcp =>  http - v1 - v1
      format!("https://{local_ip}:22501/"), // ssl => tcp => http - v1 - v1
      format!("http://{local_ip}:22502/"), // tcp => ssl => http - v1 - v1
      format!("https://{local_ip}:22503/"), // ssl => ssl => http - v1 - v1
      format!("http://{local_ip}:22504/"), // tcp => tcp => http - v2 - v1
      format!("https://{local_ip}:22505/"), // ssl => tcp => http - v2 - v1
      format!("http://{local_ip}:22506/"), // tcp => ssl => http - v2 - v1
      format!("https://{local_ip}:22507/"), // ssl => ssl => http - v2 - v1
      format!("http://{local_ip}:22510/"), // tcp => tcp =>  http - v1 - v2
      format!("https://{local_ip}:22511/"), // ssl => tcp => http - v1 - v2
      format!("http://{local_ip}:22512/"), // tcp => ssl => http - v1 - v2
      format!("https://{local_ip}:22513"), // ssl => ssl => http - v1 - v2
      format!("http://{local_ip}:22514/"), // tcp => tcp => http - v2 - v2
      format!("https://{local_ip}:22515/"), // ssl => tcp => http - v2 - v2
      format!("http://{local_ip}:22516/"), // tcp => ssl => http - v2 - v2
      format!("https://{local_ip}:22517/"), // ssl => ssl => http - v2 - v2
      format!("http://{local_ip}:22530/v1/http"), // http => http - v1
      format!("http://{local_ip}:22530/v2/http"), // http => http - v2
      format!("http://{local_ip}:22530/v1/https"), // http => https - v1
      format!("http://{local_ip}:22530/v2/https"), // http => https - v2
      format!("https://{local_ip}:22531/v1/http"), // https => http - v1
      format!("https://{local_ip}:22531/v2/http"), // https => http - v2
      format!("https://{local_ip}:22531/v1/https"), // https => https - v1
      format!("https://{local_ip}:22531/v2/https"), // https => https - v2
    ];

    for case in cases {
      log::info!("case: {case}");

      macro_rules! assert_all {
        ($res:ident) => {{
          assert_status!($res, OK);
          assert_header!($res, "content-type", "text/plain");
          assert_header!($res, "x-test", "proxy-protocol");
          assert_header!($res, "x-remote-ip", &local_ip.to_string());
          assert_header!($res, "x-proxy-protocol-remote-ip", &local_ip.to_string());
          assert_header!($res, "x-connection-remote-ip", "127.0.0.1");
        }};
      }

      if case.starts_with("https:") {
        let res = https_get(&case).await.expect("error making request");
        assert_all!(res);
      } else {
        let res = get(&case).await.expect("error making request");
        assert_all!(res);
      };
    }
  })
}
