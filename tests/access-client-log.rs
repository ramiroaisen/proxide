use std::time::Duration;

use common::{block_on, dir, get};
use proxide::config::Config;

mod common;

#[test]
fn access_client_log() {
  lock!();

  let dir = dir();

  let access_log = dir.file("access.log");
  let client_log = dir.file("client.log");

  let config_str = include_str!("access-client-log.yml")
    .replace("%ACCESS_LOG%", &access_log)
    .replace("%CLIENT_LOG%", &client_log);

  eprintln!("Config: {}", config_str);

  let config: Config = serde_yaml::from_str(&config_str).expect("error parsing yaml config file");

  launch!(@parsed config);
  
  block_on(async move {
    for _ in 0..100 {
      let res = get("http://127.0.0.1:21300/").await.unwrap();
      assert_status!(res, OK);
      assert_header!(res, "x-test", "logfiles");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let access_log = std::fs::read_to_string(&access_log).unwrap();
    let client_log = std::fs::read_to_string(&client_log).unwrap();

    assert_eq!(access_log.lines().count(), 200);
    assert_eq!(client_log.lines().count(), 100);

    drop(dir);
  })
}