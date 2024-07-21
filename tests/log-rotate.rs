use std::time::Duration;

use common::{block_on, dir};
use proxide::config::Config;
mod common;

#[test]
fn rotate() {
  lock!();

  let dir = dir();
  
  let primary_log = dir.file("primary.log");

  let config_str = include_str!("log-rotate.yml")
    .replace("%PRIMARY_LOG%", &primary_log);

  let config: Config = serde_yaml::from_str(&config_str).expect("error parsing yaml config file");

  launch!(@parsed config);

  block_on(async move {

    log::info!("starting test");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let count = std::fs::read_dir(&*dir).unwrap().count();
    assert_eq!(count, 1);

    let kb_str = String::from_utf8(vec![b'a'; 1000]).unwrap();

    for n in 2..6 {
      
      for _ in 0..1100 {
        log::info!("{}", kb_str);
      }

      tokio::time::sleep(Duration::from_millis(1000)).await;
      let count = std::fs::read_dir(&*dir).unwrap().count();
      assert_eq!(count, usize::min(n, 4));
    }
  })
}