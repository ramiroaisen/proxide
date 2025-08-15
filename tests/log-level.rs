mod common;

use common::{block_on, dir};
use log::Level;
use proxide::log::logfile::LogFileConfig;
use std::time::Duration;

use proxide::log::LevelFilter;

async fn log(config_level: LevelFilter, message_level: Level) -> bool {
  let dir = dir();

  let config = LogFileConfig {
    path: dir.file("log.log"),
    max_size_mb: None,
    retain: None,
  };

  proxide::log::init_or_update(config_level, Some(config), None, None);
  tokio::time::sleep(Duration::from_millis(20)).await;

  let rand: u64 = rand::random();
  let message = format!("log#{}#", rand);

  log::log!(message_level, "{}", message);
  tokio::time::sleep(Duration::from_millis(150)).await;

  let contents = std::fs::read_to_string(dir.file("log.log")).unwrap();
  contents.contains(&message)
}

#[test]
fn log_level() {
  launch!("log-level.yml");

  block_on(async move {
    use log::Level::*;

    let levels = [Error, Warn, Info, Debug, Trace];

    for (i, config_level) in levels.into_iter().enumerate() {
      for show in &levels[..i] {
        assert!(log(config_level.into(), *show).await);
      }

      for not_show in &levels[(i + 1)..] {
        assert!(!log(config_level.into(), *not_show).await);
      }

      let (message_level, config_level) = (config_level, LevelFilter::Off);
      assert!(!log(config_level, message_level).await);
    }
  })
}
