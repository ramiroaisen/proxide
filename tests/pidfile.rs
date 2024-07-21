use common::dir;
use proxide::config::Config;

mod common;

#[test]
fn pidfile_new() {
  lock!();

  let dir = dir();
  let pidfile = dir.file("pidfile-new.pid");
  let config_str = include_str!("pidfile.yml")
    .replace("%PIDFILE%", &pidfile);

  let config: Config = serde_yaml::from_str(&config_str).expect("error parsing yaml config file");

  launch!(@parsed config);
  
  let target = std::fs::read_to_string(&pidfile).expect("read pidfile");

  assert_eq!(target, std::process::id().to_string());
}

#[test]
fn pidfile_existing() {
  lock!();
  let dir = dir();
  let pidfile = dir.file("pidfile-existing.pid");
  let config_str = include_str!("pidfile.yml")
    .replace("%PIDFILE%", &pidfile);
  
  std::fs::write(&pidfile, "1234").expect("write pidfile");
  let config: Config = serde_yaml::from_str(&config_str).expect("error parsing yaml config file");
  
  launch!(@parsed config);

  let target = std::fs::read_to_string(&pidfile).expect("read pidfile");
  assert_eq!(target, std::process::id().to_string());
}