mod common;

use std::thread;
use clap::Parser;
use common::{block_on, dir, get};
use proxide::config::Config;

#[test]
fn start() {
  lock!();

  let args: proxide::cli::args::Args = proxide::cli::args::Args::try_parse_from(
    vec![ "proxide", "start", "--config", "tests/cmd.yml" ]
  ).unwrap();

  thread::spawn(move || {
    proxide::cli::run(args).unwrap();
  });

  thread::sleep(std::time::Duration::from_millis(100));

  block_on(async move {
    let res = get("http://127.0.0.1:20900").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "cmd");
  });
}

#[test]
fn create_config() {
  lock!();

  let dir = dir();

  let out = dir.file("config.yml");

  let args = proxide::cli::args::Args::try_parse_from(
    vec![
      "proxide",
      "create-config",
      "--output",
      &out,
    ]
  ).unwrap();

  proxide::cli::run(args).unwrap();

  let config = std::fs::read_to_string(&out).unwrap();
  let _config: Config = serde_yaml::from_str(&config).unwrap();

  let schema = std::fs::read_to_string(dir.file("config.schema.json")).unwrap();
  let _schema: serde_json::Value = serde_json::from_str(&schema).unwrap();
}


#[test]
fn create_config_not_override_existing_file() {
  lock!();

  let dir = dir();

  let out = dir.file("config.yml");
  let prev_contents = "no-override";
  std::fs::write(&out, prev_contents).expect("write prev contents");

  let args = proxide::cli::args::Args::try_parse_from(
    vec![
      "proxide",
      "create-config",
      "--output",
      &out,
    ]
  ).unwrap();

  proxide::cli::run(args).unwrap_err();

  let post_contents = std::fs::read_to_string(&out).unwrap();
  assert_eq!(post_contents, prev_contents);
}


#[test]
fn create_config_omit_schema() {
  lock!();
  let dir = dir();

  let out = dir.file("config.yml");
  
  let args = proxide::cli::args::Args::try_parse_from(
    vec![
      "proxide",
      "create-config",
      "--output",
      &out,
      "--omit-schema",
    ]
  ).unwrap();

  proxide::cli::run(args).unwrap();

  let config = std::fs::read_to_string(&out).unwrap();
  let _config: Config = serde_yaml::from_str(&config).unwrap();

  assert!(std::fs::metadata(dir.file("config.schema.json")).is_err()); 
}

#[test]
fn create_config_schema() {
  lock!();
  
  let dir = dir();

  let out = dir.file("config.schema.json");

  let args = proxide::cli::args::Args::try_parse_from(
    vec![
      "proxide",
      "create-config-schema",
      "--output",
      &out,
    ]
  ).unwrap();

  proxide::cli::run(args).unwrap();

  let schema = std::fs::read_to_string(&out).unwrap();
  let _schema: serde_json::Value = serde_json::from_str(&schema).unwrap();
}