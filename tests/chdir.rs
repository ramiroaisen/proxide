mod common;
use common::dir;
use common::{block_on, get};

#[cfg(unix)]
#[test]
fn chdir() {
  use std::{thread, time::Duration};

  use clap::Parser;

  let dir = dir();
  let file = dir.file("config.yml");

  let config_str = include_str!("chdir.yml");
  std::fs::write(file, config_str).expect("write config");

  let args = [
    "proxide",
    "start",
    // config
    "--chdir",
    &dir,
    "--config",
    "config.yml",
  ];

  let args: proxide::cli::args::Args = proxide::cli::args::Args::try_parse_from(args).unwrap();
  std::thread::spawn(move || {
    proxide::cli::run(args).unwrap();
  });

  thread::sleep(Duration::from_millis(100));

  let signal_args = proxide::cli::args::Args::try_parse_from([
    "proxide",
    "signal",
    "--config",
    "config.yml",
    "--signal",
    "reload",
  ])
  .unwrap();

  proxide::cli::run(signal_args).unwrap();

  std::thread::sleep(std::time::Duration::from_millis(50));

  block_on(async move {
    let res = get("http://127.0.0.1:10100").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "chdir");
  });
}
