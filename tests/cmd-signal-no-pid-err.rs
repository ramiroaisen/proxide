mod common;

use clap::Parser;
use common::dir;

#[cfg(unix)]
#[test]
fn signal() {
  lock!();

  let config_str = include_str!("cmd-signal-no-pid-err.yml");
  
  let dir = dir();
  let config_file = dir.file("config.yml");
  std::fs::write(&config_file, config_str).expect("write config");

  let args = proxide::cli::args::Args::try_parse_from([
    "proxide",
    "signal",
    "-c",
    &config_file,
    "-s",
    "reload"
  ]).expect("parse args");

  proxide::cli::run(args)
    .unwrap_err();
}
