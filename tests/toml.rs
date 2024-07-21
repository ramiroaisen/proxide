mod common;

use std::thread;
use clap::Parser;
use common::{block_on, get};

#[test]
fn toml() {
  let args = proxide::cli::args::Args::try_parse_from(
    vec![ "proxide", "start", "--config", "tests/toml.toml" ]
  ).unwrap();

  thread::spawn(move || {
    proxide::cli::run(args).unwrap();
  });

  thread::sleep(std::time::Duration::from_millis(100));

  block_on(async move {
    let res = get("http://127.0.0.1:24100").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "toml");
  });
}