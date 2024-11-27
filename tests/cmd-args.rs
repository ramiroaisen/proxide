mod common;
use clap::Parser;
use common::{block_on, get};

#[cfg(unix)]
#[test]
fn cmd_args() {
  use rlimit::Resource as R;

  lock!();

  // let nthr = rlimit::getrlimit(R::NTHR).unwrap().1.to_string();
  // let swap = rlimit::getrlimit(R::SWAP).unwrap().1.to_string();
  let nofile = rlimit::getrlimit(R::NOFILE).unwrap().1.to_string();
  let nproc = rlimit::getrlimit(R::NPROC).unwrap().1.to_string();
  let stack = rlimit::getrlimit(R::STACK).unwrap().1.to_string();
  let rss = rlimit::getrlimit(R::RSS).unwrap().1.to_string();
  let memlock = rlimit::getrlimit(R::MEMLOCK).unwrap().1.to_string();
  let cpu = rlimit::getrlimit(R::CPU).unwrap().1.to_string();
  let ras = rlimit::getrlimit(R::AS).unwrap().1.to_string();
  let core = rlimit::getrlimit(R::CORE).unwrap().1.to_string();
  let data = rlimit::getrlimit(R::DATA).unwrap().1.to_string();
  let fsize = rlimit::getrlimit(R::FSIZE).unwrap().1.to_string();

  let args = [
    "proxide",
    "start",
    // config
    "--config",
    "tests/cmd-args.yml",
    // log
    "--log",
    "debug",
    // graceful shutdown
    "--graceful-shutdown-timeout",
    "1s",
    "--http-graceful-shutdown-timeout",
    "2s",
    "--stream-graceful-shutdown-timeout",
    "1s",
    // rlimit
    // "--rlimit-nthr", &nthr,
    // "--rlimit-swap", &swap,
    "--rlimit-nofile",
    &nofile,
    "--rlimit-nproc",
    &nproc,
    "--rlimit-stack",
    &stack,
    "--rlimit-rss",
    &rss,
    "--rlimit-memlock",
    &memlock,
    "--rlimit-cpu",
    &cpu,
    "--rlimit-as",
    &ras,
    "--rlimit-core",
    &core,
    "--rlimit-data",
    &data,
    "--rlimit-fsize",
    &fsize,
    // runtime
    "--disable-lifo-slot",
    "--worker-threads",
    "2",
    "--max-blocking-threads",
    "32",
    "--thread-stack-size",
    "10000000",
    "--thread-keep-alive",
    "10s",
    "--thread-name",
    "runtime-args-test",
  ];

  let args = proxide::cli::args::Args::try_parse_from(args).unwrap();
  std::thread::spawn(move || {
    proxide::cli::run(args).unwrap();
  });

  std::thread::sleep(std::time::Duration::from_millis(200));

  block_on(async move {
    let res = get("http://127.0.0.1:23700").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "cmd-args");
  });
}

#[cfg(not(unix))]
#[test]
fn cmd_args() {
  lock!();

  let args = [
    "proxide",
    "start",
    // config
    "--config",
    "tests/cmd-args.yml",
    // log
    "--log",
    "debug",
    // graceful shutdown
    "--graceful-shutdown-timeout",
    "1s",
    "--http-graceful-shutdown-timeout",
    "2s",
    "--stream-graceful-shutdown-timeout",
    "1s",
    // runtime
    "--disable-lifo-slot",
    "--worker-threads",
    "2",
    "--max-blocking-threads",
    "32",
    "--thread-stack-size",
    "10000000",
    "--thread-keep-alive",
    "10s",
    "--thread-name",
    "runtime-args-test",
  ];

  let args: proxide::cli::args::Args = proxide::cli::args::Args::try_parse_from(args).unwrap();
  std::thread::spawn(move || {
    proxide::cli::run(args).unwrap();
  });

  std::thread::sleep(std::time::Duration::from_millis(200));

  block_on(async move {
    let res = get("http://127.0.0.1:23700").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "cmd-args");
  });
}
