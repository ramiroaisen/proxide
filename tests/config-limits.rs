mod common;

#[cfg(unix)]
#[test]
fn cmd_args() {
  use common::{block_on, get};
  use proxide::config::Config;

  lock!();
  use rlimit::Resource as R;

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

  let config_str = include_str!("config-limits.yml")
    .replace("NOFILE", &nofile)
    .replace("NPROC", &nproc)
    .replace("STACK", &stack)
    .replace("RSS", &rss)
    .replace("MEMLOCK", &memlock)
    .replace("CPU", &cpu)
    .replace("AS", &ras)
    .replace("CORE", &core)
    .replace("DATA", &data)
    .replace("FSIZE", &fsize);

  let config: Config = serde_yaml::from_str(&config_str).expect("error parsing yaml config file");

  launch!(@parsed config);

  block_on(async move {
    let res = get("http://127.0.0.1:23800").await.unwrap();
    assert_status!(res, OK);
    assert_header!(res, "x-test", "config-limits");
  });
}
