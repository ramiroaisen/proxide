mod common;

use clap::Parser;
use common::{block_on, dir};

#[cfg(unix)]
#[test]
fn signal() {
    use std::time::Duration;

    use tokio_util::time::FutureExt;

  lock!();
  let dir = dir();
  
  let pidfile = dir.file("pidfile.pid");
  let config_str = include_str!("cmd-signal.yml")
    .replace("%PIDFILE%", &pidfile);

  let config_file = dir.file("config.yml");
  std::fs::write(&config_file, config_str).expect("write config");

  std::fs::write(&pidfile, std::process::id().to_string()).expect("write pidfile");

  block_on(async move {
    let sigs = [
      ("reload", tokio::signal::unix::SignalKind::user_defined1()),
      ("graceful-shutdown", tokio::signal::unix::SignalKind::interrupt()),
      ("terminate", tokio::signal::unix::SignalKind::terminate()),
    ];

    for (name, sig) in sigs {
      let mut sig = tokio::signal::unix::signal(sig).expect("create signal");
      let recv = async {
        sig.recv().await.unwrap_or_else(|| panic!("receive signal for {}", name));
      };

      let send = async {
        let args = proxide::cli::args::Args::try_parse_from([
          "proxide",
          "signal",
          "--config",
          &config_file,
          "--signal",
          name,
        ]).unwrap_or_else(|e| panic!("parse args for {}: {e}: {e:?}", name));

        proxide::cli::run(args)
          .unwrap_or_else(|e| panic!("run proxide signal cmd for {}: {e}: {e:?}", name))
      };

      let task = async move {
        tokio::join!(send, recv);
      };

      task.timeout(Duration::from_millis(200))
        .await
        .expect("200ms timeout reached");
    }
  })
}
