use anyhow::Context;

use crate::cli::args::{Signal, SignalKind};

pub fn signal(args: Signal) -> Result<(), anyhow::Error> {
  let Signal {
    config,
    signal,
    chdir,
  } = args;

  if let Some(chdir) = &chdir {
    std::env::set_current_dir(chdir)
      .with_context(|| format!("error setting current working directory to {}", chdir))?;
  }

  let config = crate::config::load(&config)?;

  let pidfile = match config.pidfile {
    Some(pidfile) => pidfile,
    None => {
      anyhow::bail!("no pidfile specified in config file");
    }
  };

  let pid = std::fs::read_to_string(&pidfile)
    .with_context(|| format!("error reading pidfile at {}", pidfile))?;

  let pid = pid
    .trim()
    .parse::<i32>()
    .with_context(|| format!("error parsing pidfile at {}", pidfile))?;

  let unix_signal = match signal {
    SignalKind::Reload => nix::sys::signal::Signal::SIGUSR1,
    SignalKind::Terminate => nix::sys::signal::Signal::SIGTERM,
    SignalKind::GracefulShutdown => nix::sys::signal::Signal::SIGINT,
  };

  nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), unix_signal)
    .with_context(|| format!("error sending signal to pid {}", pid))?;

  Ok(())
}
