use std::num::NonZeroUsize;

use crate::{config::RLimit, log::LevelFilter, serde::duration::SDuration};
use clap::{Args as ClapArgs, Parser};

#[derive(Debug, Clone, Parser)]
#[command(
  author,
  version,
  about = "proxide: next generation, pure Rust proxy server"
)]
pub struct Args {
  #[command(subcommand)]
  pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Parser)]
pub enum Command {
  Start(Start),
  CreateConfig(CreateConfig),
  CreateConfigSchema(CreateConfigSchema),
  #[cfg(unix)]
  Signal(Signal),
}

// impl From<Start> for Command {
//   fn from(start: Start) -> Self {
//     Self::Start(start)
//   }
// }

// impl From<CreateConfig> for Command {
//   fn from(create_config: CreateConfig) -> Self {
//     Self::CreateConfig(create_config)
//   }
// }

// impl From<CreateConfigSchema> for Command {
//   fn from(create_config_schema: CreateConfigSchema) -> Self {
//     Self::CreateConfigSchema(create_config_schema)
//   }
// }

// #[cfg(unix)]
// impl From<Signal> for Command {
//   fn from(signal: Signal) -> Self {
//     Self::Signal(signal)
//   }
// }

#[derive(Debug, Clone, Parser)]
pub struct Start {
  // path to the configuration file, relative to cwd.
  #[arg(
    short = 'c',
    long = "config",
    default_value = "config.yml",
    env = "PROXIDE_CONFIG"
  )]
  pub config: String,

  // sets the current working directory of the process at startup
  #[arg(long, env = "PROXIDE_CHDIR")]
  pub chdir: Option<String>,

  // log level, error, warn, info (default),  debug or trace. This will take precedence over the config file log level.
  #[arg(short = 'l', long = "log", env = "PROXIDE_LOG")]
  pub log_level: Option<LevelFilter>,

  #[arg(long, env = "PROXIDE_GRACEFUL_SHUTDOWN_TIMEOUT")]
  pub graceful_shutdown_timeout: Option<SDuration>,

  #[command(flatten)]
  pub rlimit: RLimit,

  #[command(flatten)]
  pub runtime: StartRuntime,

  #[command(flatten)]
  pub http: Http,

  #[command(flatten)]
  pub stream: Stream,
}

impl Default for Start {
  fn default() -> Self {
    Self {
      config: String::from("config.yml"),
      chdir: None,
      log_level: None,
      graceful_shutdown_timeout: None,
      rlimit: RLimit::default(),
      runtime: StartRuntime::default(),
      http: Http::default(),
      stream: Stream::default(),
    }
  }
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Http {
  #[arg(long, env = "PROXIDE_HTTP_GRACEFUL_SHUTDOWN_TIMEOUT")]
  pub http_graceful_shutdown_timeout: Option<SDuration>,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Stream {
  #[arg(long, env = "PROXIDE_STREAM_GRACEFUL_SHUTDOWN_TIMEOUT")]
  pub stream_graceful_shutdown_timeout: Option<SDuration>,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct StartRuntime {
  // disable the LIFO slot for the runtime
  #[arg(long, env = "PROXIDE_DISABLE_LIFO_SLOT")]
  pub disable_lifo_slot: bool,

  // number of threads to use for the tokio runtime. Default is the number of logical CPUs.
  #[arg(short = 't', long = "worker-threads", env = "PROXIDE_WORKER_THREADS")]
  pub threads: Option<NonZeroUsize>,

  // maximum number of blocking threads to use for the tokio runtime. A safe default is used if not specified.
  #[arg(long, env = "PROXIDE_MAX_BLOCKING_THREADS")]
  pub max_blocking_threads: Option<NonZeroUsize>,

  // thread stack size for worker and blocking threads. A safe default is used if not specified.
  #[arg(long, env = "PROXIDE_THREAD_STACK_SIZE")]
  pub thread_stack_size: Option<NonZeroUsize>,

  // seconds to keep alive a worker thread after it has finished its task. A safe default is used if not specified.
  #[arg(long, env = "PROXIDE_THREAD_KEEP_ALIVE_SECS")]
  pub thread_keep_alive: Option<SDuration>,

  // A name for newly created threads. See [tokio::runtime::Builder::thread_name].
  #[arg(long, env = "PROXIDE_THREAD_NAME")]
  pub thread_name: Option<String>,
}

impl StartRuntime {
  pub fn apply(&self, runtime: &mut tokio::runtime::Builder) {
    if self.disable_lifo_slot {
      runtime.disable_lifo_slot();
    }

    if let Some(threads) = self.threads {
      runtime.worker_threads(threads.get());
    }

    if let Some(max_blocking_threads) = self.max_blocking_threads {
      runtime.max_blocking_threads(max_blocking_threads.get());
    }

    if let Some(thread_stack_size) = self.thread_stack_size {
      runtime.thread_stack_size(thread_stack_size.get());
    }

    if let Some(secs) = self.thread_keep_alive {
      runtime.thread_keep_alive(*secs);
    }

    if let Some(name) = &self.thread_name {
      runtime.thread_name(name);
    }
  }
}

/// Creates a default config file in YAML format at specified --output.
#[derive(Debug, Clone, Parser)]
pub struct CreateConfig {
  /// Path to place the output config file.
  #[arg(short, long, default_value = "config.yml")]
  pub output: String,
  /// Specifing true will skip the JSON schema file output.
  #[arg(long, default_value = "false")]
  pub omit_schema: bool,
}

/// Creates a JSON schema file for the proxide configuration at specified --output.
#[derive(Debug, Clone, Parser)]
pub struct CreateConfigSchema {
  /// Path to place the output config schema file.
  #[arg(short, long, default_value = "config.schema.json")]
  pub output: String,
}

/// Send a signal to the current proxide process.
/// The current process pid is read from the pidfile entry of the --config file
#[cfg(unix)]
#[derive(Debug, Clone, Parser)]
pub struct Signal {
  // path to the configuration file, relative to cwd.
  #[arg(
    short = 'c',
    long = "config",
    default_value = "config.yml",
    env = "PROXIDE_CONFIG"
  )]
  pub config: String,

  #[arg(long, env = "PROXIDE_CHDIR")]
  pub chdir: Option<String>,

  /// Signal to send to the proxide process
  #[arg(short, long, env = "PROXIDE_SIGNAL")]
  pub signal: SignalKind,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SignalKind {
  Reload,
  Terminate,
  GracefulShutdown,
}
