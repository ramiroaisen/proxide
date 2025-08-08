mod display;
mod level;
pub mod logfile;
pub mod logger;
pub use display::{
  DisplayDate, DisplayDuration, DisplayHeader, DisplayLevel, DisplayOption, DisplayPort,
};
pub use level::{AtomicLevelFilter, LevelFilter};

use logfile::LogFileConfig;
use logger::Logger;

use crate::once;

use static_init::dynamic;
use std::sync::{atomic::Ordering, Arc};

#[cfg(feature = "access-log")]
pub static ACCESS_LOG_ENABLED: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "client-log")]
pub static CLIENT_LOG_ENABLED: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "primary-log")]
pub static PRIMARY_LOG_ENABLED: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

#[dynamic]
static GLOBAL_LOG_LEVEL: Arc<AtomicLevelFilter> =
  Arc::new(AtomicLevelFilter::new(log::LevelFilter::Info));

pub fn init_or_update(
  log_level: LevelFilter,
  primary_log_config: Option<LogFileConfig>,
  access_log_config: Option<LogFileConfig>,
  client_log_config: Option<LogFileConfig>,
) {
  log::info!("init_or_update called for log level {log_level}, primary_log: {primary_log_config:?}, access_log: {access_log_config:?}, client_log: {client_log_config:?}");

  #[cfg(feature = "access-log")]
  {
    let enabled = access_log_config.is_some();
    ACCESS_LOG_ENABLED.store(enabled, Ordering::Relaxed);
    if let Some(access_log_config) = access_log_config {
      logfile::ACCESS_LOG.start_or_config(access_log_config);
    }
  };

  #[cfg(feature = "client-log")]
  {
    let enabled = client_log_config.is_some();
    CLIENT_LOG_ENABLED.store(enabled, Ordering::Relaxed);
    if let Some(client_log_config) = client_log_config {
      logfile::CLIENT_LOG.start_or_config(client_log_config);
    }
  };

  #[cfg(feature = "primary-log")]
  {
    let enabled = primary_log_config.is_some();
    PRIMARY_LOG_ENABLED.store(enabled, Ordering::Relaxed);
    if let Some(primary_log_config) = primary_log_config {
      logfile::PRIMARY_LOG.start_or_config(primary_log_config);
    }
  }

  let level_filter = log_level.into();

  GLOBAL_LOG_LEVEL.store(level_filter, Ordering::Relaxed);
  log::set_max_level(level_filter);

  if once!() {
    use tracing_subscriber::prelude::*;
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
      .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
      .unwrap();

    let fmt_layer = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
      .with(filter_layer)
      .with(fmt_layer)
      .init();

    // log::set_boxed_logger(Box::new(Logger::new(GLOBAL_LOG_LEVEL.clone()))).expect("failed to set logger");
  }
}

#[allow(unused)]
#[cfg(feature = "access-log")]
macro_rules! access_log {
  ($($tt:tt)*) => {
    if $crate::log::access_log_enabled!() {
      $crate::log::logfile::ACCESS_LOG.log(
        format!("{} - {}\n", $crate::log::DisplayDate::now(), format_args!($($tt)*))
      );
    }
  }
}

#[allow(unused)]
#[cfg(feature = "access-log")]
macro_rules! access_log_enabled {
  () => {
    $crate::log::ACCESS_LOG_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
  };
}

#[allow(unused)]
#[cfg(not(feature = "access-log"))]
macro_rules! access_log {
  ($($tt:tt)*) => {};
}

#[cfg(not(feature = "access-log"))]
#[allow(unused)]
macro_rules! access_log_enabled {
  () => {
    false
  };
}

#[allow(unused)]
#[cfg(feature = "client-log")]
macro_rules! client_log {
  ($($tt:tt)*) => {{
    if $crate::log::client_log_enabled!() {
      $crate::log::logfile::CLIENT_LOG.log(
        format!("{} - {}\n", $crate::log::DisplayDate::now(), format_args!($($tt)*))
      );
    }
  }}
}

#[allow(unused)]
#[cfg(feature = "client-log")]
macro_rules! client_log_enabled {
  () => {
    $crate::log::CLIENT_LOG_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
  };
}

#[allow(unused)]
#[cfg(not(feature = "client-log"))]
macro_rules! client_log_enabled {
  () => {
    false
  };
}

#[allow(unused)]
#[cfg(not(feature = "client-log"))]
macro_rules! client_log {
  ($($tt:tt)*) => {};
}

#[allow(unused)]
#[cfg(feature = "primary-log")]
macro_rules! primary_log {
  ($($tt:tt)*) => {
    if $crate::log::primary_log_enabled!() {
      $crate::log::logfile::PRIMARY_LOG.log(
        format!($($tt)*)
      );
    }
  }
}

#[allow(unused)]
#[cfg(feature = "primary-log")]
macro_rules! primary_log_enabled {
  () => {
    $crate::log::PRIMARY_LOG_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
  };
}

#[allow(unused)]
#[cfg(not(feature = "primary-log"))]
macro_rules! primary_log_enabled {
  () => {
    false
  };
}

#[allow(unused)]
#[cfg(not(feature = "primary-log"))]
macro_rules! primary_log {
  ($($tt:tt)*) => {};
}

#[allow(unused)]
pub(crate) use access_log;
#[allow(unused)]
pub(crate) use access_log_enabled;
#[allow(unused)]
pub(crate) use client_log;
#[allow(unused)]
pub(crate) use client_log_enabled;
#[allow(unused)]
pub(crate) use primary_log;
#[allow(unused)]
pub(crate) use primary_log_enabled;
