use std::fmt::Display;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LevelFilter {
  Off = 0,
  Error,
  Warn,
  #[default]
  Info,
  Debug,
  Trace,
}

impl From<log::Level> for LevelFilter {
  fn from(level: log::Level) -> Self {
    match level {
      log::Level::Error => LevelFilter::Error,
      log::Level::Warn => LevelFilter::Warn,
      log::Level::Info => LevelFilter::Info,
      log::Level::Debug => LevelFilter::Debug,
      log::Level::Trace => LevelFilter::Trace,
    }
  }
}

impl LevelFilter {
  pub fn as_str(&self) -> &'static str {
    match self {
      LevelFilter::Off => "off",
      LevelFilter::Error => "error",
      LevelFilter::Warn => "warn",
      LevelFilter::Info => "info",
      LevelFilter::Debug => "debug",
      LevelFilter::Trace => "trace",
    }
  }
}

impl Display for LevelFilter {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

impl<'de> Deserialize<'de> for LevelFilter {
  fn deserialize<D>(de: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(de)?;
    match s.to_ascii_lowercase().as_str() {
      "off" => Ok(LevelFilter::Off),
      "error" => Ok(LevelFilter::Error),
      "warn" => Ok(LevelFilter::Warn),
      "info" => Ok(LevelFilter::Info),
      "debug" => Ok(LevelFilter::Debug),
      "trace" => Ok(LevelFilter::Trace),
      _ => Err(serde::de::Error::custom(format!(
        "invalid log level: {s}, expected one of off, error, warn, info, debug or trace"
      ))),
    }
  }
}

impl From<LevelFilter> for log::LevelFilter {
  fn from(level: LevelFilter) -> Self {
    match level {
      LevelFilter::Off => log::LevelFilter::Off,
      LevelFilter::Error => log::LevelFilter::Error,
      LevelFilter::Warn => log::LevelFilter::Warn,
      LevelFilter::Info => log::LevelFilter::Info,
      LevelFilter::Debug => log::LevelFilter::Debug,
      LevelFilter::Trace => log::LevelFilter::Trace,
    }
  }
}

impl From<LevelFilter> for AtomicLevelFilter {
  fn from(level: LevelFilter) -> Self {
    Self::new(level.into())
  }
}

#[derive(Debug, Serialize)]
pub struct AtomicLevelFilter {
  inner: AtomicU8,
}

impl AtomicLevelFilter {
  pub const fn new(level: log::LevelFilter) -> Self {
    Self {
      inner: AtomicU8::new(to_u8(level)),
    }
  }

  pub fn load(&self, ordering: Ordering) -> log::LevelFilter {
    from_u8(self.inner.load(ordering))
  }

  pub fn store(&self, level: log::LevelFilter, ordering: Ordering) {
    self.inner.store(to_u8(level), ordering)
  }

  pub fn swap(&self, new: log::LevelFilter, ordering: Ordering) -> log::LevelFilter {
    from_u8(self.inner.swap(to_u8(new), ordering))
  }

  pub fn compare_exchange(
    &self,
    current: log::LevelFilter,
    new: log::LevelFilter,
    success: Ordering,
    failure: Ordering,
  ) -> Result<log::LevelFilter, log::LevelFilter> {
    match self
      .inner
      .compare_exchange(to_u8(current), to_u8(new), success, failure)
    {
      Ok(v) => Ok(from_u8(v)),
      Err(v) => Err(from_u8(v)),
    }
  }
}

impl Default for AtomicLevelFilter {
  fn default() -> Self {
    Self::new(log::LevelFilter::Info)
  }
}

const fn to_u8(level: log::LevelFilter) -> u8 {
  level as u8
}

const fn from_u8(level: u8) -> log::LevelFilter {
  match level {
    0 => log::LevelFilter::Off,
    1 => log::LevelFilter::Error,
    2 => log::LevelFilter::Warn,
    3 => log::LevelFilter::Info,
    4 => log::LevelFilter::Debug,
    5 => log::LevelFilter::Trace,
    _ => unreachable!(),
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::sync::atomic::Ordering;

  #[test]
  fn atomic_exchange() {
    let atomic = AtomicLevelFilter::new(log::LevelFilter::Off);
    let levels = [
      (log::LevelFilter::Off, log::LevelFilter::Error),
      (log::LevelFilter::Error, log::LevelFilter::Warn),
      (log::LevelFilter::Warn, log::LevelFilter::Info),
      (log::LevelFilter::Info, log::LevelFilter::Debug),
      (log::LevelFilter::Debug, log::LevelFilter::Trace),
    ];

    for (current, new) in levels {
      let prev = atomic
        .compare_exchange(current, new, Ordering::Relaxed, Ordering::Relaxed)
        .unwrap();

      assert_eq!(prev, current);
    }

    let fail = atomic
      .compare_exchange(
        log::LevelFilter::Off,
        log::LevelFilter::Error,
        Ordering::Relaxed,
        Ordering::Relaxed,
      )
      .unwrap_err();

    assert_eq!(fail, log::LevelFilter::Trace);
  }

  #[test]
  fn atomic_load_store() {
    let atomic = AtomicLevelFilter::new(log::LevelFilter::Off);
    let levels = [
      log::LevelFilter::Off,
      log::LevelFilter::Error,
      log::LevelFilter::Warn,
      log::LevelFilter::Info,
      log::LevelFilter::Debug,
      log::LevelFilter::Trace,
    ];

    for level in levels {
      atomic.store(level, Ordering::Relaxed);
      assert_eq!(atomic.load(Ordering::Relaxed), level);
    }
  }

  #[test]
  fn atomic_swap() {
    let atomic = AtomicLevelFilter::new(log::LevelFilter::Off);
    let levels = [
      log::LevelFilter::Off,
      log::LevelFilter::Error,
      log::LevelFilter::Warn,
      log::LevelFilter::Info,
      log::LevelFilter::Debug,
      log::LevelFilter::Trace,
    ];

    for level in levels {
      atomic.store(level, Ordering::Relaxed);
      assert_eq!(atomic.swap(level, Ordering::Relaxed), level);
    }
  }
}
