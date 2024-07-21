use std::sync::{atomic::Ordering, Arc};

use super::level::AtomicLevelFilter;
use crate::log::{DisplayDate, DisplayLevel};

#[derive(Debug, Clone, Default)]
pub struct Logger {
  level: Arc<AtomicLevelFilter>,
}

impl Logger {
  pub fn new(level: Arc<AtomicLevelFilter>) -> Self {
    Self { level }
  }

  pub fn level(&self) -> &Arc<AtomicLevelFilter> {
    &self.level
  }
}

impl log::Log for Logger {
  fn enabled(&self, meta: &log::Metadata) -> bool {
    meta.level() <= self.level.load(Ordering::Relaxed)
  }

  fn log(&self, record: &log::Record) {
    if self.enabled(record.metadata()) {
      use owo_colors::OwoColorize;
      println!(
        "{} {} {} > {}",
        DisplayDate::now(),
        DisplayLevel(record.level()),
        record.target().bold(),
        record.args()
      );

      #[cfg(feature = "primary-log")]
      crate::log::primary_log!(
        "{} {} {} > {}",
        DisplayDate::now(),
        DisplayLevel(record.level()),
        record.target().bold(),
        record.args()
      )
    }
  }

  fn flush(&self) {}
}
