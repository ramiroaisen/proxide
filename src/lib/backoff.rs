use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::serde::duration::SDuration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]  
#[serde(tag = "type")]
pub enum BackOff {
  #[serde(rename = "exponential")]
  Exponential {
    exponent_base: f64,
    delay_base: SDuration,
    delay_max: SDuration,
  },

  #[serde(rename = "constant")]
  Constant {
    delay: SDuration,
  }
}

impl BackOff {
  pub fn duration_for(self, i: usize) -> Duration {
    match self {
      BackOff::Exponential { exponent_base, delay_base, delay_max } => {
        let base = delay_base.as_secs_f64();
        let max = delay_max.as_secs_f64();
        let target = (exponent_base.powf(i as f64) * base).min(max);
        Duration::from_secs_f64(target)
      }

      BackOff::Constant { delay } => {
        *delay
      }
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn exponential_backoff() {

    let expo_cases: &[(f64, u64, u64, usize, u64)] = &[
      // exponent_base, base, max, i,  expected
      (1.5, 100, 2000, 0, 100),
      (1.5, 100, 2000, 1, 150),
      (1.5, 100, 2000, 2, 225),
      (1.5, 100, 2000, 3, 337),
      (1.5, 100, 2000, 4, 506),
      (1.5, 100, 2000, 100, 2000),
      (1.5, 100, 2000, 200, 2000),
      (1.5, 100, 2000, 300, 2000),

      (2.0, 1000, 5000, 0, 1000),
      (2.0, 1000, 5000, 1, 2000),
      (2.0, 1000, 5000, 2, 4000),
      (2.0, 1000, 5000, 3, 5000),
      (2.0, 1000, 5000, 4, 5000),
    ];

    for (exponent_base, delay_base_millis, delay_max_millis, i, expected) in expo_cases.iter().cloned() {
      let backoff = BackOff::Exponential {
        exponent_base,
        delay_base: Duration::from_millis(delay_base_millis).into(),
        delay_max: Duration::from_millis(delay_max_millis).into(),
      };

      let duration = backoff.duration_for(i);
      assert_eq!(duration.as_millis(), expected as u128);
    }
  }

  #[test]
  fn constant_backoff() {
    for millis in 0..100 {
      let backoff = BackOff::Constant { delay: Duration::from_millis(millis).into() };
      for i in 0..100 {
        let duration = backoff.duration_for(i);
        assert_eq!(duration.as_millis(), millis as u128);
      }
    }
  }
}