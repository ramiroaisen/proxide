use serde::{Deserialize, Serialize, Serializer};
use std::{fmt::Display, str::FromStr, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SDuration(pub Duration);

crate::newtype!(SDuration => Duration);
crate::json_schema_as!(SDuration => String);

impl Serialize for SDuration {
  fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
    self.to_string().serialize(ser)
  }
}

impl<'de> Deserialize<'de> for SDuration {
  fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
    let s = String::deserialize(de)?;
    Self::from_str(&s).map_err(serde::de::Error::custom)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
  "invalid duration, duration is expected to have a number followed by a unit (ms, s, m, h, d)"
)]
pub struct InvalidDurationError;

impl FromStr for SDuration {
  type Err = InvalidDurationError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // zero can have or not have a unit
    #[allow(non_upper_case_globals)]
    let zero = regex_static::static_regex!(r"^0(ms|s|m|h|d)?$");
    if zero.is_match(s) {
      return Ok(Self(Duration::ZERO));
    }

    // seconds are allowed to have a decimal point for milliseconds
    #[allow(non_upper_case_globals)]
    let secs = regex_static::static_regex!(r"^([0-9]+(?:\.[0-9]+)?)s$");
    if let Some(secs) = secs.captures(s) {
      let secs = secs.get(1).unwrap().as_str().parse::<f64>().unwrap();
      return Ok(Self(Duration::from_secs_f64(secs)));
    }

    // all other units can only have a integer followed by a unit (millis, seconds minutes, hours, days)
    #[allow(non_upper_case_globals)]
    let unit = regex_static::static_regex!(r"^([0-9]+)(ms|m|h|d)$");
    if let Some(unit) = unit.captures(s) {
      let n = unit.get(1).unwrap().as_str().parse::<u64>().unwrap();
      let unit = unit.get(2).unwrap().as_str();

      const MINUTE: u64 = 60;
      const HOUR: u64 = 60 * MINUTE;
      const DAY: u64 = 24 * HOUR;

      let inner = match unit {
        "ms" => Duration::from_millis(n),
        "m" => Duration::from_secs(n.saturating_mul(MINUTE)),
        "h" => Duration::from_secs(n.saturating_mul(HOUR)),
        "d" => Duration::from_secs(n.saturating_mul(DAY)),
        _ => unreachable!(),
      };

      return Ok(Self(inner));
    }

    Err(InvalidDurationError)
  }
}

impl Display for SDuration {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let secs = self.as_secs();
    let millis = self.subsec_millis();

    // 0 has no unit
    if millis == 0 && secs == 0 {
      write!(f, "0")
    // if less than a second only millis is displayed
    } else if secs == 0 {
      write!(f, "{}ms", millis)
    // if millis in not 0 we display all as seconds with fractional millis
    } else if millis != 0 {
      write!(f, "{}s", secs as f64 + millis as f64 / 1000.0)
    } else {
      const MINUTE: u64 = 60;
      const HOUR: u64 = 60 * MINUTE;
      const DAY: u64 = 24 * HOUR;

      // hole days
      if secs % DAY == 0 {
        write!(f, "{}d", secs / DAY)
      // hole hours
      } else if secs % HOUR == 0 {
        write!(f, "{}h", secs / HOUR)
      // hole minutes
      } else if secs % MINUTE == 0 {
        write!(f, "{}m", secs / MINUTE)
      // otherwise seconds
      } else {
        write!(f, "{}s", secs)
      }
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn parse_zero() {
    let tests = ["0", "0ms", "0s", "0.00s", "0m", "0h", "0d"];

    for test in tests {
      let dur = SDuration::from_str(test).unwrap();
      assert_eq!(*dur, Duration::ZERO);
    }
  }

  #[test]
  fn parse_secs_with_fraction() {
    let secs = [0.0, 0.1, 0.5, 1.7, 2.5, 150.5, 3566.4];

    for sec in secs {
      let parsed = SDuration::from_str(&format!("{}s", sec)).unwrap();
      assert_eq!(*parsed, Duration::from_secs_f64(sec));
    }
  }

  #[test]
  fn parse_with_unit() {
    let tests = [
      ("1ms", Duration::from_millis(1)),
      ("2s", Duration::from_secs(2)),
      ("3m", Duration::from_secs(3 * 60)),
      ("4h", Duration::from_secs(4 * 60 * 60)),
      ("5d", Duration::from_secs(5 * 24 * 60 * 60)),
    ];

    for (test, expected) in tests {
      let dur = SDuration::from_str(test).unwrap();
      assert_eq!(*dur, expected);
    }
  }

  #[test]
  fn stringify_zero() {
    assert_eq!(SDuration(Duration::ZERO).to_string(), "0");
  }

  #[test]
  fn stringify_secs_with_fraction() {
    let secs = [1.1, 1.5, 314.2, 354587.2];

    for sec in secs {
      let dur = SDuration(Duration::from_secs_f64(sec));
      assert_eq!(dur.to_string(), format!("{}s", sec));
    }
  }

  #[test]
  fn stringify_with_unit() {
    let tests = [
      (Duration::from_millis(1), "1ms"),
      (Duration::from_secs(2), "2s"),
      (Duration::from_secs(3 * 60), "3m"),
      (Duration::from_secs(4 * 60 * 60), "4h"),
      (Duration::from_secs(5 * 60 * 60 * 24), "5d"),
    ];

    for (dur, expected) in tests {
      assert_eq!(SDuration(dur).to_string(), expected);
    }
  }
}
