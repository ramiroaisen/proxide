pub struct DisplayDate(time::OffsetDateTime);
use std::{fmt::Display, time::Duration};
use hyper::header::HeaderValue;
use time::{OffsetDateTime, UtcOffset};

#[static_init::dynamic]
static UTC_OFFSET: UtcOffset = {
  let secs = chrono::Local::now()
    .offset()
    .local_minus_utc();

  match UtcOffset::from_whole_seconds(secs) {
    Ok(offset) => offset,
    Err(_) => UtcOffset::UTC,
  }
};

impl DisplayDate {
  #[inline(always)]
  pub fn now() -> Self {
    Self::new(OffsetDateTime::now_utc().to_offset(*UTC_OFFSET))
  }

  #[inline(always)]
  pub fn new(date: OffsetDateTime) -> Self {
    Self(date)
  }
}


impl Display for DisplayDate {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let now = self.0;
    let (h, m, _) = now.offset().as_hms();
    let sign = if now.offset().is_negative() { "-" } else { "+" };
    write!(f, "{}-{:0>2}-{:0>2}T{:0>2}:{:0>2}:{:0>2}.{:0>3}{}{:0>2}:{:0>2}", 
      now.year(),
      now.month() as u8,
      now.day(),
      now.hour(),
      now.minute(),
      now.second(),
      now.millisecond(),
      sign,
      h.abs(),
      m.abs()
    )
  }
}



pub struct DisplayPort(pub Option<u16>);
impl Display for DisplayPort{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.0 {
      None => Ok(()),
      Some(port) => write!(f, ":{}", port),
    }
  }
}

pub struct DisplayHeader<'a>(pub Option<&'a HeaderValue>);
impl Display for DisplayHeader<'_> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.0 {
      None => Ok(()),
      // this will almost never allocate a string
      // it will only check that the header is utf-8 and return a Cow<str>
      Some(header) => String::from_utf8_lossy(header.as_bytes()).fmt(f),
    }
  }
}

pub struct DisplayOption<'a, T: Display>(pub Option<&'a T>);
impl<T: Display> Display for DisplayOption<'_, T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self.0 {
      None => Ok(()),
      Some(value) => value.fmt(f),
    }
  }
}

pub struct DisplayLevel(pub log::Level);
impl Display for DisplayLevel {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    use owo_colors::OwoColorize;
    match self.0 {
      log::Level::Error => "ERROR".red().fmt(f),
      log::Level::Warn =>  "WARN ".yellow().fmt(f),
      log::Level::Info =>  "INFO ".green().fmt(f),
      log::Level::Debug => "DEBUG".blue().fmt(f),
      log::Level::Trace => "TRACE".magenta().fmt(f),
    }
  }
}


pub struct DisplayDuration(pub Duration);

impl<D: Into<Duration>> From<D> for DisplayDuration {
  fn from(duration: D) -> Self {
    Self(duration.into())
  }
}

impl Display for DisplayDuration {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let millis = self.0.as_millis() as u64;
    
    const SEC: u64 = 1000;
    const MIN: u64 = 60 * SEC;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;

    let d = millis / DAY;
    let h = (millis % DAY) / HOUR;
    let m = (millis % HOUR) / MIN;
    let s = (millis % MIN) / SEC;
    let ms = millis % SEC;

    if d > 0 {
      if h != 0 {
        if m != 0 {
          write!(f, "{}d {}h {}m", d, h, m)
        } else {
          write!(f, "{}d {}h", d, h)
        }
      } else if m != 0 {
        write!(f, "{}d 0h {}m", d, m)
      } else {
        write!(f, "{}d", d)
      }
    } else if h > 0 {
      if m != 0 {
        write!(f, "{}h {}m", h, m)
      } else {
        write!(f, "{}h", h)
      }
    } else if m > 0 {
      if s != 0 {
        write!(f, "{}m {}s", m, s)
      } else {
        write!(f, "{}m", m)
      }
    } else if s > 0 {
      if ms != 0 {
        write!(f, "{}.{:03}s", s, ms)
      } else {
        write!(f, "{}s", s)
      }
    } else {
      write!(f, "0.{:03}s", ms)
    }

  }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::time::Duration;

  #[test]
  fn display_duration() {
    let cases = [
      (Duration::from_millis(100), "0.100s"),
      (Duration::from_millis(200), "0.200s"),
      (Duration::from_millis(1136), "1.136s"),
      (Duration::from_millis(35010), "35.010s"),
      (Duration::from_secs(59), "59s"),
      (Duration::from_secs(60), "1m"),
      (Duration::from_secs(61), "1m 1s"),
      (Duration::from_secs(3661), "1h 1m"),
    ];

    for (duration, expected) in cases {
      assert_eq!(DisplayDuration(duration).to_string(), expected);
    }
  }  
}