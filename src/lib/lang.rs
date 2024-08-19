/// a macro to get the first Some value from a list of Options with an optional
/// default and a special case for [crate::serde::duration::SDuration] options
/// ```
/// # fn main() {
/// # use proxide::option;
/// // if you don't specify a default value, the return value will be wrapped in an Option
/// let value = option!(
///   None,
///   Some(10),
///   Some(20),
/// );
///
/// assert_eq!(value, Some(10));
///
/// // if you specifiy a default value, the return value will not be wrapped in an Option
/// let value2 = option!(
///   None,
///   => 1
/// );
///
/// assert_eq!(value2, 1);
/// # }
/// ```
#[macro_export]
macro_rules! option {

  // only one item
  ($head:expr $(,)?) => {
    $head
  };

  // two or more items, recursive
  ($head:expr, $($tail:expr),* $(,)?) => {
    match $head {
      Some(v) => Some(v),
      None => $crate::option!($($tail),*),
    }
  };

  // one item with upfront default
  ($head:expr $(,)? => $default:expr) => {
    $crate::option!($head).unwrap_or($default)
  };

  // two or more items with upfront default
  ($head:expr, $($tail:expr),* $(,)? => $default:expr) => {
    $crate::option!($head, $($tail),*).unwrap_or($default)
  };

  // one item with lazy default
  ($head:expr $(,)? => || $default:expr) => {
    $crate::option!($head).unwrap_or_else(|| $default)
  };

  // two or more items with lazy default
  ($head:expr, $($tail:expr),* $(,)? => || $default:expr) => {
    $crate::option!($head, $($tail),*).unwrap_or_else(|| $default)
  };

  // timeout
  // @timeout one item
  (@timeout $head:expr $(,)?) => {
    match $head {
      Some(v) => Some(Duration::from(v)),
      None => None,
    }
  };

  // @timeout two or more items
  (@timeout $head:expr, $($tail:expr),* $(,)?) => {
    match $head {
      Some(v) => Some(Duration::from(v)),
      None => $crate::option!(@timeout $($tail),*),
    }
  };

  // @timeout one item with upfront default
  (@timeout $head:expr $(,)? => $default:expr) => {
    $crate::option!(@timeout $head).unwrap_or($default)
  };

  // @timeout two or more items with upfront default
  (@timeout $head:expr, $($tail:expr),* $(,)? => $default:expr) => {
    $crate::option!(@timeout $head, $($tail),*).unwrap_or($default)
  };

  // @timeout one item with lazy default
  (@timeout $head:expr $(,)? => || $default:expr) => {
    $crate::option!(@timeout $head).unwrap_or_else(|| $default)
  };

  // @timeout two or more items with lazy default
  (@timeout $head:expr, $($tail:expr),* $(,)? => || $default:expr) => {
    $crate::option!(@timeout $head, $($tail),*).unwrap_or_else(|| $default)
  };
}

/// This macro is used to group multiple declarations without a block
/// Eg: for applying a cfg attribute to several items at once
#[macro_export]
macro_rules! group {
  ($($tt:tt)*) => {
    $($tt)*
  }
}
