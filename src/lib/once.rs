#[macro_export]
macro_rules! once {
  () => {{
    static CALLED: ::std::sync::atomic::AtomicBool = ::std::sync::atomic::AtomicBool::new(false);
    !CALLED.swap(true, ::std::sync::atomic::Ordering::AcqRel)
  }};
}