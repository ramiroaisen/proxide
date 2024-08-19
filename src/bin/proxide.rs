use clap::Parser;
use proxide::cli::{self, args::Args};

#[cfg(all(target_os = "linux", feature = "jemalloc"))]
proxide::group!(
  #[global_allocator]
  static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

  #[allow(non_upper_case_globals)]
  #[export_name = "malloc_conf"]
  pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";
);

fn main() -> Result<(), anyhow::Error> {
  #[cfg(feature = "human-panic")]
  human_panic::setup_panic!();

  let args = Args::parse();
  cli::run(args)?;
  Ok(())
}
