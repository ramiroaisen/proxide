pub mod cmd;
pub mod args;

use args::Args;
use args::Command;

/// Run the application, from a parsed [`Args`] struct, unsually parsed from the command line.
pub fn run(args: Args) -> Result<(), anyhow::Error> {
  match args.command {
    Command::Start(start) => cmd::start(start),
    Command::CreateConfig(create_config) => cmd::create_config(create_config),
    Command::CreateConfigSchema(create_config_schema) => cmd::create_config_schema(create_config_schema),
    #[cfg(unix)]
    Command::Signal(signal) => cmd::signal(signal),
  }
}