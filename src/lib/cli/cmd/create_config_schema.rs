use crate::cli::args::CreateConfigSchema;
use crate::config::Config;

pub fn create_config_schema(args: CreateConfigSchema) -> Result<(), anyhow::Error> {
  let CreateConfigSchema { output } = args;
  let schema = Config::schema();
  std::fs::write(&output, serde_json::to_string_pretty(&schema).unwrap())?;
  eprintln!("config schema written to {}", output);
  Ok(())
}