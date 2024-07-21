use std::path::{Path, PathBuf};

use crate::cli::args::CreateConfig;
use crate::config::Config;

pub fn create_config(args: CreateConfig) -> Result<(), anyhow::Error> {
  let CreateConfig { output, omit_schema: no_schema } = args;
  let config_str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config.sample.yml"));
  if Path::new(&output).exists() {
    anyhow::bail!("output file {} already exists, aborting", output);
  }
  std::fs::write(&output, config_str)?;
  eprintln!("config file written to {}", output);
  if !no_schema {
    let schema = Config::schema();
    let mut schema_path = PathBuf::from(output);
    schema_path.pop();
    schema_path.push("config.schema.json");
    std::fs::write(&schema_path, serde_json::to_string_pretty(&schema).unwrap())?;
    eprintln!("config JSON schema file written to {}", schema_path.display());
  }
  Ok(())
}