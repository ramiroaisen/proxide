#![allow(unused)]
use std::{convert::Infallible, io::Write, path::Path, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::SystemTime};

use kanal::{AsyncReceiver, AsyncSender, Receiver, Sender};
use owo_colors::OwoColorize;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use std::future::Future;

pub struct LogFile {
  log_sender: Sender<String>,
  log_receiver: AsyncReceiver<String>,
  config_sender: Sender<LogFileConfig>,
  config_receiver: AsyncReceiver<LogFileConfig>,
  cancel_token: CancellationToken,
  started: AtomicBool,
}

impl LogFile {
  pub fn new() -> Self {
    let (log_sender, log_receiver) = kanal::unbounded_async();
    let (config_sender, config_receiver) = kanal::unbounded_async();
    let cancel_token = CancellationToken::new();
    
    LogFile {
      log_receiver,
      log_sender: log_sender.to_sync(),
      config_receiver,
      config_sender: config_sender.to_sync(),
      cancel_token,
      started: AtomicBool::new(false),
    }
  }

  #[inline(always)]
  pub fn log(&self, message: String) {
    // this will never fail because we have a reference to the receiver
    let _ = self.log_sender.send(message);
  }

  #[inline(always)]
  pub async fn recv(&self) -> String {
    // this will never fail because we have a reference to the sender
    self.log_receiver.recv().await.unwrap()
  }

  #[inline(always)]
  pub async fn recv_config(&self) -> LogFileConfig {
    // this will never fail because we have a reference to the sender
    self.config_receiver.recv().await.unwrap()
  }

  #[inline(always)]
  pub fn cancel(&self) {
    self.cancel_token.cancel();
  }

  #[inline(always)]
  pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
    self.cancel_token.cancelled()
  }

  #[inline(always)]
  pub fn is_cancelled(&self) -> bool {
    self.cancel_token.is_cancelled()
  }

  pub fn start_or_config(&'static self, mut config: LogFileConfig) -> Option<JoinHandle<Result<(), LogFileError>>> {
    

    if self.started.swap(true, Ordering::AcqRel) { 
      let _ = self.config_sender.send(config);
      return None
    }

    log::info!("starting log file at {}", config.path);

    let rt = tokio::runtime::Handle::current();
  
    let handle = tokio::task::spawn_blocking(move || {
  
      rt.block_on(async move {
        
        let cancel_signal = self.cancelled();
        
        tokio::pin!(cancel_signal);
        
        'config: loop {
          
          let path = config.path.clone();
          
          let retain = match config.retain {
            Some(retain) => retain,
            None => crate::config::defaults::DEFAULT_LOGFILE_RETAIN, 
          };
  
          let max_size_bytes = match config.max_size_mb {
            Some(max_size_mb) => max_size_mb * 1000 * 1000,
            None => crate::config::defaults::DEFAULT_LOGFILE_MAX_SIZE_BYTES,
          };
  
          // mkdir -p log
          let mut dir = std::path::PathBuf::from(&path);
          
          let filename = match dir.file_name() {
            None => return Err(LogFileError::NoFileName),
            Some(name) => match name.to_str() {
              None => return Err(LogFileError::InvalidFileName),
              Some(name) => String::from(name),
            }
          };
  
          dir.pop();
          std::fs::create_dir_all(&dir)
            .map_err(LogFileError::CreateDir)?;
  
          let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(LogFileError::Open)?;
  
          let timeout = std::time::Duration::from_millis(100); // 100 ms
  
          let mut current_size = file.metadata()
            .map_err(LogFileError::Metadata)?
            .len();
          
          let file = std::io::BufWriter::new(file);
          // we enclose the writer to call flush on drop
          let mut writer = FileWriter { file };
          let mut flushed = true;
  
          let messages_task = async {
  
            // TODO: is there a better way to explicitly set the return type of this future?
            if false {
              // this will be removed by the compiler
              return Err::<Infallible, LogFileError>(LogFileError::NoFileName);
            }
  
            'messages: loop {
              
              let message = match tokio::time::timeout(timeout, self.recv()).await {
                Ok(message) => message,
                Err(_) => {
                  if !flushed {
                    writer.file.flush()
                      .map_err(LogFileError::Flush)?;
                    flushed = true;
                  }
                  continue 'messages;
                }
              };
  
              writer.file.write_all(message.as_bytes())
                .map_err(LogFileError::Write)?;
              
              current_size += message.len() as u64;
              flushed = false;
              
              if current_size >= max_size_bytes {
                writer
                  .file
                  .flush()
                  .map_err(LogFileError::Flush2)?;
                
                let timestamp = humantime::format_rfc3339_nanos(SystemTime::now())
                  .to_string()
                  .replace(':', "_");

                let new_name = format!("{}-{}.log", path, timestamp);
                std::fs::rename(&path, new_name)
                  .map_err(LogFileError::Rename)?;
                
                // clear previous files
                match std::fs::read_dir(&dir) {
                  Err(e) => log::error!("error reading log file directory: {}", e),
                  Ok(dir_entry) => {
                    let prefix = format!("{}-", filename);
                    let mut log_files = dir_entry.filter_map(|item| {
                      match item {
                        Err(e) => None,
                        Ok(item) => match item.file_name().into_string() {
                          Err(_) => None,
                          Ok(name) => {
                            if name.starts_with(&prefix) && name.ends_with(".log") {
                              Some(name)
                            } else {
                              None
                            }
                          }
                        }
                      }
                    }).collect::<Vec<String>>();
  
                    if log_files.len() > retain {
                      log_files.sort();
                      log_files.reverse();
                      // we skip the first ones cause they are the newest
                      for file in log_files.iter().skip(retain) {
                        let target = dir.join(file);
                        if let Err(e) = std::fs::remove_file(&target) {
                          log::error!("error removing old log file at {target:?} - {e} {e:?}");
                        }
                      }
                    }
                  }
                }
                
                let new_file = std::fs::OpenOptions::new()
                  .create(true)
                  .append(true)
                  .open(&path)
                  .map_err(LogFileError::Open2)?;
              
                let new_buf = std::io::BufWriter::new(new_file);
                writer = FileWriter { file: new_buf };
                current_size = 0;
                flushed = true;
              }
            }
          };
  
          tokio::pin!(messages_task);
  
          'messages: loop {

            tokio::select! {
              
              _ = &mut cancel_signal => {
                log::info!("stopping logfile task for {path} due to shutdown signal");
                return Ok(())
              }
  
              result = &mut messages_task => {
                match result {
                  Ok(never) => match never {},
                  Err(e) => {
                    log::error!("stopping logfile task for {path} due to error - {e}: {e:?}");
                    return Err(e)
                  },
                }
              }
  
              new_config = self.recv_config() => {
                if config != new_config {
                  config = new_config;
                  log::info!("re-configuring log file at {}", config.path);
                  continue 'config;
                } else {
                  continue 'messages;
                }
              }
            }
          }
        }
      })
    });

    Some(handle)
  }    
}

impl Default for LogFile {
  fn default() -> Self {
    Self::new()
  }
}

#[doc(hidden)]
#[static_init::dynamic]
pub(crate) static ACCESS_LOG: LogFile = LogFile::new();

#[doc(hidden)]
#[static_init::dynamic]
pub(crate) static CLIENT_LOG: LogFile = LogFile::new();

#[doc(hidden)]
#[static_init::dynamic]
pub(crate) static PRIMARY_LOG: LogFile = LogFile::new();

struct FileWriter<W: Write> {
  file: W,
}

impl<W: Write> Drop for FileWriter<W> {
  fn drop(&mut self) {
    let _ = self.file.flush();
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct LogFileConfig {
  pub path: String,
  pub max_size_mb: Option<u64>,
  pub retain: Option<usize>, 
}

#[derive(Debug, thiserror::Error)]
  pub enum LogFileError {
    #[error("invalid log file path: no file name")]
    NoFileName,
    #[error("invalid log file path: invalid file name")]
    InvalidFileName,
    #[error("create directory: {0}")]
    CreateDir(std::io::Error),
    #[error("open file: {0}")]
    Open(std::io::Error),
    #[error("re-open file: {0}")]
    Open2(std::io::Error),
    #[error("read directory: {0}")]
    ReadDir(std::io::Error),
    #[error("rename file: {0}")]
    Rename(std::io::Error),
    #[error("metadata: {0}")]
    Metadata(std::io::Error),
    #[error("flush: {0}")]
    Flush(std::io::Error),
    #[error("flush2: {0}")]
    Flush2(std::io::Error),
    #[error("write: {0}")]
    Write(std::io::Error),
  }