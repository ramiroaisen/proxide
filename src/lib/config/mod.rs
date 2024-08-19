use std::str::FromStr;
#[cfg(feature = "stats")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use listen::Listen;
use matcher::RequestMatcher;
use schemars::gen::{SchemaGenerator, SchemaSettings};
use schemars::schema::RootSchema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use server_name::ServerName;

use crate::backoff::BackOff;
#[cfg(any(
  feature = "compression-br",
  feature = "compression-zstd",
  feature = "compression-gzip",
  feature = "compression-deflate"
))]
use crate::compression::Encoding;

use crate::log::logfile::LogFileConfig;
use crate::log::LevelFilter;
#[cfg(feature = "interpolation")]
use crate::proxy::context::HttpInterpolation;
use crate::proxy_protocol::ProxyProtocolVersion;
use crate::serde::duration::SDuration;
use crate::serde::header_name::SHeaderName;
use crate::serde::sni::Sni;
use crate::serde::status_code::SStatusCode;
use crate::serde::url::{HttpUpstreamBaseUrl, StreamUpstreamOrigin};

#[allow(unused)]
use crate::serde::content_type::ContentTypeMatcher;
#[cfg(feature = "serve-static")]
use crate::serve_static::DotFiles;

pub mod listen;
pub mod matcher;
pub mod regex;
pub mod server_name;

#[cfg(feature = "interpolation")]
pub type ResponseHeaders = Vec<(SHeaderName, HttpInterpolation)>;

#[cfg(not(feature = "interpolation"))]
pub type ResponseHeaders = Vec<(SHeaderName, crate::serde::header_value::SHeaderValue)>;

#[cfg(feature = "interpolation")]
pub type ProxyHeaders = Vec<(SHeaderName, HttpInterpolation)>;

#[cfg(not(feature = "interpolation"))]
pub type ProxyHeaders = Vec<(SHeaderName, crate::serde::header_value::SHeaderValue)>;

#[cfg(feature = "interpolation")]
pub type ResponseBody = HttpInterpolation;

#[cfg(not(feature = "interpolation"))]
pub type ResponseBody = String;

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
  value == &T::default()
}

fn arc_atomic_bool<const B: bool>() -> Arc<AtomicBool> {
  Arc::new(AtomicBool::new(B))
}

pub mod defaults {
  use super::*;

  pub const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;

  pub const DEFAULT_HTTP_SERVER_READ_TIMEOUT: Duration = Duration::from_secs(120);
  pub const DEFAULT_HTTP_SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(120);

  pub const DEFAULT_HTTP_PROXY_READ_TIMEOUT: Duration = Duration::from_secs(60 * 60);
  pub const DEFAULT_HTTP_PROXY_WRITE_TIMEOUT: Duration = Duration::from_secs(60 * 10);

  pub const DEFAULT_STREAM_SERVER_READ_TIMEOUT: Duration = Duration::from_secs(60 * 60);
  pub const DEFAULT_STREAM_SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(60 * 5);

  pub const DEFAULT_STREAM_PROXY_READ_TIMEOUT: Duration = Duration::from_secs(60 * 60);
  pub const DEFAULT_STREAM_PROXY_WRITE_TIMEOUT: Duration = Duration::from_secs(60 * 5);

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate",
  ))]
  pub const DEFAULT_COMPRESSION_MIN_SIZE: u64 = 128;

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  macro_rules! list {
    ($($v:expr,)*) => {
      &[
        $(ContentTypeMatcher::from_static($v)),*
      ]
    };
  }
  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  pub const DEFAULT_COMPRESSION_CONTENT_TYPES: &[ContentTypeMatcher] = list!(
    "text/*",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/x-javascript",
    "application/vnd.ms-fontobject",
    "application/x-font-ttf",
    "application/x-font-opentype",
    "application/x-font-truetype",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "font/ttf",
    "font/otf",
    "font/eot",
    "font/opentype",
    "application/wasm",
    "*/*+json",
    "*/*+xml",
  );

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  pub const DEFAULT_COMPRESSION: &[Compress] = &[
    #[cfg(feature = "compression-zstd")]
    Compress {
      algo: Encoding::Zstd,
      level: 1,
    },
    #[cfg(feature = "compression-br")]
    Compress {
      algo: Encoding::Br,
      level: 1,
    },
    #[cfg(feature = "compression-gzip")]
    Compress {
      algo: Encoding::Gzip,
      level: 9,
    },
    #[cfg(feature = "compression-deflate")]
    Compress {
      algo: Encoding::Deflate,
      level: 9,
    },
  ];

  // TODO: make this configurable

  pub const DEFAULT_HTTP_PROXY_RETRIES: usize = 10; // 10 retries is equal to aprox 15 seconds
  pub const DEFAULT_HTTP_RETRY_BACKOFF: BackOff = BackOff::Exponential {
    exponent_base: 1.5,
    delay_base: SDuration(Duration::from_millis(100)),
    delay_max: SDuration(Duration::from_millis(2000)),
  };

  pub const DEFAULT_STREAM_PROXY_RETRIES: usize = 10; // 10 retries is equal to aprox 15 seconds
  pub const DEFAULT_STREAM_RETRY_BACKOFF: BackOff = BackOff::Exponential {
    exponent_base: 1.5,
    delay_base: SDuration(Duration::from_millis(100)),
    delay_max: SDuration(Duration::from_millis(2000)),
  };

  pub const DEFAULT_HTTP_BALANCE: Balance = Balance::RoundRobin;
  pub const DEFAULT_STREAM_BALANCE: Balance = Balance::RoundRobin;

  pub const DEFAULT_LOGFILE_RETAIN: usize = 3;
  pub const DEFAULT_LOGFILE_MAX_SIZE_BYTES: u64 = 1000 * 1000 * 20;

  pub const DEFAULT_PROXY_PROTOCOL_READ_TIMEOUT: Duration = Duration::from_secs(60);
  pub const DEFAULT_PROXY_PROTOCOL_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

  pub const DEFAULT_PROXY_TCP_NODELAY: bool = false;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub pidfile: Option<String>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub log_level: Option<LevelFilter>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub primary_log: Option<LogFileConfig>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub access_log: Option<LogFileConfig>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_log: Option<LogFileConfig>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub graceful_shutdown_timeout: Option<SDuration>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_read_timeout: Option<SDuration>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default, skip_serializing_if = "is_default")]
  pub rlimit: RLimit,

  #[serde(default, skip_serializing_if = "Http::is_empty")]
  pub http: Http,

  #[serde(default, skip_serializing_if = "Stream::is_empty")]
  pub stream: Stream,
}

// this struct is reused in the args and config structs
#[derive(
  Debug, Clone, Copy, Default, Serialize, Eq, PartialEq, Deserialize, JsonSchema, Parser,
)]
#[serde(deny_unknown_fields)]
pub struct RLimit {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-nofile", env = "PROXIDE_RLIMIT_NOFILE")]
  pub nofile: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-nproc", env = "PROXIDE_RLIMIT_NPROC")]
  pub nproc: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-threads", env = "PROXIDE_RLIMIT_THREADS")]
  pub rthreads: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-nthr", env = "PROXIDE_RLIMIT_NTHR")]
  pub nthr: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-stack", env = "PROXIDE_RLIMIT_STACK")]
  pub stack: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-rss", env = "PROXIDE_RLIMIT_RSS")]
  pub rss: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-memlock", env = "PROXIDE_RLIMIT_MEMLOCK")]
  pub memlock: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-swap", env = "PROXIDE_RLIMIT_SWAP")]
  pub swap: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-cpu", env = "PROXIDE_RLIMIT_CPU")]
  pub cpu: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-as", env = "PROXIDE_RLIMIT_AS")]
  #[serde(rename = "as")]
  pub r#as: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-core", env = "PROXIDE_RLIMIT_CORE")]
  pub core: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-data", env = "PROXIDE_RLIMIT_DATA")]
  pub data: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[clap(long = "rlimit-fsize", env = "PROXIDE_RLIMIT_FSIZE")]
  pub fsize: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Http {
  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression: Option<Vec<Compress>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_content_types: Option<Vec<ContentTypeMatcher>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_min_size: Option<u64>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_write_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub graceful_shutdown_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub response_headers: ResponseHeaders,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub proxy_headers: ProxyHeaders,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retries: Option<usize>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retry_backoff: Option<BackOff>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub balance: Option<Balance>,

  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub apps: Vec<HttpApp>,
}

impl Http {
  fn is_empty(&self) -> bool {
    match self {
      Http {
        balance: None,
        retries: None,
        retry_backoff: None,
        proxy_protocol_write_timeout: None,
        graceful_shutdown_timeout: None,
        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
          compression: None,
        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
          compression_content_types: None,
        #[cfg(any(
          feature = "compression-br",
          feature = "compression-zstd",
          feature = "compression-gzip",
          feature = "compression-deflate"
        ))]
          compression_min_size: None,
        server_read_timeout: None,
        server_write_timeout: None,
        proxy_read_timeout: None,
        proxy_write_timeout: None,
        proxy_protocol_read_timeout: None,
        proxy_tcp_nodelay: None,
        apps,
        response_headers,
        proxy_headers,
      } => apps.is_empty() && response_headers.is_empty() && proxy_headers.is_empty(),

      _ => false,
    }
  }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Stream {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_write_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub graceful_shutdown_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retries: Option<usize>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retry_backoff: Option<BackOff>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub balance: Option<Balance>,

  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub apps: Vec<StreamApp>,
}

impl Stream {
  fn is_empty(&self) -> bool {
    match self {
      Stream {
        balance: None,
        retries: None,
        retry_backoff: None,
        proxy_protocol_write_timeout: None,
        graceful_shutdown_timeout: None,
        server_read_timeout: None,
        server_write_timeout: None,
        proxy_read_timeout: None,
        proxy_write_timeout: None,
        proxy_protocol_read_timeout: None,
        proxy_tcp_nodelay: None,
        apps,
      } => apps.is_empty(),

      _ => false,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpApp {
  pub listen: Vec<Listen>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_names: Option<Vec<ServerName>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression: Option<Vec<Compress>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_content_types: Option<Vec<ContentTypeMatcher>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_min_size: Option<u64>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub balance: Option<Balance>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retries: Option<usize>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retry_backoff: Option<BackOff>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub response_headers: ResponseHeaders,

  #[serde(flatten)]
  pub handle: HttpHandle,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamApp {
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub listen: Vec<Listen>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub server_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(flatten)]
  pub handle: StreamHandle,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum Balance {
  #[serde(rename = "round-robin")]
  RoundRobin,
  #[serde(rename = "random")]
  Random,
  #[serde(rename = "ip-hash")]
  IpHash,
  #[serde(rename = "least-connections")]
  LeastConnections,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpUpstream {
  pub base_url: HttpUpstreamBaseUrl,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub sni: Option<Sni>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub send_proxy_protocol: Option<ProxyProtocolVersion>,

  #[serde(default)]
  pub version: UpstreamVersion,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub proxy_headers: ProxyHeaders,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub response_headers: ResponseHeaders,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression: Option<Vec<Compress>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_content_types: Option<Vec<ContentTypeMatcher>>,

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub compression_min_size: Option<u64>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_write_timeout: Option<SDuration>,

  #[serde(default)]
  pub danger_accept_invalid_certs: bool,

  // should we send requests to this upstream or not
  #[serde(skip_deserializing, default = "arc_atomic_bool::<true>")]
  #[schemars(skip)]
  pub state_health: Arc<AtomicBool>,

  // u32 gives us 4 B per upstream, i think that's enough
  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  pub state_open_connections: Arc<AtomicUsize>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_read_bytes: Arc<AtomicU64>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_write_bytes: Arc<AtomicU64>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_connections: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamUpstream {
  pub origin: StreamUpstreamOrigin,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub sni: Option<Sni>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub send_proxy_protocol: Option<ProxyProtocolVersion>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_read_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_write_timeout: Option<SDuration>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_protocol_write_timeout: Option<SDuration>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub proxy_tcp_nodelay: Option<bool>,

  #[serde(default)]
  pub danger_accept_invalid_certs: bool,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  pub state_open_connections: Arc<AtomicUsize>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_read_bytes: Arc<AtomicU64>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_write_bytes: Arc<AtomicU64>,

  #[serde(skip_deserializing, default)]
  #[schemars(skip)]
  #[cfg(feature = "stats")]
  pub stats_total_connections: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum StreamHandle {
  #[serde(rename = "proxy")]
  Proxy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    balance: Option<Balance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retries: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_backoff: Option<BackOff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_protocol_write_timeout: Option<SDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_read_timeout: Option<SDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_write_timeout: Option<SDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_tcp_nodelay: Option<bool>,
    #[serde(default, skip_deserializing)]
    #[schemars(skip)]
    state_round_robin_index: Arc<AtomicUsize>,
    upstream: Vec<StreamUpstream>,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum HttpHandle {
  #[serde(rename = "return")]
  Return {
    status: SStatusCode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_headers: ResponseHeaders,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body: Option<ResponseBody>,
  },

  #[serde(rename = "heap_profile")]
  HeapProfile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_headers: ResponseHeaders,
  },

  #[serde(rename = "stats")]
  Stats {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_headers: ResponseHeaders,
  },

  #[cfg(feature = "serve-static")]
  #[serde(rename = "static")]
  Static {
    base_dir: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    index_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dot_files: Option<DotFiles>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_headers: ResponseHeaders,
  },

  #[serde(rename = "proxy")]
  Proxy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    balance: Option<Balance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retries: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_backoff: Option<BackOff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_read_timeout: Option<SDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_write_timeout: Option<SDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_tcp_nodelay: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proxy_headers: ProxyHeaders,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_headers: ResponseHeaders,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_protocol_write_timeout: Option<SDuration>,
    #[serde(skip_deserializing, default)]
    state_round_robin_index: Arc<AtomicUsize>,
    upstream: Vec<HttpUpstream>,
  },

  #[serde(rename = "when")]
  When(Vec<HttpMatcher>),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpMatcher {
  #[serde(rename = "match")]
  pub matcher: RequestMatcher,
  #[serde(flatten)]
  pub handle: HttpHandle,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum UpstreamVersion {
  #[serde(rename = "http/1.0")]
  Http10,
  #[default]
  #[serde(rename = "http/1.1")]
  Http11,
  #[serde(rename = "http/2")]
  Http2,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid upstream version: {0}, expected one of 'http/1.0', 'http/1.1', 'http/2'")]
pub struct InvalidVersionError(String);

impl FromStr for UpstreamVersion {
  type Err = InvalidVersionError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "http/1.0" => Ok(UpstreamVersion::Http10),
      "http/1.1" => Ok(UpstreamVersion::Http11),
      "http/2" => Ok(UpstreamVersion::Http2),
      _ => Err(InvalidVersionError(s.to_string())),
    }
  }
}

impl From<UpstreamVersion> for hyper::Version {
  fn from(version: UpstreamVersion) -> Self {
    match version {
      UpstreamVersion::Http10 => hyper::Version::HTTP_10,
      UpstreamVersion::Http11 => hyper::Version::HTTP_11,
      UpstreamVersion::Http2 => hyper::Version::HTTP_2,
    }
  }
}

#[cfg(any(
  feature = "compression-br",
  feature = "compression-zstd",
  feature = "compression-gzip",
  feature = "compression-deflate"
))]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Compress {
  pub algo: Encoding,
  #[schemars(range(min = 1))]
  pub level: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadConfigError {
  // #[error("{0}")]
  // Metre(#[from] metre::Error),
  #[error("{0}")]
  Toml(#[from] toml::de::Error),

  #[error("{0}")]
  Yaml(#[from] serde_yaml::Error),

  #[error("{0}")]
  Json(#[from] serde_json::Error),

  #[error("{0}")]
  Io(#[from] std::io::Error),

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[error("compression level out of range for {}: level must be between {} and {}, received {}", item.algo, min, max, item.level)]
  CompressionLevelOutOfRange { min: u8, max: u8, item: Compress },
}

#[allow(unused)]
pub fn validate_config(config: &Config) -> Result<(), LoadConfigError> {
  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  {
    if let Some(compression) = &config.http.compression {
      for item in compression {
        validate_compression(*item)?;
      }
    }

    for app in &config.http.apps {
      if let Some(compression) = &app.compression {
        for item in compression {
          validate_compression(*item)?;
        }
      }
    }
  }

  Ok(())
}

#[cfg(any(
  feature = "compression-br",
  feature = "compression-zstd",
  feature = "compression-gzip",
  feature = "compression-deflate"
))]
fn validate_compression(item: Compress) -> Result<(), LoadConfigError> {
  let min = 1;
  let max = match item.algo {
    #[cfg(feature = "compression-zstd")]
    Encoding::Zstd => 19,
    #[cfg(feature = "compression-br")]
    Encoding::Br => 9,
    #[cfg(feature = "compression-gzip")]
    Encoding::Gzip => 9,
    #[cfg(feature = "compression-deflate")]
    Encoding::Deflate => 9,
  };

  if item.level < min || item.level > max {
    return Err(LoadConfigError::CompressionLevelOutOfRange { min, max, item });
  }

  Ok(())
}

pub fn load(path: &str) -> Result<Config, LoadConfigError> {
  // let mut loader = ConfigLoader::<Config>::new();
  // loader.file(path, Format::Toml)?;
  // let config = loader.finish()?;
  // validate_config(&config)?;

  let string = std::fs::read_to_string(path)?;
  let config: Config = if path.ends_with(".yml") || path.ends_with(".yaml") {
    serde_yaml::from_str(&string)?
  } else if path.ends_with(".json") {
    serde_json::from_str(&string)?
  } else {
    toml::from_str(&string)?
  };

  validate_config(&config)?;

  Ok(config)
}

impl Config {
  pub fn schema() -> RootSchema {
    let mut settings = SchemaSettings::default();
    settings.option_add_null_type = false;
    let mut gen = SchemaGenerator::new(settings);
    gen.root_schema_for::<Self>()
  }
}

#[cfg(test)]
pub mod export {
  use super::*;
  use schemars::gen::SchemaGenerator;

  #[test]
  fn export_config_schema() {
    let mut gen = SchemaGenerator::default();
    let schema = gen.root_schema_for::<Config>();
    let dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{}/config.schema.json", dir);
    std::fs::write(path, serde_json::to_string_pretty(&schema).unwrap()).unwrap();
  }

  #[test]
  fn sample_config_is_valid() {
    let config_str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config.sample.yml"));
    let config: Config = serde_yaml::from_str(config_str).expect("error parsing yaml config file");
    validate_config(&config).expect("error validating config");
  }

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[test]
  fn validate_compression_ok() {
    let items = vec![
      Compress {
        algo: Encoding::Zstd,
        level: 19,
      },
      Compress {
        algo: Encoding::Br,
        level: 9,
      },
      Compress {
        algo: Encoding::Gzip,
        level: 9,
      },
      Compress {
        algo: Encoding::Deflate,
        level: 9,
      },
    ];

    for item in items {
      validate_compression(item).unwrap();
    }
  }

  #[cfg(any(
    feature = "compression-br",
    feature = "compression-zstd",
    feature = "compression-gzip",
    feature = "compression-deflate"
  ))]
  #[test]
  fn validate_compression_err() {
    let items = vec![
      Compress {
        algo: Encoding::Zstd,
        level: 0,
      },
      Compress {
        algo: Encoding::Br,
        level: 10,
      },
      Compress {
        algo: Encoding::Gzip,
        level: 10,
      },
      Compress {
        algo: Encoding::Deflate,
        level: 10,
      },
    ];

    for item in items {
      assert!(validate_compression(item).is_err());
    }
  }
}
