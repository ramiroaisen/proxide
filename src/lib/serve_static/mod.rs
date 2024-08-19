use headers::{
  AcceptRanges, ContentLength, ContentRange, ContentType, HeaderMapExt, IfModifiedSince, IfRange,
  IfUnmodifiedSince, LastModified, Range,
};
use http::{HeaderMap, StatusCode};
use http_body::Frame;
use std::{
  fs::File,
  io::{Read, Seek, Take},
  ops::Bound,
  path::PathBuf,
  str::FromStr,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{body::Body, proxy::error::ProxyHttpError};

// copied from static-web-server
#[cfg(unix)]
pub(crate) fn get_optimal_buf_size(metadata: &std::fs::Metadata, len: u64) -> usize {
  use std::os::unix::fs::MetadataExt;
  // If file length is smaller than block size,
  // don't waste space reserving a bigger-than-needed buffer.
  std::cmp::min(
    std::cmp::max(metadata.blksize() as usize, 1024 * 4),
    len as usize,
  )
}

// copied from static-web-server
#[cfg(not(unix))]
fn get_optimal_buf_size(_metadata: &std::fs::Metadata, len: u64) -> usize {
  std::cmp::min(1024 * 8, len)
}

fn create_body<R: std::io::Read + Send + Sync + 'static>(mut read: R, buf_size: usize) -> Body {
  use bytes::BytesMut;
  // use bytes::Bytes;
  // let mut buf = [0; 1024 * 4];
  let stream = async_stream::try_stream! {
    loop {
      let mut buf = BytesMut::zeroed(buf_size);
      let n = read.read(&mut buf).map_err(ProxyHttpError::FileRead)?;
      if n == 0 {
        break;
      } else {
        // let chunk = Bytes::copy_from_slice(&buf[..n]);
        // yield Frame::data(chunk);
        buf.truncate(n);
        yield Frame::data(buf.freeze());
      }
    }
  };

  Body::stream(stream)
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Resolved {
  AppendSlash,
  NotModified,
  UnmodifiedPreconditionFailed,
  RangeNotSatisfiable,
  Serve {
    range: Option<(Bound<u64>, Bound<u64>)>,
    path: PathBuf,
    metadata: std::fs::Metadata,
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Body,
  },
}

#[derive(Debug, thiserror::Error)]
pub enum ServeStaticError {
  #[error("invalid root dir path component")]
  PathComponentRootDir,
  #[error("invalid prefix path component")]
  PathComponentPrefix,
  #[error("invalid current dir path component")]
  PathComponentCurDir,
  #[error("invalid parent dir path component")]
  PathComponentParentDir,
  #[error("invalid empty path component")]
  PathComponentEmpty,
  #[error("dotfiles ignored")]
  DotFilesIgnored,
  #[error("dotfiles error")]
  DotFilesError,
  #[error("target is a directory")]
  Directory,
  #[error("target is not a file")]
  IndexFileDirectory,
  #[error("target is not a file")]
  NotAFile,
  #[error("index file not a file")]
  IndexFileNotAFile,
  #[error("canonicalize base error: {0}")]
  CanonicalizeBase(#[source] std::io::Error),
  #[error("canonicalize path error: {0}")]
  CanonicalizeTarget(#[source] std::io::Error),
  #[error("canonicalize index file error: {0}")]
  IndexFileCanonicalizeTarget(#[source] std::io::Error),
  #[error("metadata error: {0}")]
  Metadata(#[source] std::io::Error),
  #[error("metadata index file error: {0}")]
  IndexFileMetadata(#[source] std::io::Error),
  #[error("open file error: {0}")]
  Open(#[source] std::io::Error),
  #[error("index file open error: {0}")]
  IndexFileOpen(#[source] std::io::Error),
  #[error("file outside base directory")]
  OutsideBase,
  #[error("index file outside base directory")]
  IndexFileOutsideBase,
  #[error("file seek error: {0}")]
  FileSeek(#[source] std::io::Error),
}

impl ServeStaticError {
  pub fn is_not_found(&self) -> bool {
    use ServeStaticError as E;
    match self {
      E::PathComponentRootDir => false,
      E::PathComponentPrefix => false,
      E::PathComponentCurDir => false,
      E::PathComponentParentDir => false,
      E::PathComponentEmpty => false,
      E::DotFilesError => false,
      E::Directory => false,
      E::IndexFileDirectory => false,
      E::NotAFile => false,
      E::IndexFileNotAFile => false,
      E::OutsideBase => false,
      E::IndexFileOutsideBase => false,
      E::DotFilesIgnored => true,

      E::CanonicalizeBase(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::CanonicalizeTarget(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileCanonicalizeTarget(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::Metadata(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileMetadata(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::Open(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileOpen(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::FileSeek(_) => false,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServeStaticOptions<'a> {
  pub index_files: &'a [String],
  pub dot_files: DotFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum DotFiles {
  #[serde(rename = "ignore")]
  Ignore,
  #[serde(rename = "allow")]
  Allow,
  #[serde(rename = "error")]
  Error,
}

/// parameter path should not have the leading slash
pub async fn resolve(
  base_dir: &str,
  path: &str,
  request_headers: &hyper::HeaderMap,
  options: ServeStaticOptions<'_>,
) -> Result<Resolved, ServeStaticError> {
  // remove leading slash
  let base = std::fs::canonicalize(base_dir).map_err(ServeStaticError::CanonicalizeBase)?;

  let mut target = if path.is_empty() {
    base.clone()
  } else {
    let target = PathBuf::from(path);
    for component in target.components() {
      use std::path::Component as C;
      // only allow normal path components: Eg: foo/bar/baz
      // not C:/ or /root or foo/../ or foo/./
      match component {
        C::CurDir => return Err(ServeStaticError::PathComponentCurDir),
        C::Prefix(_) => return Err(ServeStaticError::PathComponentPrefix),
        C::ParentDir => return Err(ServeStaticError::PathComponentParentDir),
        C::RootDir => return Err(ServeStaticError::PathComponentRootDir),
        C::Normal(component) => {
          let bytes = component.as_encoded_bytes();
          match bytes.first() {
            None => return Err(ServeStaticError::PathComponentEmpty),
            Some(b'.') => match options.dot_files {
              DotFiles::Ignore => return Err(ServeStaticError::DotFilesIgnored),
              DotFiles::Error => return Err(ServeStaticError::DotFilesError),
              DotFiles::Allow => {}
            },
            _ => {}
          }
        }
      }
    }

    let target =
      std::fs::canonicalize(base.join(target)).map_err(ServeStaticError::CanonicalizeTarget)?;

    // check if the target file is inside the base directory
    // else return an error
    if !target.starts_with(&base) {
      // dbg!(&base, &target, "base outside target");
      return Err(ServeStaticError::OutsideBase);
    }

    target
  };

  // dbg!(&target);

  let mut metadata = std::fs::metadata(&target).map_err(ServeStaticError::Metadata)?;

  let mut file: std::fs::File;

  'resolve: {
    if metadata.is_dir() {
      for index_file in options.index_files {
        let index_target = match std::fs::canonicalize(target.join(index_file)) {
          Ok(index_target) => index_target,
          Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
              continue;
            }
            return Err(ServeStaticError::IndexFileCanonicalizeTarget(e));
          }
        };

        if !index_target.starts_with(base) {
          return Err(ServeStaticError::IndexFileOutsideBase);
        }

        let index_metadata =
          std::fs::metadata(&index_target).map_err(ServeStaticError::Metadata)?;

        if !index_metadata.is_file() {
          return Err(ServeStaticError::IndexFileNotAFile);
        }

        if !path.is_empty() && !path.ends_with('/') {
          return Ok(Resolved::AppendSlash);
        }

        file = std::fs::OpenOptions::new()
          .read(true)
          .open(&index_target)
          .map_err(ServeStaticError::IndexFileOpen)?;
        target = index_target;
        metadata = index_metadata;

        break 'resolve;
      }

      return Err(ServeStaticError::Directory);
    } else {
      if !metadata.is_file() {
        return Err(ServeStaticError::NotAFile);
      }

      file = std::fs::OpenOptions::new()
        .read(true)
        .open(&target)
        .map_err(ServeStaticError::Open)?;
    }
  }

  if let Ok(meta_modified) = metadata.modified() {
    if let Some(if_modified_since) = request_headers.typed_get::<IfModifiedSince>() {
      if !if_modified_since.is_modified(meta_modified) {
        return Ok(Resolved::NotModified);
      }
    }

    if let Some(if_unmodified_since) = request_headers.typed_get::<IfUnmodifiedSince>() {
      if !if_unmodified_since.precondition_passes(meta_modified) {
        return Ok(Resolved::UnmodifiedPreconditionFailed);
      }
    }
  }

  let range = 'range: {
    match (
      request_headers.typed_get::<Range>(),
      request_headers.typed_get::<IfRange>(),
      metadata.modified(),
    ) {
      (None, _, _) => break 'range None,
      (Some(ranges), if_range, last_modified_time) => {
        if let Some(if_range) = if_range {
          let last_modified = last_modified_time.ok().map(LastModified::from);
          if if_range.is_modified(None, last_modified.as_ref()) {
            break 'range None;
          }
        };

        let mut ranges_iter = ranges.satisfiable_ranges(metadata.len());

        match ranges_iter.next() {
          // no satisfiable range
          None => return Ok(Resolved::RangeNotSatisfiable),

          Some(range) => {
            // more than 1 range (multipart ranges) is not supported
            let next = ranges_iter.next();
            if next.is_some() {
              return Ok(Resolved::RangeNotSatisfiable);
            }

            break 'range Some(range);
          }
        }
      }
    }
  };

  let mut headers = HeaderMap::new();

  // content type
  let mime = mime_guess::from_path(&target).first();
  if let Some(mime) = mime {
    headers.typed_insert(ContentType::from_str(mime.as_ref()).unwrap());
  } else {
    headers.typed_insert(ContentType::octet_stream())
  }

  if let Ok(meta_modified) = metadata.modified() {
    headers.typed_insert(LastModified::from(meta_modified));
  }

  let len: u64;
  let status: StatusCode;
  let content_range: Option<ContentRange>;
  // we always use take to avoid dynamic dispatch even when there's nothing to take
  // also if the file length increase afterwise, the content-length header will be wrong
  let reader: Take<File>;

  match range {
    Some((start_bound, end_bound)) => {
      let start = match start_bound {
        Bound::Included(start) => start,
        Bound::Excluded(start) => start + 1,
        Bound::Unbounded => 0,
      };

      let end = match end_bound {
        Bound::Included(end) => end + 1,
        Bound::Excluded(end) => end,
        Bound::Unbounded => metadata.len(),
      };

      len = end - start;
      status = StatusCode::PARTIAL_CONTENT;
      content_range = Some(ContentRange::bytes(start..end, metadata.len()).unwrap());

      if start != 0 {
        file
          .seek(std::io::SeekFrom::Start(start))
          .map_err(ServeStaticError::FileSeek)?;
      }

      reader = file.take(len);
    }

    None => {
      status = StatusCode::OK;
      len = metadata.len();
      content_range = None;
      reader = file.take(len);
    }
  };

  headers.typed_insert(AcceptRanges::bytes());
  headers.typed_insert(ContentLength(len));
  if let Some(content_range) = content_range {
    headers.typed_insert(content_range);
  }

  let body = create_body(reader, get_optimal_buf_size(&metadata, len));

  let resolved = Resolved::Serve {
    path: target,
    range,
    metadata,
    status,
    headers,
    body,
  };

  Ok(resolved)
}
