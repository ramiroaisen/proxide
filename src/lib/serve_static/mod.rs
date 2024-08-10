use std::path::PathBuf;

#[derive(Debug)]
pub enum Resolved {
  AppendSlash,
  Serve {
    path: PathBuf,
    metadata: std::fs::Metadata,
    file: tokio::fs::File,
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
      E::DotFilesIgnored => false,
      E::DotFilesError => false,
      E::Directory => false,
      E::IndexFileDirectory => false,
      E::NotAFile => false,
      E::IndexFileNotAFile => false,
      E::OutsideBase => false,
      E::IndexFileOutsideBase => false,
      E::CanonicalizeBase(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::CanonicalizeTarget(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileCanonicalizeTarget(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::Metadata(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileMetadata(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::Open(e) => e.kind() == std::io::ErrorKind::NotFound,
      E::IndexFileOpen(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServeStaticOptions<'a> {
  pub index_file: Option<&'a str>,
  pub dotfiles: ServeStaticOptionsDotFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServeStaticOptionsDotFiles {
  Ignore,
  Allow,
  Error,
}

/// parameter path should not have the leading slash
pub async fn resolve(
  base_dir: &str,
  path: &str,
  options: ServeStaticOptions<'_>,
) -> Result<Resolved, ServeStaticError> {
  // remove leading slash
  let base = tokio::fs::canonicalize(base_dir)
    .await
    .map_err(ServeStaticError::CanonicalizeBase)?;

  // dbg!(&base, path);

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
            Some(b'.') => match options.dotfiles {
              ServeStaticOptionsDotFiles::Ignore => return Err(ServeStaticError::DotFilesIgnored),
              ServeStaticOptionsDotFiles::Error => return Err(ServeStaticError::DotFilesError),
              ServeStaticOptionsDotFiles::Allow => {}
            },
            _ => {}
          }
        }
      }
    }

    let target = tokio::fs::canonicalize(base.join(target))
      .await
      .map_err(ServeStaticError::CanonicalizeTarget)?;

    // check if the target file is inside the base directory
    // else return an error
    if !target.starts_with(&base) {
      // dbg!(&base, &target, "base outside target");
      return Err(ServeStaticError::OutsideBase);
    }

    target
  };

  // dbg!(&target);

  let mut metadata = tokio::fs::metadata(&target)
    .await
    .map_err(ServeStaticError::Metadata)?;

  let mut file_type = metadata.file_type();

  let mut is_index_file = false;

  if file_type.is_dir() {
    let index_file = match options.index_file {
      None => return Err(ServeStaticError::Directory),
      Some(index_file) => index_file,
    };

    target.push(index_file);

    target = tokio::fs::canonicalize(target)
      .await
      .map_err(ServeStaticError::IndexFileCanonicalizeTarget)?;

    if !target.starts_with(&base) {
      return Err(ServeStaticError::IndexFileOutsideBase);
    }

    metadata = tokio::fs::metadata(&target)
      .await
      .map_err(ServeStaticError::IndexFileMetadata)?;

    if metadata.is_dir() {
      return Err(ServeStaticError::IndexFileDirectory);
    }

    if !path.is_empty() && !path.ends_with('/') {
      return Ok(Resolved::AppendSlash);
    }

    file_type = metadata.file_type();

    is_index_file = true;
  }

  // dbg!(&metadata);

  if !file_type.is_file() {
    if !is_index_file {
      return Err(ServeStaticError::NotAFile);
    } else {
      return Err(ServeStaticError::IndexFileNotAFile);
    }
  }

  let file = tokio::fs::OpenOptions::new()
    .read(true)
    .open(&target)
    .await
    .map_err(|e| {
      if is_index_file {
        ServeStaticError::IndexFileOpen(e)
      } else {
        ServeStaticError::Open(e)
      }
    })?;

  let resolved = Resolved::Serve {
    path: target,
    metadata,
    file,
  };

  Ok(resolved)
}
