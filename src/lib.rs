//! homecert: locally trusted HTTPS certificates for development, from a root
//! that can only sign for local names.
//!
//! The library holds the modules from `docs/design.md`; the binary is a thin
//! front end. Built so far (milestone M1): [`names`], [`ca`], [`files`] and
//! [`issue`].

use std::fmt;
use std::path::{Path, PathBuf};

pub mod ca;
pub mod files;
pub mod issue;
pub mod names;

use names::SubjectName;

/// Everything that can go wrong outside [`names::NameError`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A name outside the CA's constraints. Nothing was written.
    Refused(SubjectName),
    /// `issue` was given no names.
    NoNames,
    /// A leaf validity outside 1 to 825 days.
    LeafDays(u16),
    /// rcgen could not build or sign a certificate.
    Certificate(rcgen::Error),
    /// The system random source failed.
    Random,
    /// A file did not hold what it should; the text says which.
    Parse(&'static str),
    /// The file exists and was not overwritten.
    Exists(PathBuf),
    /// A file operation failed.
    Io {
        /// The file or directory.
        path: PathBuf,
        /// What the OS said.
        source: std::io::Error,
    },
    /// Owner-only permissions could not be set or read.
    Permissions(String),
}

impl Error {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(name) => write!(f, "{name} is outside the names this root may sign for"),
            Self::NoNames => f.write_str("no names to issue a certificate for"),
            Self::LeafDays(days) => {
                write!(f, "{days} days is outside 1 to {} days", ca::LeafDays::MAX)
            }
            Self::Certificate(e) => write!(f, "cannot build the certificate: {e}"),
            Self::Random => f.write_str("the system random source failed"),
            Self::Parse(what) => write!(f, "cannot read {what}"),
            Self::Exists(path) => write!(f, "{} exists and was not overwritten", path.display()),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Permissions(text) => write!(f, "cannot set owner-only permissions: {text}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(e) => Some(e),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<rcgen::Error> for Error {
    fn from(e: rcgen::Error) -> Self {
        Self::Certificate(e)
    }
}
