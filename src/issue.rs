//! `homecert issue`: check the names, sign a leaf with the CA in a
//! directory, write the certificate chain and a fresh key.

use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::Error;
use crate::ca::LeafDays;
use crate::files::{Access, CaDir, Overwrite, write_file};
use crate::names::SubjectName;

/// Where `issue` writes the certificate chain and the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    cert: PathBuf,
    key: PathBuf,
}

impl Output {
    /// Explicit paths, like `--cert-file` and `--key-file`.
    pub fn new(cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Self {
        Self {
            cert: cert.as_ref().to_owned(),
            key: key.as_ref().to_owned(),
        }
    }

    /// mkcert's default names in `dir`: the first name, with `*` written as
    /// `_wildcard` and `:` as `_`, then `+<n>` for the other names, so
    /// `app.test localhost 127.0.0.1` gives `app.test+2.pem` and
    /// `app.test+2-key.pem`.
    pub fn default_in(dir: impl AsRef<Path>, names: &[SubjectName]) -> Self {
        let first = names
            .first()
            .map(|name| name.to_string().replace('*', "_wildcard").replace(':', "_"))
            .unwrap_or_default();
        let stem = match names.len() {
            0 | 1 => first,
            n => format!("{first}+{}", n - 1),
        };
        let dir = dir.as_ref();
        Self {
            cert: dir.join(format!("{stem}.pem")),
            key: dir.join(format!("{stem}-key.pem")),
        }
    }

    /// The certificate chain file.
    #[must_use]
    pub fn cert(&self) -> &Path {
        &self.cert
    }

    /// The key file.
    #[must_use]
    pub fn key(&self) -> &Path {
        &self.key
    }
}

/// Issues a leaf for `names` from the CA in `ca_dir`. Every name is checked
/// before anything is signed or written. The key is written owner-only and
/// never over an existing file; the certificate chain replaces an existing
/// file.
///
/// # Errors
///
/// [`Error::Refused`] for a name outside the CA's constraints, with nothing
/// written; [`Error::Exists`] if the key file exists; otherwise the errors of
/// [`CaDir::load`], [`crate::ca::Ca::issue`] and [`write_file`].
pub fn issue(
    ca_dir: &CaDir,
    names: &[SubjectName],
    output: &Output,
    days: LeafDays,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let leaf = ca_dir.load()?.issue(names, days, now)?;
    write_file(
        &output.key,
        leaf.key_pem().as_bytes(),
        Access::OwnerOnly,
        Overwrite::Refuse,
    )?;
    write_file(
        &output.cert,
        leaf.chain_pem().as_bytes(),
        Access::Public,
        Overwrite::Replace,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use crate::files::test_support::{TempDir, owner_only};
    use crate::names::Constraints;

    fn names(list: &[&str]) -> Vec<SubjectName> {
        list.iter()
            .map(|n| SubjectName::parse(n).unwrap())
            .collect()
    }

    /// A CA made by the test helper, as M1 asks: no `install` exists yet.
    fn ca_dir(tmp: &TempDir) -> CaDir {
        let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
        CaDir::create(tmp.path().join("ca"), &ca).unwrap()
    }

    #[test]
    fn default_file_names_follow_mkcert() {
        let out = Output::default_in("out", &names(&["app.test", "localhost", "127.0.0.1"]));
        assert_eq!(out.cert(), Path::new("out").join("app.test+2.pem"));
        assert_eq!(out.key(), Path::new("out").join("app.test+2-key.pem"));
        let out = Output::default_in("", &names(&["*.app.test"]));
        assert_eq!(out.cert(), Path::new("_wildcard.app.test.pem"));
        let out = Output::default_in("", &names(&["::1"]));
        assert_eq!(out.key(), Path::new("__1-key.pem"));
    }

    #[test]
    fn issue_writes_the_chain_and_an_owner_only_key() {
        let tmp = TempDir::new();
        let dir = ca_dir(&tmp);
        let list = names(&["app.test", "localhost", "127.0.0.1"]);
        let out = Output::default_in(tmp.path(), &list);
        issue(
            &dir,
            &list,
            &out,
            LeafDays::default(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();

        let chain = std::fs::read_to_string(out.cert()).unwrap();
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(chain.ends_with(&std::fs::read_to_string(dir.path().join("issuer.pem")).unwrap()));
        assert!(
            std::fs::read_to_string(out.key())
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
        owner_only(out.key(), 0o600).unwrap();
    }

    #[test]
    fn a_name_outside_the_constraints_is_refused_and_nothing_is_written() {
        let tmp = TempDir::new();
        let dir = ca_dir(&tmp);
        let list = names(&["app.test", "example.com"]);
        let out = Output::default_in(tmp.path(), &list);
        let err = issue(
            &dir,
            &list,
            &out,
            LeafDays::default(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(&err, Err(Error::Refused(SubjectName::Dns(n))) if n.as_str() == "example.com")
        );
        assert!(!out.cert().exists());
        assert!(!out.key().exists());
    }

    #[test]
    fn an_existing_key_file_is_not_overwritten() {
        let tmp = TempDir::new();
        let dir = ca_dir(&tmp);
        let list = names(&["app.test"]);
        let out = Output::default_in(tmp.path(), &list);
        std::fs::write(out.key(), b"keep me").unwrap();
        let err = issue(
            &dir,
            &list,
            &out,
            LeafDays::default(),
            OffsetDateTime::now_utc(),
        );
        assert!(matches!(err, Err(Error::Exists(_))));
        assert_eq!(std::fs::read(out.key()).unwrap(), b"keep me");
    }
}
