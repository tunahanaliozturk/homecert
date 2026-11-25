//! The CA directory, owner-only files and atomic writes.
//!
//! On Unix a private file is created with mode 0600 and the CA directory with
//! 0700, so neither ever exists with wider permissions. On Windows the file or
//! directory gets a protected DACL with one entry, full control for the
//! current user's SID, set with `icacls` before any secret is written; a file
//! is held open with share mode 0 until then, so no one else can open it.
//!
//! Every write goes to a temporary file in the target directory, is flushed,
//! and is then moved into place.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Error;
use crate::ca::Ca;

/// The root certificate. Public.
pub const ROOT_FILE: &str = "root.pem";
/// The intermediate certificate. Public.
pub const ISSUER_FILE: &str = "issuer.pem";
/// The intermediate's key. Owner-only.
pub const ISSUER_KEY_FILE: &str = "issuer-key.pem";

/// What to do when the target file already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// Fail with [`Error::Exists`] and leave the file alone.
    Refuse,
    /// Replace the file.
    Replace,
}

/// Who may read a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Only the current user (mode 0600, or a one-entry DACL on Windows).
    OwnerOnly,
    /// Anyone (mode 0644 on Unix; inherited permissions on Windows).
    Public,
}

/// A CA directory: `root.pem`, `issuer.pem` and `issuer-key.pem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaDir {
    path: PathBuf,
}

impl CaDir {
    /// Refers to an existing CA directory. Nothing is read until
    /// [`CaDir::load`].
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }

    /// Creates the directory owner-only and writes `ca` into it. Parent
    /// directories are created with default permissions.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the directory already exists or a write fails, and
    /// [`Error::Permissions`] if the Windows DACL cannot be set.
    pub fn create(path: impl AsRef<Path>, ca: &Ca) -> Result<Self, Error> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        create_owner_only_dir(path)?;
        let dir = Self::open(path);
        write_file(
            dir.file(ROOT_FILE),
            ca.root_pem().as_bytes(),
            Access::Public,
            Overwrite::Refuse,
        )?;
        write_file(
            dir.file(ISSUER_FILE),
            ca.issuer_pem().as_bytes(),
            Access::Public,
            Overwrite::Refuse,
        )?;
        write_file(
            dir.file(ISSUER_KEY_FILE),
            ca.issuer_key_pem().as_bytes(),
            Access::OwnerOnly,
            Overwrite::Refuse,
        )?;
        Ok(dir)
    }

    /// Reads the CA from the directory.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a file cannot be read, [`Error::Parse`] if its content
    /// is not what it should be.
    pub fn load(&self) -> Result<Ca, Error> {
        let read = |name| {
            let path = self.file(name);
            fs::read_to_string(&path).map_err(|e| Error::io(&path, e))
        };
        Ca::from_pem(
            &read(ROOT_FILE)?,
            &read(ISSUER_FILE)?,
            &read(ISSUER_KEY_FILE)?,
        )
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

/// Writes `bytes` to `path` atomically: a temporary file next to it, with the
/// final permissions set before anything is written, then moved into place.
///
/// # Errors
///
/// [`Error::Exists`] if `path` exists and `overwrite` is [`Overwrite::Refuse`];
/// [`Error::Io`] or [`Error::Permissions`] if a step fails. The temporary file
/// is removed on failure.
pub fn write_file(
    path: impl AsRef<Path>,
    bytes: &[u8],
    access: Access,
    overwrite: Overwrite,
) -> Result<(), Error> {
    let path = path.as_ref();
    if overwrite == Overwrite::Refuse && path.exists() {
        return Err(Error::Exists(path.to_owned()));
    }
    let (tmp, mut file) = create_temp(path, access)?;
    let result = fill(&mut file, &tmp, bytes);
    drop(file);
    let result = result.and_then(|()| place(&tmp, path, overwrite));
    if result.is_err() {
        fs::remove_file(&tmp).ok();
    }
    result
}

/// Creates a fresh temporary file next to `path`. A name that already exists
/// belongs to someone else, so it is left alone and the next number is tried,
/// up to 16 times.
fn create_temp(path: &Path, access: Access) -> Result<(PathBuf, File), Error> {
    const RETRIES: u32 = 16;
    let mut retries = 0;
    loop {
        let tmp = temp_path(path);
        match create_new(&tmp, access) {
            Err(Error::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists && retries < RETRIES =>
            {
                retries += 1;
            }
            result => return result.map(|file| (tmp, file)),
        }
    }
}

fn fill(file: &mut File, tmp: &Path, bytes: &[u8]) -> Result<(), Error> {
    file.write_all(bytes).map_err(|e| Error::io(tmp, e))?;
    file.sync_all().map_err(|e| Error::io(tmp, e))
}

/// Moves the finished temporary file to `path`. Refusing to overwrite uses a
/// hard link, which fails if `path` exists, so a file created since the check
/// in [`write_file`] is not replaced either.
// ponytail: hard links need a file system that has them (NTFS, ext4, APFS);
// on FAT and some network shares the write fails, and `link_error` says that
// a hard link was the cause.
fn place(tmp: &Path, path: &Path, overwrite: Overwrite) -> Result<(), Error> {
    match overwrite {
        Overwrite::Replace => fs::rename(tmp, path).map_err(|e| Error::io(path, e)),
        Overwrite::Refuse => {
            fs::hard_link(tmp, path).map_err(|e| link_error(path, &e))?;
            // The file is in place now. A temporary name left behind is
            // untidy, not a failed write.
            fs::remove_file(tmp).ok();
            Ok(())
        }
    }
}

/// The error for a failed hard link. Any failure other than an existing
/// target names the hard link, because on a file system without them (FAT,
/// some network shares) the OS error alone, such as "unsupported" or "access
/// denied", does not say what homecert tried to do.
///
/// There is deliberately no fallback to creating the target directly: that
/// would write the key under its final name a piece at a time, so a crash or
/// a full disk would leave a partial key there, which a rerun then refuses to
/// replace. An error that points at the cause lets the user pick another
/// directory instead.
fn link_error(path: &Path, e: &std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::AlreadyExists => Error::Exists(path.to_owned()),
        kind => Error::io(
            path,
            std::io::Error::new(
                kind,
                format!(
                    "cannot create a hard link ({e}); homecert writes a file it must not \
                     replace through a hard link, which this file system may not support"
                ),
            ),
        ),
    }
}

/// Numbers the temporary names this process makes.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(path: &Path) -> PathBuf {
    temp_name(path, TEMP_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn temp_name(path: &Path, n: u64) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.{}-{n}.tmp", std::process::id()))
}

/// Creates the empty temporary file with its final permissions: the mode on
/// Unix, the DACL on Windows, before any byte is written.
#[cfg(unix)]
fn create_new(path: &Path, access: Access) -> Result<File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let mode = match access {
        Access::OwnerOnly => 0o600,
        Access::Public => 0o644,
    };
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| Error::io(path, e))
}

/// See the Unix version. Until `icacls` has run, the file has the
/// directory's inherited permissions, so it is opened with share mode 0:
/// while the writer holds it, every other open fails with a sharing
/// violation, and no handle can be opened early to read what is written
/// later. `icacls` still works, because changing the DACL is not a read or
/// a write of the file's data.
#[cfg(windows)]
fn create_new(path: &Path, access: Access) -> Result<File, Error> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    if access == Access::OwnerOnly
        && let Err(e) = windows::restrict(path, "F")
    {
        // Windows cannot delete a file that is still open.
        drop(file);
        fs::remove_file(path).ok();
        return Err(e);
    }
    Ok(file)
}

#[cfg(unix)]
fn create_owner_only_dir(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| Error::io(path, e))
}

#[cfg(windows)]
fn create_owner_only_dir(path: &Path) -> Result<(), Error> {
    fs::create_dir(path).map_err(|e| Error::io(path, e))?;
    windows::restrict(path, "(OI)(CI)F").inspect_err(|_| {
        fs::remove_dir(path).ok();
    })
}

#[cfg(windows)]
pub(crate) mod windows {
    //! The DACL through the system's own tools, so the crate stays free of
    //! `unsafe`. The SID is used instead of the account name, so the output's
    //! language does not matter.

    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use crate::Error;

    /// `%SystemRoot%\System32\<exe>`, so a program of the same name earlier
    /// on `PATH` is not run instead.
    pub(crate) fn system32(exe: &str) -> Result<PathBuf, Error> {
        system32_in(std::env::var_os("SystemRoot"), exe)
    }

    /// [`system32`] with the value of `SystemRoot` passed in.
    pub(crate) fn system32_in(
        root: Option<std::ffi::OsString>,
        exe: &str,
    ) -> Result<PathBuf, Error> {
        let root = PathBuf::from(
            root.ok_or_else(|| Error::Permissions("SystemRoot is not set".to_owned()))?,
        );
        if !root.is_absolute() {
            return Err(Error::Permissions(format!(
                "SystemRoot is not an absolute path: {:?}",
                root.display().to_string()
            )));
        }
        Ok(root.join("System32").join(exe))
    }

    /// The current user's SID, from `whoami /user /fo csv /nh`, whose output
    /// is `"DOMAIN\user","S-1-5-..."`.
    pub(crate) fn current_user_sid() -> Result<String, Error> {
        let output = Command::new(system32("whoami.exe")?)
            .args(["/user", "/fo", "csv", "/nh"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Permissions(format!("cannot run whoami: {e}")))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let sid = text
            .trim()
            .rsplit(',')
            .next()
            .unwrap_or_default()
            .trim_matches('"');
        if !output.status.success() || !sid.starts_with("S-1-") {
            return Err(Error::Permissions(format!(
                "cannot read the user's SID from whoami: {text}"
            )));
        }
        Ok(sid.to_owned())
    }

    /// Removes inherited entries and grants `rights` to the current user
    /// only.
    pub(crate) fn restrict(path: &Path, rights: &str) -> Result<(), Error> {
        let sid = current_user_sid()?;
        let output = Command::new(system32("icacls.exe")?)
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("*{sid}:{rights}"))
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::Permissions(format!("cannot run icacls: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::Permissions(format!(
                "icacls failed on {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stdout).trim()
            )))
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A temporary directory and an owner-only check that does not share code
    //! with the writer above.

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh directory under the system temp directory, removed on drop.
    #[derive(Debug)]
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("homecert-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Whether only the owner may access `path`: on Unix, no group or other
    /// bits; on Windows, a protected DACL whose every entry is the current
    /// user's SID. Returns a description of what is wrong.
    #[cfg(unix)]
    pub(crate) fn owner_only(path: &Path, expected_mode: u32) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        if mode == expected_mode {
            Ok(())
        } else {
            Err(format!("mode {mode:o}"))
        }
    }

    /// See the Unix version. Reads the ACL back with PowerShell `Get-Acl`.
    #[cfg(windows)]
    pub(crate) fn owner_only(path: &Path, _expected_mode: u32) -> Result<(), String> {
        let script = "$a = Get-Acl -LiteralPath $env:HOMECERT_ACL_PATH; \
            'protected ' + $a.AreAccessRulesProtected; \
            $a.Access | ForEach-Object { 'sid ' + \
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }";
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("HOMECERT_ACL_PATH", path)
            // A module path inherited from PowerShell 7 makes Windows
            // PowerShell load the wrong security module, and `Get-Acl` then
            // fails without a failing exit code.
            .env_remove("PSModulePath")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && errors.trim().is_empty(),
            "Get-Acl failed: {text} {errors}"
        );
        let user = super::windows::current_user_sid().unwrap();
        let sids: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("sid "))
            .collect();
        let protected = text.lines().any(|l| l.trim() == "protected True");
        if protected && !sids.is_empty() && sids.iter().all(|sid| *sid == user) {
            Ok(())
        } else {
            Err(format!("ACL of {}: {}", path.display(), text.trim()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{TempDir, owner_only};
    use super::*;
    use crate::names::Constraints;

    fn new_ca() -> Ca {
        Ca::create(Constraints::local(), time::OffsetDateTime::now_utc()).unwrap()
    }

    #[test]
    fn the_ca_directory_and_issuer_key_are_owner_only() {
        let tmp = TempDir::new();
        let dir = CaDir::create(tmp.path().join("ca"), &new_ca()).unwrap();
        owner_only(dir.path(), 0o700).unwrap();
        owner_only(&dir.path().join(ISSUER_KEY_FILE), 0o600).unwrap();
    }

    #[test]
    fn a_private_file_outside_the_ca_directory_is_owner_only() {
        let tmp = TempDir::new();
        let path = tmp.path().join("app.test-key.pem");
        write_file(&path, b"secret", Access::OwnerOnly, Overwrite::Refuse).unwrap();
        owner_only(&path, 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    /// Between creating a file and `icacls`, the file has the directory's
    /// inherited permissions. A handle opened then would read every byte
    /// written later, so nobody may open the file while the writer holds it.
    #[cfg(windows)]
    #[test]
    fn no_one_can_open_a_file_while_it_is_being_written() {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        let tmp = TempDir::new();
        let path = tmp.path().join("app.test-key.pem");
        let held = create_new(&path, Access::OwnerOnly).unwrap();
        for open in [
            OpenOptions::new().read(true).open(&path),
            OpenOptions::new().write(true).open(&path),
        ] {
            let err = open.unwrap_err();
            assert_eq!(err.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{err}");
        }
        drop(held);
        assert!(File::open(&path).is_ok());
    }

    /// Once the hard link is made the file is in place; a temporary name that
    /// cannot be removed must not turn that into an error. Windows refuses to
    /// delete a file that is open without delete sharing, which makes the
    /// removal fail on demand.
    #[cfg(windows)]
    #[test]
    fn a_temporary_file_that_cannot_be_removed_does_not_fail_the_write() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        let dir = TempDir::new();
        let (temp, path) = (dir.path().join("t.tmp"), dir.path().join("key.pem"));
        fs::write(&temp, b"secret").unwrap();
        let _pin = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&temp)
            .unwrap();
        place(&temp, &path, Overwrite::Refuse).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn a_taken_temporary_name_is_skipped() {
        let dir = TempDir::new();
        let path = dir.path().join("key.pem");
        // Someone else holds the next few temporary names.
        let next = TEMP_COUNTER.load(Ordering::Relaxed);
        let taken: Vec<_> = (next..next + 4).map(|n| temp_name(&path, n)).collect();
        for squatter in &taken {
            fs::write(squatter, b"not ours").unwrap();
        }
        write_file(&path, b"secret", Access::OwnerOnly, Overwrite::Refuse).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        for squatter in &taken {
            assert_eq!(fs::read(squatter).unwrap(), b"not ours");
        }
    }

    #[test]
    fn a_failed_hard_link_says_so() {
        let path = Path::new("key.pem");
        let exists = link_error(path, &std::io::ErrorKind::AlreadyExists.into());
        assert!(matches!(exists, Error::Exists(_)), "{exists}");
        // FAT and some network shares have no hard links.
        let unsupported = link_error(path, &std::io::ErrorKind::Unsupported.into()).to_string();
        assert!(unsupported.contains("hard link"), "{unsupported}");
    }

    /// An empty or relative `SystemRoot` would make `icacls` and `whoami`
    /// resolve against the current directory.
    #[cfg(windows)]
    #[test]
    fn system_root_must_be_an_absolute_path() {
        use super::windows::system32_in;
        for root in [None, Some(""), Some("Windows"), Some(r"..\Windows")] {
            let result = system32_in(root.map(Into::into), "icacls.exe");
            assert!(
                matches!(result, Err(Error::Permissions(_))),
                "{root:?}: {result:?}"
            );
        }
        assert_eq!(
            system32_in(Some(r"C:\Windows".into()), "icacls.exe").unwrap(),
            Path::new(r"C:\Windows\System32\icacls.exe")
        );
    }

    #[test]
    fn the_owner_only_check_rejects_a_plainly_written_file() {
        // The control: without this the check above could pass for anything.
        let tmp = TempDir::new();
        let path = tmp.path().join("plain.pem");
        fs::write(&path, b"x").unwrap();
        assert!(owner_only(&path, 0o600).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn certificates_are_written_world_readable() {
        let tmp = TempDir::new();
        let dir = CaDir::create(tmp.path().join("ca"), &new_ca()).unwrap();
        owner_only(&dir.path().join(ROOT_FILE), 0o644).unwrap();
        owner_only(&dir.path().join(ISSUER_FILE), 0o644).unwrap();
    }

    #[test]
    fn an_existing_file_is_not_overwritten_and_no_temporary_file_is_left() {
        let tmp = TempDir::new();
        let path = tmp.path().join("key.pem");
        fs::write(&path, b"old").unwrap();
        let err = write_file(&path, b"new", Access::OwnerOnly, Overwrite::Refuse).unwrap_err();
        assert!(matches!(err, Error::Exists(_)), "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"old");
        write_file(&path, b"new", Access::Public, Overwrite::Replace).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let names: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["key.pem"]);
    }

    #[test]
    fn an_existing_ca_directory_is_not_reused() {
        let tmp = TempDir::new();
        let path = tmp.path().join("ca");
        CaDir::create(&path, &new_ca()).unwrap();
        assert!(CaDir::create(&path, &new_ca()).is_err());
    }

    #[test]
    fn a_ca_reads_back_with_its_constraints() {
        let tmp = TempDir::new();
        let ca = new_ca();
        let dir = CaDir::create(tmp.path().join("ca"), &ca).unwrap();
        let loaded = dir.load().unwrap();
        assert_eq!(loaded.constraints(), &Constraints::local());
        assert_eq!(loaded.root_pem(), ca.root_pem());
        assert_eq!(loaded.issuer_key_pem(), ca.issuer_key_pem());
    }
}
