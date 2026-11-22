# 0003: NSS databases are changed through certutil, on Linux only

Status: accepted, 2026-11-22

## Context

Firefox on every platform and Chromium on Linux keep trust in NSS databases (`cert9.db`, `key4.db`, `pkcs11.txt`). The databases are SQLite files whose rows hold PKCS #11 objects with encoded attributes and an integrity scheme defined by NSS. mkcert runs NSS's `certutil` (`truststore_nss.go`).

Options:

1. Run `certutil` from the NSS tools package (`libnss3-tools` on Debian and Ubuntu, `nss-tools` on Fedora, `nss` in Homebrew).
2. Write the SQLite database directly from Rust. That needs an SQLite dependency, a reimplementation of NSS's object encoding, and keeping up with NSS's changes; a bug corrupts the user's browser profile.
3. Avoid NSS: on Linux, load `p11-kit-trust.so` into each profile so Firefox reads the system store. That also needs `modutil`, the module path differs per distribution, and it changes the profile more than adding one certificate.
4. Firefox enterprise policy (`Certificates.Install`). On Linux it reads fixed directories, and `policies.json` sits in the Firefox install directory, which needs root and is replaced by snap and Flatpak packaging.

Also relevant: since Firefox 120 (2023) the pref `security.enterprise_roots.enabled` defaults to true, and Firefox then reads the Windows root stores and the macOS trust settings ([bug 1848815](https://bugzilla.mozilla.org/show_bug.cgi?id=1848815)). There is no packaged NSS `certutil` for Windows, and mkcert does not support NSS there. On Linux, Firefox does not read the system store ([bug 1600509](https://bugzilla.mozilla.org/show_bug.cgi?id=1600509), WONTFIX).

## Decision

Option 1, and only on Linux (including WSL). On Windows and macOS homecert writes no NSS database and relies on enterprise roots; `status` warns if a profile's `prefs.js` turns that pref off.

On Linux homecert finds the NSS databases (`~/.pki/nssdb`, `~/.local/share/pki/nssdb`, the snap paths for Chromium and Firefox, and each Firefox profile), runs `certutil -A -t C,, -n homecert-<fp8>` to add, `certutil -L` to look, and `certutil -D` to remove. If no Chromium database exists, it creates one at `~/.local/share/pki/nssdb`, the default since Chromium 146. If `certutil` is missing, the NSS steps are shown as not possible with the package to install, and the other steps still run.

## Consequences

- No SQLite or NSS code in homecert; NSS stays the only writer of its own files.
- One more package for the user on Linux. The error says which.
- certutil's text output is parsed only for the listing (`-L`), whose format has been stable for many years. Adds and removals are judged by exit code.
- The Windows and macOS paths depend on Mozilla keeping enterprise roots on by default. The pref check in `status` makes a change visible.
- The `C,,` trust flags trust the root for TLS servers only, which is all homecert needs.
