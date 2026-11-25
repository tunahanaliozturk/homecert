# homecert design

This document is the contract for the build. Code that disagrees with it is a bug in one of the two, and the fix says which. Facts were checked on 2026-11-22; anything that could not be checked is under [Open questions](#open-questions), not stated as fact.

## The problem and who has it

A developer runs a web application on their own machine and needs it served over HTTPS that the browser accepts without a warning. OAuth providers want an `https` callback, `Secure` cookies and service workers need a secure context, and HTTP/2 in browsers needs TLS. Self-signed leaf certificates produce warnings, and clicking through them hides the bugs that real TLS would show.

The common answer is mkcert: it creates a root, adds it to the machine's trust stores and issues leaf certificates. Its problems, with sources, are in the [README](../README.md#the-problem). In short:

1. It is unmaintained: no code change since 2022-04-26 and no answer to the maintenance issue opened 2026-05-13.
2. Its root can sign for any name, so the root key file is as valuable as a key that can impersonate every site to that machine. The key sits in a user directory that ends up in backups, dotfiles and container images.
3. The weak spots people hit are Windows with WSL, headless CI runners that have never started a browser, and an automatic `sudo` fallback that surprises people.

The users are web developers on Windows (often with WSL), macOS and Linux, and the CI jobs that run their end-to-end tests. They want one command that works, and they want to know what it changed.

The core job is small. homecert is worth having for three reasons: the constrained root, platform coverage that includes WSL and headless runners, and someone maintaining it.

## Goals

1. A certificate from homecert is accepted for its names by the browsers and runtimes a developer uses, on Windows, WSL, macOS, Debian or Ubuntu, and Fedora.
2. The key that exists on disk can only sign for the names the user chose (local names by default), in every consumer that enforces name constraints in an intermediate certificate. That includes Java, which ignores them in a root.
3. Every trust store change is listed before it is made, needs a yes, and is undone by `homecert uninstall`. `uninstall` leaves each store as it was before `install`.
4. homecert never raises its privileges without the user confirming the exact command.
5. Private keys are readable by their owner only, on every platform.
6. A user can move from mkcert by changing command names in their scripts.

## Non-goals

- An ACME server, a GUI, profiles for phones, a background service.
- Importing or reusing mkcert's root.
- PKCS#12 output, client certificates and S/MIME in the first release.
- Protection against code already running as the user. Such code can read the issuing key and can add its own root to the user's stores.
- Trust stores other than those listed under [Platform support](#platform-support), for example Arch, openSUSE, Alpine, or Android.

## The user's view

### Commands

```
homecert install   [--name <dns>]... [--ip <cidr>]... [--no-default-names]
                   [--store <id>]... [--yes] [--dry-run]
homecert issue     <name>... [--cert-file <path>] [--key-file <path>] [--days <n>]
homecert status
homecert uninstall [--store <id>]... [--yes] [--dry-run] [--keep-files]
homecert rotate    [--name <dns>]... [--ip <cidr>]... [--no-default-names] [--yes] [--dry-run]
homecert snippet   docker | env [--shell sh|powershell]
homecert --version | --help
```

- `install` creates the CA if there is none, then adds the root to the selected stores. Running it again adds the root to any selected store that lacks it and changes nothing else.
- `issue` writes a leaf certificate and a fresh key. The certificate file holds the leaf followed by the intermediate, like a `fullchain.pem`.
- `status` reads, never writes. It shows the root, its constraints, its expiry, each store and whether the root is trusted there, and any mkcert root it finds.
- `uninstall` removes every homecert root, current and retired, from the selected stores (all known stores by default), then deletes the CA directory unless `--keep-files` is given.
- `rotate` creates a new CA (with new constraints if given), trusts it everywhere the old one was trusted, then removes the old one. Leaves issued by the old CA stop working once the old root is gone; `rotate` says so before it asks.
- `snippet` prints text and changes nothing.

`--name` and `--ip` add to the default list; `--no-default-names` starts from an empty list. A `--name` is a DNS name without a leading dot or wildcard: `--name corp.example` permits `corp.example` and every name under it.

Store ids: `windows-user`, `windows-machine`, `macos-user`, `macos-admin`, `system` (the Linux system store), `nss`, `java`, and `windows-from-wsl`. The defaults per platform are in [Platform support](#platform-support). `java`, `windows-machine` and `macos-admin` are never selected unless named.

Commands keep mkcert's shapes where they map: `mkcert -install` becomes `homecert install`, `mkcert app.test localhost 127.0.0.1` becomes `homecert issue app.test localhost 127.0.0.1`, and the default output names are the same (`./app.test+2.pem`, `./app.test+2-key.pem`), as are `--cert-file` and `--key-file`.

### Files

The CA directory is `$HOMECERT_DIR` if set, otherwise:

| Platform | Default |
| --- | --- |
| Linux, WSL | `$XDG_DATA_HOME/homecert`, or `~/.local/share/homecert` |
| macOS | `~/Library/Application Support/homecert` |
| Windows | `%LOCALAPPDATA%\homecert` |

It holds `root.pem` (the root certificate, no key), `issuer.pem` and `issuer-key.pem` (the intermediate and its key, owner-only), and `retired/` (certificates of earlier roots, kept so that `uninstall` can remove them). There is no other state file: the constraints are read from `root.pem` itself, and which stores trust the root is found by looking.

### Example session

```
$ homecert install
homecert will create a new root and trust it in these places.

  root       homecert root 2026-11-22 7c1e, expires 2031-11-21
  names      localhost, test, internal, home.arpa, and every name under them
  addresses  127.0.0.0/8, ::1/128

  1. create  ~/.local/share/homecert (owner-only)
  2. add     system store, Debian family                       needs root
             sudo install -m 0644 /home/ana/.local/share/homecert/root.pem /usr/local/share/ca-certificates/homecert-3f9a1c2e.crt
             sudo update-ca-certificates
  3. add     NSS ~/.pki/nssdb (Chromium)
             certutil -A -d sql:/home/ana/.pki/nssdb -t C,, -n homecert-3f9a1c2e -i /home/ana/.local/share/homecert/root.pem
  4. add     NSS Firefox profile 8x2k1q.default-release
             certutil -A -d sql:/home/ana/.mozilla/firefox/8x2k1q.default-release -t C,, -n homecert-3f9a1c2e -i ...

Undo all of it with: homecert uninstall
Continue? [y/N] y
...
done: trusted in 3 of 3 places.
```

```
$ homecert issue app.test localhost 127.0.0.1
wrote ./app.test+2.pem       leaf and intermediate, valid until 2027-11-22
wrote ./app.test+2-key.pem   owner-only

$ homecert issue example.com
error: example.com is outside the names this root may sign for
       (localhost, test, internal, home.arpa, 127.0.0.0/8, ::1/128).
       Browsers that enforce name constraints would reject the certificate.
       To allow it, make a new root: homecert rotate --name example.com
$ echo $?
3

$ homecert issue '*.test'
error: *.test is a wildcard directly under a top-level name. Chrome and
       Firefox reject such certificates. Use a name like *.app.test.
```

```
$ homecert status
root       homecert root 2026-11-22 7c1e (sha256 3f9a1c2e...), expires 2031-11-21
issuer     ~/.local/share/homecert/issuer.pem, key owner-only: yes
names      localhost, test, internal, home.arpa, and every name under them
addresses  127.0.0.0/8, ::1/128

trusted in
  yes  system store, Debian family
  yes  NSS ~/.pki/nssdb (Chromium)
  no   NSS Firefox profile 8x2k1q.default-release    fix: homecert install
  -    Java keystore                                 not selected

other roots
  warn mkcert development CA, unconstrained: system store, NSS ~/.pki/nssdb
       remove it with: mkcert -uninstall
$ echo $?
4
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. For `status`: the root is trusted in every default store and does not expire within 60 days. |
| 1 | An operation failed. The message names the step, what was already done, and how to undo it. |
| 2 | Usage error. |
| 3 | `issue` refused a name. Nothing was written. |
| 4 | `status` found a problem: no CA, a default store without the root, expiry within 60 days, or an unconstrained root such as mkcert's. |
| 5 | A confirmation was needed and not given: the user said no, or there is no terminal and no `--yes`. Nothing was changed. |

## Architecture

One package with a library target that holds the modules and a thin binary that calls them. The library target exists so that tests can reach every module, including the test-only `Ca::issue_unchecked`; nothing is published as a library. Modules, with what is pure and what does I/O:

| Module | Job | I/O |
| --- | --- | --- |
| `names` | The name rules: parse and normalise DNS names and IP addresses, decide whether a name is inside a constraint list, refuse unusable wildcards. | None |
| `ca` | Build the root, intermediate and leaf with rcgen. Read certificates back with x509-parser. Fingerprints. | None; takes and returns bytes |
| `files` | The CA directory, owner-only files, atomic writes. | Files |
| `stores` | One `Store` implementation per kind of trust store: `contains`, `add`, `remove`, `list_foreign`. | Platform APIs and tools |
| `probe` | Find out what exists on this machine: OS family, WSL and interop, NSS databases, certutil, `JAVA_HOME`, `sudo`. Returns a `Machine` value. | Reads files, environment |
| `plan` | Turn a command, the `Machine` and the current store state into a `Plan`: a list of `Step`s. | None |
| `apply` | Show the plan, ask, run the steps in order, stop at the first failure and report. | Terminal, runs steps |
| `cli` | Parse arguments with lexopt, print, map errors to exit codes. | Terminal |

Data flow for `install`: `cli` parses, `probe` builds a `Machine`, each selected `Store` reports `contains(fingerprint)`, `plan` produces the steps that are missing, `apply` prints them and asks, then runs them. `uninstall`, `rotate` and `status` follow the same path; `status` stops after the report.

### Main types

```rust
pub struct Constraints { dns: Vec<DnsName>, ip: Vec<IpNet> }   // what the root permits
pub struct DnsName(String);          // lower case, no trailing dot, A-labels only
pub enum   SubjectName { Dns(DnsName), Wildcard(DnsName), Ip(IpAddr) }
pub struct Fingerprint([u8; 32]);    // SHA-256 of the certificate DER
pub struct Ca { root: CertDer, issuer: CertDer, issuer_key: KeyPem, constraints: Constraints }

pub enum   StoreId { WindowsUser, WindowsMachine, MacosUser, MacosAdmin, System(LinuxFamily),
                     Nss(PathBuf), Java(PathBuf), WindowsFromWsl }
pub enum   Privilege { User, Root, Desktop }     // Desktop: the OS shows a dialog
pub struct Step { store: StoreId, action: Action, privilege: Privilege, shown: Vec<String> }
pub enum   Action { CreateCa, Add(Fingerprint), Remove(Fingerprint), DeleteCaDir }
pub struct Plan { steps: Vec<Step> }

pub trait Store {
    fn id(&self) -> StoreId;
    fn contains(&self, fp: &Fingerprint) -> Result<bool, StoreError>;
    fn add(&self, root: &CertDer) -> Result<(), StoreError>;
    fn remove(&self, fp: &Fingerprint) -> Result<(), StoreError>;
    fn foreign_roots(&self) -> Result<Vec<ForeignRoot>, StoreError>; // mkcert and others
}
```

`Step::shown` is the text the user sees, and for steps run as a command it is the exact command line that `apply` runs. A test compares the two, so the plan cannot drift from what is executed.

`names::permits(&Constraints, &SubjectName) -> bool` is the one function that decides whether a name may be issued. `issue` calls it before signing. It follows RFC 5280 section 4.2.1.10: a DNS constraint `test` permits `test` and any name made by adding labels on the left, compared label by label, so `xtest` and `test.evil` are outside it. A wildcard `*.a.test` is checked as `a.test`. An IP address must fall inside one of the IP ranges, and an IPv4-mapped IPv6 address such as `::ffff:127.0.0.1` is treated as IPv6 and refused unless an IPv6 range covers it.

A constraint list needs at least one DNS name. An empty IP list means no address may be issued, and is written into the certificates as an excluded subtree covering all IPv4 and IPv6 addresses, because a permitted list restricts only names of its own type ([ADR 0006](adr/0006-empty-ip-list-is-excluded.md)).

### The certificates

All keys are ECDSA P-256, made by rcgen with ring. ring cannot generate RSA keys ([rcgen](https://github.com/rustls/rcgen) 0.14.10 returns `KeyGenerationUnavailable` for RSA without aws-lc-rs), and every consumer in scope accepts P-256.

| | Root | Intermediate (issuer) | Leaf |
| --- | --- | --- | --- |
| Subject CN | `homecert root <date> <4 random hex>` | `homecert issuer <date> <4 random hex>` | first DNS name in the request; with only IP addresses, no CN and `O=homecert` ([ADR 0007](adr/0007-leaf-common-name.md)) |
| Validity | 5 years | same as the root | 365 days by default, at most 825 |
| Basic constraints | CA, path length 1 | CA, path length 0 | not a CA |
| Key usage | certificate sign, CRL sign | certificate sign, CRL sign | digital signature |
| Extended key usage | none | server auth | server auth |
| Name constraints | yes, critical; an empty IP list adds an excluded subtree for all addresses | yes, critical, the same list | none |
| Subject alternative names | none | none | every requested name |
| Key stored | **never** | `issuer-key.pem`, owner-only | `<name>-key.pem`, owner-only |

The subject names carry no user or host name, unlike mkcert's, because the root certificate gets copied into container images and shared repositories.

The 825-day cap on leaves follows Apple's rule for TLS server certificates ([Apple, HT210176, now 103769](https://support.apple.com/en-us/103769)). Whether that rule applies to user-added roots is not confirmed; the cap costs nothing, so it stays.

The root key is created in memory, signs the intermediate, and is dropped. See [ADR 0002](adr/0002-discard-the-root-key.md). The name constraints are marked critical; rcgen always does that, and [ADR 0001](adr/0001-critical-name-constraints.md) records why that is also the right choice.

### Trust stores

| Store id | Mechanism | Privilege |
| --- | --- | --- |
| `windows-user` | `CurrentUser\Root` through the `schannel` crate (`CertStore::open_current_user("Root")`, `add_cert`, `CertContext::delete`) | User, and Windows shows a confirmation dialog |
| `windows-machine` | `LocalMachine\Root`, same crate | An elevated process; homecert does not elevate itself |
| `macos-user` | `/usr/bin/security add-trusted-cert -r trustRoot -k <login keychain>`, `remove-trusted-cert`, `find-certificate -a -Z` | User, and macOS asks for the password in a dialog |
| `macos-admin` | the same with `-d` and the System keychain | Root and an administrator password |
| `system` (Debian family) | copy to `/usr/local/share/ca-certificates/homecert-<fp8>.crt`, `update-ca-certificates` | Root |
| `system` (Fedora family) | copy to `/etc/pki/ca-trust/source/anchors/homecert-<fp8>.pem`, `update-ca-trust extract` | Root |
| `nss` | `certutil -A`, `-D`, `-L` on each NSS database, `-t C,,` | User |
| `java` | `keytool -importcert -cacerts` / `-delete` with the default store password | Usually root, since `cacerts` belongs to the JDK |
| `windows-from-wsl` | `certutil.exe -user -addstore Root`, `-delstore`, `-verifystore` through WSL interop | User, and the Windows dialog |

Facts behind the table:

- The Debian tool only picks up files ending in `.crt` in PEM format (`update-ca-certificates` man page and script in Ubuntu 24.04, ca-certificates 20240203). Fedora's anchor directory takes `.pem`. Both paths are the ones mkcert uses (`truststore_linux.go`, read 2026-11-22).
- Firefox reads the Windows `CurrentUser` and `LocalMachine` root stores and the macOS user and admin trust settings by default since Firefox 120 (pref `security.enterprise_roots.enabled`, [bug 1848815](https://bugzilla.mozilla.org/show_bug.cgi?id=1848815), 2023; `security/manager/ssl/EnterpriseRoots.cpp`). So homecert writes no NSS database on Windows or macOS. `status` reads `prefs.js` of each Firefox profile and warns if a user has set that pref to `false`.
- Firefox on Linux does not read the system store ([bug 1600509](https://bugzilla.mozilla.org/show_bug.cgi?id=1600509), WONTFIX), so its profiles need NSS.
- Chrome and Edge use their own verifier with locally added roots from the platform store: Windows and macOS since Chrome 105, on by default since 108, Linux since 114 ([Chrome Root Store FAQ](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md)). On Linux the platform store for Chromium is the NSS shared database; since Chromium 146 the default path is `~/.local/share/pki/nssdb`, and an existing `~/.pki/nssdb` is still used ([Chromium Linux cert management](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md)).
- For QUIC (HTTP/3), Chrome honours local trust settings only to remove trust, not to add it (same FAQ). A dev server on HTTP/3 falls back to TCP for locally trusted roots. The README of the first release says so.

The NSS approach is in [ADR 0003](adr/0003-nss-through-certutil.md), the privilege rules in [ADR 0004](adr/0004-privileged-steps-are-shown-and-confirmed.md), and WSL in [ADR 0005](adr/0005-wsl-from-inside-the-distribution.md).

### Identifying our certificates

A store entry is homecert's if and only if its SHA-256 fingerprint equals that of `root.pem` or a file in `retired/`. Never by name, subject or alias. `uninstall` therefore cannot remove a certificate homecert did not add, even one with the same subject. Store-side names (`homecert-<first 8 hex of fingerprint>`) are only for people reading the store.

Foreign roots are found by subject for reporting only: an mkcert root has organisation `mkcert development CA` (mkcert `cert.go`). `status` reports it as unconstrained when it has no name constraints. homecert never removes it; the message gives `mkcert -uninstall`.

### Containers

`homecert snippet docker` prints, for Debian-based images:

```dockerfile
COPY homecert-root.crt /usr/local/share/ca-certificates/homecert-root.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/homecert-root.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

and a note on copying `root.pem` into the build context under that name. `--family fedora` and `--family alpine` variants print the matching paths. `homecert snippet env` prints `export` (or PowerShell `$env:`) lines for the host.

The variables behave differently, and the snippet's comments say so:

- `NODE_EXTRA_CA_CERTS` adds to Node's built-in roots and is read only at process start ([Node CLI docs](https://nodejs.org/api/cli.html)).
- `SSL_CERT_FILE` replaces OpenSSL's default bundle ([openssl-env](https://docs.openssl.org/master/man7/openssl-env/)), so it must point at a bundle that contains the root and the public roots, which the system bundle does after `update-ca-certificates`.
- `REQUESTS_CA_BUNDLE` replaces certifi's bundle in Python requests ([requests docs](https://requests.readthedocs.io/en/latest/user/advanced/)).
- Node 22.19 and 24.6 or newer can instead use the system store with `NODE_USE_SYSTEM_CA=1` (Node changelog); the snippet mentions it as an alternative.

## Hard parts

### Consumers that ignore constraints

The constraint is only worth something where it is enforced, and RFC 5280 leaves constraints inside a trust anchor up to the implementation (section 6.2). Reading the sources gives the table in the README: Chrome, Firefox, Apple, OpenSSL and Go enforce constraints in the root; Java does not; Windows is unconfirmed.

Handling:

1. The constraints are put in the intermediate as well, and the root key is discarded ([ADR 0002](adr/0002-discard-the-root-key.md)). Java checks constraints in every certificate of the path below the anchor, so a leaf for `example.com` made with the stolen issuing key fails in Java too. The only way around it would be a new intermediate without constraints, and that needs the root key, which no longer exists.
2. A CI job (milestone M2) tries forged certificates against every consumer it can run and fails if one behaves differently from the published table. The README table is replaced by that job's output before the first release.

### Servers that do not send the intermediate

Since leaves are signed by the intermediate, a server must send the leaf and the intermediate. The certificate file holds both, in that order, which is what most servers expect from a `fullchain.pem`. A server that sends only the first certificate of the file would break every client.

Handling: the M2 probe also starts small HTTPS servers with the issued files (Node, Go, Python, .NET Kestrel, Caddy or nginx where available on the runner) and checks with curl that the chain arrives. If a common stack fails, homecert also adds the intermediate to the intermediate stores (`CurrentUser\CA` on Windows, NSS with trust `,,`), so that clients can build the path themselves. Which servers need this is an open question.

### The Windows confirmation dialog

Adding a certificate to `CurrentUser\Root` makes Windows show a "Security Warning" dialog that the user must accept ([Microsoft Learn](https://learn.microsoft.com/troubleshoot/developer/visualstudio/installation/warnings-untrusted-certificate)). There is no documented way to suppress it, and that is fine: it is a second confirmation the user can read. The plan marks the step `Desktop`, and homecert says before asking that a Windows dialog will follow.

CI cannot answer the dialog. CI tests use `--store windows-machine` on the runner (`LocalMachine\Root`, no dialog). Whether the runner process is elevated, and whether the dialog also appears on removal, are open questions; the `windows-user` path is a manual check until settled.

### macOS authorisation

Setting trust in the user domain makes macOS ask for the user's password in a dialog. The admin domain needs root, and since macOS 11.3 an administrator password even when run as root; without a user session it fails with "no user interaction was possible" ([mkcert #415](https://github.com/FiloSottile/mkcert/issues/415), still reported on macOS 14 in 2023). homecert defaults to the user domain, which Chrome, Safari and Firefox all read, and leaves the admin domain to `--store macos-admin`.

CI on macOS may not be able to add trust at all. The M2 probe does not need to: it checks macOS's verifier with the root passed as an explicit anchor (`SecTrustSetAnchorCertificates` from a small Swift script). Store install and uninstall on macOS are tried in CI in M5; if the runner refuses, they are a manual check, and the roadmap says so.

### Missing NSS databases

On a fresh machine or runner no browser has run, so there is no NSS database to add to, and mkcert silently skips it ([ddev/github-action-setup-ddev#39](https://github.com/ddev/github-action-setup-ddev/issues/39)). homecert creates the Chromium database if neither `~/.pki/nssdb` nor `~/.local/share/pki/nssdb` exists (`certutil -N --empty-password -d sql:<path>`), in the new location. Firefox profiles cannot be created ahead of time; `status` says when none were found. If `certutil` is missing, the NSS steps appear in the plan as "cannot be done: install libnss3-tools (Debian) or nss-tools (Fedora)", the rest goes ahead, and `install` exits 1 after the other steps.

### Privilege

The Linux system stores, `macos-admin`, `windows-machine` and usually `java` need root or elevation. mkcert re-runs commands with `sudo` on its own ([#236](https://github.com/FiloSottile/mkcert/issues/236)). homecert shows each privileged step with the exact command, asks once for the whole plan, and runs those commands through `sudo`, which then asks for the password itself. `--dry-run` prints the plan and exits. Running homecert itself as root is refused unless `HOMECERT_DIR` is set, because the CA would otherwise land in root's home directory. Details and the rejected alternatives are in [ADR 0004](adr/0004-privileged-steps-are-shown-and-confirmed.md). The unprivileged M1 code finds `icacls` and `whoami` under `%SystemRoot%\System32` and refuses a `SystemRoot` that is empty or not an absolute path, but the value still comes from the user's environment, which is fine for a process running as that user. A privileged step (M3 to M5) must not take a tool's path from the environment at all: it uses fixed absolute paths (`/usr/bin/security`, `/usr/sbin/update-ca-certificates`), or on Windows asks the system for its directory, because an elevated process that trusts the caller's environment runs whatever the caller points it at.

### Uninstall that leaves nothing behind

`uninstall` is tested as hard as `install`:

- It finds entries by fingerprint only, current and retired.
- It is idempotent: running it twice is not an error, and a second run plans no steps.
- If it stops half way (a step fails, the user closes the dialog), re-running it finishes the job. A CI test interrupts it after each step in turn and re-runs it.
- The exit test compares each store's full list of fingerprints before `install` and after `uninstall`; they must be equal.

### Owner-only keys

- Unix: the CA directory is created with mode 0700 and key files are opened with `create_new` and mode 0600 through `std::os::unix::fs::OpenOptionsExt`, so there is no moment when they exist with wider permissions. Writes go to a temporary file in the same directory, which is renamed into place, or hard-linked into place when an existing file must not be replaced, since a hard link fails if the target exists.
- Windows: the CA directory gets a protected DACL with one entry, full control for the current user's SID, and no inherited entries. Files created inside inherit it. This is done with `icacls` (with the SID, so that the output's language does not matter) to keep the crate free of `unsafe`; the SID comes from `whoami /user /fo csv /nh`. Leaf key files written outside the CA directory get the same one-entry DACL, set with `icacls` before any byte is written. `icacls` works on a path, so between creating such a file and running `icacls` the file has the permissions it inherited from its directory. The file is therefore created with share mode 0 (`OpenOptionsExt::share_mode`): while homecert holds it, every other open fails with a sharing violation, so no handle can be opened in that moment and used to read the key later. A test reads the ACL back with PowerShell `Get-Acl` and fails if any other SID has access, and another (`no_one_can_open_a_file_while_it_is_being_written`) tries to open the file while the writer holds it. What remains is the CA directory's own moment between `create_dir` and `icacls`: another user who may write to the parent can create a file inside it then, which at worst takes a name homecert wanted and makes a write fail. Nothing has been written into the directory at that point, so nothing leaks.
- Leaf keys written to a path the user chose follow the same rules. A key is never written over an existing file without `--force`.

### Getting the name rules exactly right

The refusal in `issue` is only useful if it matches what verifiers do. A name homecert accepts but a browser rejects is a confusing failure; a name homecert refuses but a verifier would accept is harmless but annoying. The test plan below checks `names::permits` against rustls-webpki on a shared table, in both directions.

## Testing strategy

Levels, from cheap to expensive:

1. **Unit tests on pure code.** `names` gets a table of at least 60 cases: exact matches, subdomains, label-boundary traps (`xtest`, `test.evil`, `localhost.evil.com`, `127.0.0.1.nip.io`), trailing dots, upper case, punycode, wildcards at each level, IPv4 and IPv6 edges (`127.255.255.255`, `128.0.0.1`, `::1`, `::2`, `::ffff:127.0.0.1`). `plan` is tested with fake `Machine` values: every combination of present and missing stores gives the expected steps, and an `uninstall` plan after an `install` plan is its exact inverse.
2. **Certificates checked by a second implementation.** Each issued chain is parsed back with x509-parser and its fields compared with the profile table above. Then rustls-webpki (a dev-dependency) verifies it with the root as anchor. Every name in the table is issued twice: through `issue`, and through a test-only `issue_unchecked` that skips `permits`. For every name, `permits` must agree with webpki's verdict on the unchecked certificate. Where `openssl` on `PATH` is OpenSSL (not LibreSSL, which macOS ships under that name), the same table goes through `openssl verify` as a third opinion; it found the leaf common name problem in [ADR 0007](adr/0007-leaf-common-name.md), which webpki cannot see because it ignores the CN.
3. **Deliberately wrong variants.** These must fail the tests that guard them:
   - `permits` with a plain string suffix check instead of label comparison: the table catches `xtest`.
   - A root built without constraints: the profile test catches it, and so does reading the CA back, since the constraints come from `root.pem`. The webpki cross-check does not, because the intermediate carries the same constraints and webpki enforces those.
   - An intermediate built without constraints: the Java probe (level 4) catches it.
   - A key file created without the mode: the permission test catches it.
   - `uninstall` matching by subject instead of fingerprint: the store test with a decoy certificate of the same subject catches it.
4. **The consumer probe (CI, no store changes).** A test-only generator writes fixtures: a good leaf; a leaf for `example.com` signed by the constrained intermediate; a leaf for `example.com` under an unconstrained intermediate signed by a constrained root (this one needs a kept root key, so it exists only in the generator); a leaf for `10.0.0.5`; and a control chain from a root without constraints, where everything must be accepted, to prove the harness can say yes. Each runner verifies every fixture with every consumer it has, using the root as an explicit anchor: OpenSSL (`openssl verify`), Go, Java, Node, Python, .NET, curl with the platform's TLS library, PowerShell on Windows, a Swift script on macOS. The results must match `probe/expected.toml`, and the job prints the table that replaces the one in the README.
5. **Store tests (CI, real stores, throwaway runners).** Marked `#[ignore]` and run with `--ignored` only in CI: install into each store the runner supports, check with the platform's own verifier and with curl against a local server, uninstall, check the store is as before. Linux runs on Ubuntu and in a Fedora container; Windows uses `windows-machine`; macOS as far as the runner allows.
6. **Manual checks.** Browsers cannot be driven against the real trust store in CI with any confidence. `docs/manual-checks.md` (written in M7) lists the checks per platform: Chrome, Edge, Firefox and Safari load `https://app.test:8443` from a homecert leaf, show an error for the forged `example.com` leaf, and stop trusting after `uninstall`. The `windows-user` dialog path and WSL are manual too. Each release records who ran them, on which versions, and when.

## Platform support

| Platform | Default stores | Optional stores | Tested by |
| --- | --- | --- | --- |
| Windows 10 and 11 | `windows-user` | `windows-machine`, `java` | CI with `windows-machine`; `windows-user` manual |
| WSL 2 (Ubuntu, Debian, Fedora) | `system`, `nss`, `windows-from-wsl` | `java` | manual; the WSL-specific code is unit-tested with fake `Machine` values |
| macOS 14 and newer | `macos-user` | `macos-admin`, `java` | CI where the runner allows, otherwise manual |
| Debian 12, Ubuntu 22.04 and newer | `system`, `nss` | `java` | CI on `ubuntu-latest` |
| Fedora 41 and newer, RHEL 9 | `system`, `nss` | `java` | CI in a Fedora container |

Binaries for x86_64 and aarch64 on all three systems. Other Linux families get a clear "not supported yet" for `system`, and `nss` and `issue` still work.

## Dependencies

rcgen, ring, x509-parser, time and the two dev-only crates were added in M1; the others are still planned. All have permissive licences that `deny.toml` allows.

| Crate | Version checked | Licence | Why |
| --- | --- | --- | --- |
| rcgen, features `crypto`, `pem`, `ring`, `x509-parser`, no defaults | 0.14.10 (2026-08-28) | MIT OR Apache-2.0 | Builds the certificates, including name constraints with DNS and IP subtrees (`NameConstraints`, `GeneralSubtree::DnsName`, `GeneralSubtree::IpAddress(CidrSubnet)`); `Issuer::from_ca_cert_pem` signs leaves with the stored intermediate. |
| ring | 0.17.14 | Apache-2.0 AND ISC | Already pulled in by rcgen; the random part of CA names now, SHA-256 and SHA-1 fingerprints later. Chosen over aws-lc-rs because aws-lc-sys needs CMake and NASM on Windows and some versions carried the OpenSSL licence. |
| x509-parser | 0.18.1 | MIT OR Apache-2.0 | Reads certificates back: validity, constraints, subject. Already pulled in by rcgen's feature. |
| time | 0.3.55 | MIT OR Apache-2.0 | rcgen takes validity as `time::OffsetDateTime`. |
| lexopt | 0.3.2 | MIT | Argument parsing with no dependencies. The command set is small enough that hand-written help is fine; clap would add at least four crates. |
| schannel (Windows only) | 0.1.30 | MIT | Safe wrapper over the Windows certificate store: open, add, enumerate, delete, fingerprint. Keeps the crate free of `unsafe`. |
| rustls-webpki (dev only), features `ring`, `std` | 0.103.17 | ISC | An independent verifier that enforces constraints from the anchor, for the cross-check tests. |
| rustls-pki-types (dev only) | 1.16.0 | MIT OR Apache-2.0 | The certificate and time types webpki takes. Already pulled in by rcgen. |

No crate for macOS: `/usr/bin/security` covers adding, removing and listing trust, and security-framework 3.7 has no call to remove trust settings. No crate for directories, WSL or OS detection: environment variables, `/etc/os-release` and `/proc` are enough. No serde: there is no state file. No networking code at all.

The MSRV is 1.88 because rcgen 0.14.8 and later need it, and so does time 0.3.55. x509-parser brings in syn 2 and syn 3 through its proc macros; `clippy.toml` allows that one duplicate.

## Security considerations

- **What the constraint protects.** A copy of `issuer-key.pem` lets its holder sign certificates only for the permitted names, in every consumer that enforces constraints in an intermediate. It does not protect consumers that ignore constraints entirely; the probe will name any.
- **The root key** is never written. A copy of the CA directory cannot produce a new intermediate.
- **Wider lists are wider risk.** `--name corp.example` permits impersonating `corp.example` with the issuing key. `status` always prints the list. `internal` and `home.arpa` are in the default list because the scope of the first release fixes them; the README tells users they are real private namespaces.
- **Trust store changes** are listed, confirmed, made in the listed order and undone by `uninstall`. Nothing is removed that homecert did not add.
- **Privilege**: no automatic `sudo`, no self-elevation on Windows, refusal to run as root with the default directory.
- **Files**: owner-only keys and CA directory; certificate files are public and written 0644.
- **Leaked personal data**: no user or host names in certificate subjects.
- **Supply chain**: few dependencies, all checked by cargo-deny in CI for licences and advisories.
- **mkcert**: homecert never reads or reuses mkcert's key.

## Open questions

1. **Windows and constraints in a root.** No Microsoft statement says whether CryptoAPI enforces name constraints in a self-signed root, nor how it treats IP constraints. Partly answered on 2026-11-25, read-only: on Windows 11 (build 26100) with .NET 10.0.12, `X509Chain` in `CustomRootTrust` mode, which builds the chain with CryptoAPI and the root as an in-memory exclusive anchor, rejected leaves for `example.com`, `10.0.0.5` and `2001:db8::1` under an unconstrained intermediate from a root constrained to `test` and `127.0.0.0/8`, with `HasNotPermittedNameConstraint`, and accepted `app.test`, `127.0.0.1` and an unconstrained control chain. Nothing was added to a store. Whether CryptoAPI does the same for a root trusted through the `Root` store is still open; the M2 probe answers it on the runner.
2. **The Windows dialog.** Does removing a certificate from `CurrentUser\Root` also show a dialog? What happens to `add` in a session with no desktop? Are GitHub's Windows runners elevated, so that `windows-machine` works in CI?
3. **macOS on CI.** Does `sudo security add-trusted-cert -d` work on current GitHub macOS runners, or does it need the interaction that mkcert #415 describes?
4. **Servers and the chain.** Which common server stacks send only the first certificate of a PEM file? This decides whether the intermediate also goes into the intermediate stores.
5. **p11-kit and Fedora.** Does `update-ca-trust extract` keep the root's own name constraints in the bundles it writes? It should, since it copies the certificate, but this has not been tested.
6. **Apple's 825-day rule** for certificates from user-added roots. Apple says its later 398-day rule does not affect them ([Apple 102028](https://support.apple.com/en-us/102028)); nothing found says the same for 825.
7. **Firefox on Linux distributions.** Some distributions ship `p11-kit-trust` as Firefox's built-in roots module, and then Firefox reads the system store. Which ones do so today (Fedora, Ubuntu's snap) was not confirmed. homecert writes to the profiles regardless; the question only affects what `status` should say.
8. **WSL interop disabled.** With `[interop] enabled=false` in `/etc/wsl.conf`, homecert cannot reach Windows. The plan then prints a PowerShell command to run on the Windows side. The exact detection (the `WSLInterop` binfmt entry reads `enabled`) has been seen on one machine only.
9. **icacls owner semantics.** Whether an elevated administrator's files are owned by the Administrators group changes nothing for the DACL plan above, but the test must run both elevated and not.
10. **rcgen 0.15.** The next rcgen is unreleased. Its API may move `Issuer`; M1 pins the version it builds with.
