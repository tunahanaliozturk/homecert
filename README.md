# homecert

Locally trusted HTTPS certificates for development, on Windows, WSL, macOS and Linux.

`homecert install` creates a root certificate and adds it to the trust stores of your machine. `homecert issue app.test` then gives you a certificate and key that your browser, curl and your runtime accept without warnings. Unlike mkcert, the root carries X.509 name constraints: it can only vouch for local names such as `localhost`, `*.test` and `127.0.0.1`, so a leaked key file cannot be used to impersonate your bank.

## Status

Milestone M1 is built: the name rules, the root, intermediate and leaf certificates, owner-only files and the `issue` logic, as a library with tests. There is no command line yet; the binary only prints its name and version, and nothing touches a trust store. What the tests show so far:

- `permits`, the check that decides whether a name may be issued, agrees with rustls-webpki and with OpenSSL on 65 names, including label traps such as `xtest`, `evil-home.arpa` and `::ffff:127.0.0.1` (`src/ca/tests.rs`).
- The root key is never written: the CA directory holds the root certificate, the intermediate and the intermediate's key, nothing else (`the_root_key_is_never_stored`).
- Key files are owner-only on Windows (a one-entry DACL, read back with `Get-Acl`). The file is held open with no sharing until the DACL is set, so no one can open it in between (`no_one_can_open_a_file_while_it_is_being_written`). Key files are never written over an existing file (`src/files.rs`).


- [docs/design.md](docs/design.md): the problem, the commands, the architecture, the hard parts and how each promise is tested.
- [docs/roadmap.md](docs/roadmap.md): milestones to the first release, each with an exit test.
- [docs/adr/](docs/adr/): decisions that had a real alternative.

## The problem

Developers need real HTTPS on their own machine for OAuth callbacks, secure cookies, service workers and HTTP/2. The usual tool is [mkcert](https://github.com/FiloSottile/mkcert). As checked on 2026-11-22:

- It has about 59,900 stars. Its last code commit is from 2022-04-26, the last commit of any kind (a README link) from 2024-04-18, and the last release is v1.4.4 from 2022-04-26 ([commits](https://github.com/FiloSottile/mkcert/commits/master)).
- [Issue #664](https://github.com/FiloSottile/mkcert/issues/664), "Project maintenance status and possibility of adding maintainers", opened 2026-05-13, has no reply.
- mkcert's root can sign for any name. Whoever copies `rootCA-key.pem` from a backup, a dotfiles repository or a container image can make certificates for any site that the machine will accept. Name constraints were asked for in [issue #302](https://github.com/FiloSottile/mkcert/issues/302) (2020) and offered in [PR #657](https://github.com/FiloSottile/mkcert/pull/657) (2026-01-29); neither is merged.
- Other open pull requests ask to stop installing into NSS by default ([#674](https://github.com/FiloSottile/mkcert/pull/674), 2026-07-16) and to write the PKCS#12 file with mode 0600 ([#685](https://github.com/FiloSottile/mkcert/pull/685), 2026-11-15).
- mkcert re-runs commands through `sudo` on its own, which [issue #236](https://github.com/FiloSottile/mkcert/issues/236), "Automatic sudo fallback is scary!", objects to (2020, open).
- On a fresh CI runner mkcert finds no browser database and Chromium keeps rejecting the certificate ([ddev/github-action-setup-ddev#39](https://github.com/ddev/github-action-setup-ddev/issues/39), 2025-08-06). DDEV documents browser workarounds for mkcert ([DDEV docs](https://docs.ddev.com/en/stable/users/install/configuring-browsers/)).
- mkcert has no step for WSL. Run inside a distribution, it installs into the Linux stores only (its `truststore_linux.go` has no Windows path), so the Windows browser that opens the page does not trust the root.

## What the first release will do

- `homecert install`: create a root whose name constraints permit only `localhost`, `test`, `internal`, `home.arpa` (each with every name under it), `127.0.0.0/8` and `::1`. The list can be changed when the root is created and is shown by `status`. List every trust store change, ask, then make it.
- `homecert issue <names>`: write a certificate and key for the names. A name outside the constraints is refused with a message that says why.
- `homecert uninstall`, `homecert rotate`, `homecert status`.
- Trust stores: the Windows current user store (no administrator rights), the macOS login trust settings, the system stores of the Debian and Fedora families, NSS databases for Firefox and Chromium on Linux, and a Java keystore when asked.
- WSL: run `homecert install` inside the distribution and the same root is also trusted on the Windows side.
- Containers: `homecert snippet docker` and `homecert snippet env` print the Dockerfile lines and the environment variables (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`) that make a container trust the root.
- Private keys are written readable by their owner only, on every platform.
- The root's own private key is never written to disk. Leaves are signed by a constrained intermediate, and the root key is thrown away once that intermediate exists ([ADR 0002](docs/adr/0002-discard-the-root-key.md)).

## What it will not do

- It is not an ACME server, has no GUI, makes no profiles for phones, and runs no background service.
- It does not import mkcert's root. Replacing an unconstrained root is the point. `status` warns when it finds one, and the README of the first release will say how to remove it.
- It does not write PKCS#12 files in the first release.
- It does not stop someone who already runs code as you. Such a person can read the issuing key, and can also add a root of their own to your stores without homecert.
- Name constraints only help where the software checking the certificate enforces them. The table below will be filled from a CI job that tries a forged certificate against each one, not from documentation. Until then, this is what the sources say:

| Consumer | Enforces constraints in a root? | Source |
| --- | --- | --- |
| Chrome and Edge on Windows, macOS, Linux | Yes, since Chrome 112, with no opt-out since 126 | [Chromium policy definition](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/EnforceLocalAnchorConstraintsEnabled.yaml) |
| Firefox (NSS, mozilla::pkix) | Yes, from reading the code | [pkixbuild.cpp](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/mozpkix/lib/pkixbuild.cpp) |
| Safari and macOS | Yes, from Apple's own tests | [NameConstraintsTests.m](https://github.com/apple-oss-distributions/Security/blob/main/tests/TrustTests/EvaluationTests/NameConstraintsTests.m) |
| Windows (Schannel, .NET, curl) | Not confirmed | No Microsoft statement found |
| OpenSSL, and so Node.js, Python, curl on Linux, .NET on Linux | Yes | [x509_vfy.c](https://github.com/openssl/openssl/blob/master/crypto/x509/x509_vfy.c) |
| Go | Yes | [verify.go](https://github.com/golang/go/blob/master/src/crypto/x509/verify.go) |
| Java | **No**: constraints inside a root from `cacerts` are ignored | [ConstraintsChecker.java](https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/provider/certpath/ConstraintsChecker.java) |
| Chrome on Android | No | Chromium unit tests |

Java ignores constraints in the root but does check them in an intermediate. That is why homecert signs leaves from a constrained intermediate and discards the root key: the key that exists on disk can then only sign for local names, for Java too. All sources above were read on 2026-11-22; the details are in [docs/design.md](docs/design.md).

Two more limits, stated plainly:

- `internal` and `home.arpa` are real private namespaces. If your employer names hosts `*.internal`, or your router answers at `router.home.arpa`, a stolen issuing key can impersonate them on your machine. Remove them at creation if that matters to you.
- The constraint limits what a stolen key can sign. It does not make the key harmless: certificates for your own local names can still be forged.

## Licence

Dual licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
