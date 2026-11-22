# Roadmap

Each milestone ends with a test that has to pass. A milestone is not done because the code exists.

| # | Milestone | Scope | Exit test |
| --- | --- | --- | --- |
| M0 | Plan | Repository, lints, CI, design, roadmap, ADRs. | CI green on a crate that prints its name and version. |
| M1 | Names and certificates | `names` (constraint matching, wildcard rules), `ca` (root, intermediate and leaf with rcgen and ring; root key dropped), `files` (CA directory, owner-only keys on Unix and Windows, atomic writes). `issue` works against a CA created by a test helper. | The 60-case name table agrees with rustls-webpki in both directions, on all three CI systems. Each certificate field matches the profile table in the design. The label-suffix mutation of `permits` fails the table. The permission test fails when the mode or the DACL is left out, on Linux, macOS and Windows. |
| M2 | Consumer probe | Fixture generator (good leaf, forged leaf under the constrained intermediate, forged leaf under an unconstrained intermediate from a constrained root, out-of-range IP leaf, unconstrained control chain). CI job that verifies every fixture with OpenSSL, Go, Java, Node, Python, .NET and curl on each runner, PowerShell on Windows, a Swift script on macOS. Small servers check that the chain is sent. `probe/expected.toml`. Answers open questions 1 and 4. | Every result matches `expected.toml` on all three runners. The control chain is accepted everywhere, so a harness that rejects everything fails. Java rejects the forged leaf under the constrained intermediate. The job's table is committed as `docs/consumers.md`. |
| M3 | Plans and the Linux stores | `probe` (`Machine`), `plan`, `apply` with confirmation, `--dry-run`, `--yes`, exit codes. Stores: `system` for Debian and Fedora families through `sudo`, `nss` through certutil, including creating the Chromium database. `install`, `uninstall`, `status` on Linux. | On `ubuntu-latest` and in a Fedora container: install, curl to a local server succeeds, uninstall, curl fails, and every store's fingerprint list equals the one taken before install. Uninstall interrupted after each step in turn and re-run ends in the same state. A test proves every shown command is the command run. |
| M4 | Windows and macOS stores | `windows-user` and `windows-machine` through schannel, `macos-user` and `macos-admin` through `/usr/bin/security`, Firefox pref check. Answers open questions 2 and 3. | Windows CI: install to `windows-machine`, PowerShell `Invoke-WebRequest` and curl (Schannel) succeed against a local server, uninstall, both fail, store list as before. macOS CI: the same with `macos-admin` if the runner allows it; if not, the job proves the plan and the commands with a fake `security`, and the store test is added to the manual checklist. A decoy certificate with homecert's subject survives `uninstall`. |
| M5 | WSL, Java and containers | `windows-from-wsl` through interop, the fallback command when interop is off, `java` through keytool, `snippet docker` and `snippet env`. | Unit tests with fake `Machine` values cover WSL with interop on and off. A manual run on WSL 2 with Ubuntu shows Edge on Windows loading a page served from WSL, recorded in the progress entry. CI builds a Debian and a Fedora image from the printed Dockerfile lines and curl inside each trusts a homecert leaf. Java on `ubuntu-latest` trusts a leaf after `install --store java` and not after `uninstall`. |
| M6 | Rotate, status and mkcert | `rotate` with new constraints, `retired/`, expiry warnings, detection of mkcert roots in every store, the migration section of the README. | Rotate under CI on Linux: the new root is trusted wherever the old one was, the old root is gone, leaves from the old CA fail and leaves from the new one succeed. `status` exits 4 when a planted mkcert root is present and 0 after it is removed. Uninstall after two rotations leaves no homecert root in any store. |
| M7 | Documents and release | README with the probe's consumer table and measured facts only, `docs/manual-checks.md` executed on Windows 11, macOS and Ubuntu with recorded browser versions, one PNG diagram of the root, intermediate and leaf (light and dark), release workflow for binaries. | Every claim in the README links a test or a recorded manual check. The manual checklist passes on all three systems. Tag v0.1.0, after the owner says yes. |

## Progress

- **M0**, 2026-11-22: done. Scaffold, design, roadmap and five ADRs. Facts were checked against primary sources on 2026-11-22; the design lists ten open questions, most of which M2 and M4 answer.

## Order of work inside a milestone

1. Write the exit test first, and see it fail.
2. Implement until it passes.
3. Add the deliberately wrong variant if the milestone has one, and see the test reject it.
4. Record any decision that is hard to reverse as an ADR.

## After the first release

Not planned, listed so they are not forgotten: PKCS#12 output, client certificates (`--client`), Arch, openSUSE and Alpine system stores, installing from the Windows side into WSL distributions with `wsl.exe -u root`, adding the intermediate to intermediate stores if M2 does not already require it, a Homebrew formula, winget and Scoop manifests, Debian and RPM packages, a GitHub Action for CI users, a JSON output for `status`, signed release binaries.
