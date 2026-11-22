# 0005: WSL is handled from inside the distribution

Status: accepted, 2026-11-22

## Context

A common Windows setup runs the development server inside a WSL 2 distribution and the browser on Windows. Both sides must trust the same root: the Windows browser, and the tools inside the distribution (curl, Node, Python) that call the server. The leaf files must be inside the distribution, where the server reads them.

Checked on a Windows 11 machine with WSL 2.7.3 and Ubuntu 24.04 on 2026-11-22: inside the distribution, `powershell.exe` and `certutil.exe` run through interop, `wslpath -w` translates paths, `WSL_DISTRO_NAME` and `WSL_INTEROP` are set, and `/proc/sys/fs/binfmt_misc/WSLInterop` reads `enabled`. From Windows, `wsl.exe -d <distro> -u root -- <cmd>` runs as root without a password.

Options:

1. Run homecert inside the distribution. It manages the Linux stores as on any Linux, and adds the root to the Windows `CurrentUser\Root` store through interop with `certutil.exe -user -addstore Root <wslpath -w root.pem>`.
2. Run `homecert.exe` on Windows. It manages the Windows store natively and reaches each distribution with `wsl.exe -u root`, which needs no sudo.
3. Two separate installs, one per side, sharing a root by copying files.

## Decision

Option 1. When homecert detects WSL with interop enabled, the default stores are `system`, `nss` and `windows-from-wsl`. The Windows step is marked as one that shows the Windows dialog. `status` checks the Windows side with `certutil.exe -user -verifystore Root <sha1>`, judged by exit code since certutil's text is localised. With interop disabled, the plan shows the PowerShell command to run on Windows instead.

## Consequences

- The CA and the leaves live where the server runs. Users install one binary, the Linux one, in the place they already work.
- One root covers both sides, so there is nothing to keep in sync.
- The Windows step uses `certutil.exe` instead of the schannel code path, so WSL has a second implementation of the Windows store to test. It is small: add, remove and check by hash.
- Option 2's password-free root access is lost; the distribution's system store still goes through `sudo` as in [ADR 0004](0004-privileged-steps-are-shown-and-confirmed.md).
- Someone who runs servers on Windows and in WSL needs two CAs, each trusted on both sides, or runs `issue` on one side only. The README says so. Option 2 is listed after the first release.
- CI cannot run WSL on GitHub's hosted runners, so the WSL path is unit-tested with fake `Machine` values and checked by hand before each release.
