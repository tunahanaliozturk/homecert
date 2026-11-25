# 0008: The Windows owner-only DACL is set with `icacls /reset`, then `/inheritance:r /grant:r`

Status: accepted, 2026-11-25

## Context

Owner-only files and the CA directory on Windows must end up with a protected DACL that holds exactly one entry, full control for the current user's SID. Until now homecert ran `icacls <path> /inheritance:r /grant:r *<SID>:<rights>`. `/inheritance:r` removes only inherited entries.

When the parent directory passes no entries down, Windows gives a new file or directory the default DACL from the creator's token instead, and those entries are explicit. They survived. This was seen, not read: the first CI run on `windows-latest`, elevated as the built-in Administrator, failed three owner-only tests with SYSTEM (`S-1-5-18`), Administrators (`S-1-5-32-544`) and the user in the DACL. On Windows 11 (build 26100), unelevated, a temporary directory with one non-inheritable entry gave a new file SYSTEM, the user and the logon session SID; with the old steps SYSTEM and the logon session stayed. `entries_from_the_default_dacl_are_removed` repeats that and failed before the fix.

The crate forbids `unsafe`, and the design keeps Windows permissions to system tools.

Options:

1. `icacls <dir> /restore <file>` with the exact SDDL (`D:P(A;;FA;;;<SID>)`). Exact in one step, but it needs `SeRestorePrivilege`: unelevated it fails with error 1300 ("Not all privileges or groups referenced are assigned to the caller"), seen on 2026-11-25.
2. Grant the user, then `/remove` every other SID. The SIDs would come from `icacls /save` as SDDL, where well-known ones appear as aliases (`SY`, `BA`, `WD` and many more) that `icacls` does not take back, so homecert would need an alias table and an SDDL parser.
3. PowerShell `Set-Acl` with `SetSecurityDescriptorSddlForm`. Exact, but it starts a PowerShell for every key, and the tests already hit an inherited module path that made `Get-Acl` fail with a zero exit code.
4. Set the security descriptor at creation through the Windows API (`CreateFileW` and `CreateDirectoryW` with `SECURITY_ATTRIBUTES`). Exact and with no moment of wider permissions, but it needs `unsafe` or a new crate.
5. `icacls <path> /reset`, which replaces the DACL with only what the parent passes down and drops every explicit entry, then `icacls <path> /inheritance:r /grant:r *<SID>:<rights>`. `icacls` takes `/reset` only on its own, so these are two runs.

## Decision

Option 5. Neither step names an account, so the output's language does not matter, and neither needs a privilege. After the first step the DACL holds only inherited entries, possibly none; the second removes those and adds the one entry. If the DACL is empty in between, the owner can still change it, because an owner always may.

## Consequences

- One more `icacls` run per owner-only file and for the CA directory.
- Between the two runs the object has the permissions its parent passes down, as it already had between creation and the old single run. A file is held open with share mode 0 the whole time and holds no secret yet; the CA directory is empty.
- Option 4 remains the way to remove that moment altogether, if the crate ever accepts `unsafe` or a Windows security crate; that would replace this ADR.
- The test check now requires exactly one entry (SID, allow, full control, not inherited, inherited by children on a directory), so a second entry of any kind fails it.
