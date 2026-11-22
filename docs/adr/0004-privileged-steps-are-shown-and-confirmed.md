# 0004: Privileged steps are shown, confirmed, then run through sudo

Status: accepted, 2026-11-22

## Context

Some stores need root: the Linux system stores, the macOS admin trust domain, the Windows machine store, and usually a JDK's `cacerts`. mkcert re-runs these commands with `sudo` on its own when it is not root (`commandWithSudo` in `main.go`). [Issue #236](https://github.com/FiloSottile/mkcert/issues/236), "Automatic sudo fallback is scary!", objects that this silently uses another command's cached sudo session, and asks for "rerun with sudo" instead.

Options:

1. Do what mkcert does.
2. Never escalate: print the privileged commands and let the user run them. Safe, but `install` then needs two steps, CI scripts must copy commands out of the output, and `uninstall` is no longer one command.
3. Ask the user to run all of homecert as root. The CA directory then lands in root's home, owned by root, and the user's own NSS databases get root-owned files.
4. Show the whole plan, with the exact command for each privileged step, ask once, then run those commands through `sudo`, which asks for the password in the usual way.

## Decision

Option 4.

- Every step that needs root is shown with the command that will run, word for word. A test asserts that the shown text and the executed command are the same.
- One confirmation covers the plan. `--yes` gives it in advance for CI; without a terminal and without `--yes`, homecert exits 5 and changes nothing.
- `--dry-run` prints the plan and exits, for people who want option 2.
- On Windows homecert never elevates itself. The machine store is used only when the user started homecert elevated and named `--store windows-machine`.
- Running homecert as root is refused unless `HOMECERT_DIR` is set, so the CA cannot land in root's home by accident.

## Consequences

- No privileged command runs that the user has not seen, which answers #236.
- sudo may still use a cached session for the password; that is sudo's policy, and the user approved the commands just before.
- `install` and `uninstall` stay one command each, interactive or in CI.
- Each privileged step is a separate `sudo` invocation, so a long plan may ask for the password more than once on systems with no sudo cache. Acceptable for a tool run rarely.
- Systems without `sudo` (for example with `doas`) get the plan with the commands to run by hand. Supporting `doas` is a later addition.
