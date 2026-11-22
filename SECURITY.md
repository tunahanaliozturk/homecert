# Security policy

## Reporting a vulnerability

Report it privately through GitHub: the **Security** tab of this repository, then **Report a vulnerability**. Please do not open a public issue, discussion or pull request for it.

Include what you found and how to reproduce it. You will get an answer within 7 days, and a fix or a plan within 30 days for confirmed issues. You are credited in the advisory unless you ask not to be.

## Supported versions

Security fixes go into the latest release only.

## What counts

homecert edits the trust stores of the machine it runs on, so mistakes here are serious. These count:

- A certificate issued by homecert that a consumer homecert lists as enforcing name constraints accepts for a name outside the constraints.
- `homecert issue` accepting a name that is outside the constraints of the installed root.
- A private key file readable by another local user, on any platform.
- A store change that `homecert install` made without listing it first, or that `homecert uninstall` does not undo.
- `uninstall` or `rotate` removing a certificate that homecert did not add.
- homecert running a command with raised privileges (sudo, an elevated process) that the user did not confirm.
- homecert writing the root's private key anywhere. By design the root key is never stored (see `docs/adr/0002-discard-the-root-key.md`).

Out of scope: an attacker who already runs code as the same user. Such an attacker can read the issuing key, and can add their own root to the user's stores without homecert. The README says what the name constraints do and do not protect against.
