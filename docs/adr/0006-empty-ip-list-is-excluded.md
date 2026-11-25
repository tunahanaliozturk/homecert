# 0006: An empty IP list is written as an excluded subtree for every address

Status: accepted, 2026-11-25

## Context

The user can build a root with `--no-default-names --name corp.example` and no `--ip`. The obvious encoding is a nameConstraints extension whose permitted subtrees hold the one dNSName and nothing else.

That encoding does not mean what the user meant. RFC 5280 section 4.2.1.10 applies a permitted subtree only to names of its own type, so with no iPAddress subtree at all, an IP address in a leaf is not restricted. rustls-webpki follows that reading: with the excluded subtree taken out of the code by hand on 2026-11-25, it accepted leaves for `127.0.0.1`, `10.1.2.3` and `::1` under a root that permits only `corp.example`. A stolen issuing key could then sign a leaf for `10.0.0.5` or any other address, and verifiers that enforce the constraint would still accept it.

Options:

1. Refuse a constraint list without an IP range. Users who only want DNS names would have to list an address they do not need.
2. Add an excluded subtree that covers all IPv4 and all IPv6 addresses (`0.0.0.0/0` and `::/0`) whenever the IP list is empty. An excluded subtree wins over everything, so no address passes.
3. Accept the gap and document it.

The same gap exists for DNS names with an IP-only list. There is no clean way to exclude every DNS name: an empty dNSName as a constraint is read as "matches everything" by some verifiers (rustls-webpki says so in a comment) and is not defined by the RFC.

## Decision

Option 2 for IP addresses. For DNS names, a constraint list must hold at least one name; `Constraints::new` refuses an empty one with `NameError::NoDnsNames`.

`permits` agrees: an empty IP list permits no address. When a CA is read back, the excluded pair is recognised and turned back into an empty list; any other excluded subtree is refused as not written by homecert.

## Consequences

- What `status` shows ("addresses: none") is what verifiers enforce. The cross-check test `webpki_agrees_with_permits_under_other_constraint_lists` issues `127.0.0.1` and `::1` under a DNS-only root and requires rustls-webpki to reject both.
- The extension carries excluded subtrees only in this case. Verifiers that do not handle excluded subtrees would fail closed, since the extension is critical ([ADR 0001](0001-critical-name-constraints.md)).
- A root that permits IP addresses only cannot be made. Nobody has asked for one, and the default list has names.
