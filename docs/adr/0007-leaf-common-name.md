# 0007: The leaf common name is the first DNS name, never an IP address

Status: accepted, 2026-11-25

## Context

The profile table in the design said a leaf's subject CN is "the first name in the request", as mkcert does with its hosts. For `homecert issue 127.0.0.1` that CN is `127.0.0.1`.

OpenSSL checks a leaf's CN against the DNS name constraints when the leaf has no DNS name in its subject alternative names (`NAME_CONSTRAINTS_check_CN`, called from `check_name_constraints` in `crypto/x509/x509_vfy.c`). A CN made of letters, digits and dots, such as `127.0.0.1`, is treated as a host name. It is not under `localhost`, `test`, `internal` or `home.arpa`, so OpenSSL rejects the leaf with "permitted subtree violation", although its only SAN, `127.0.0.1`, is inside `127.0.0.0/8`.

This was seen, not read: with the CN set to the first name, `openssl_agrees_with_permits_on_every_table_name` failed for `127.0.0.1`, `127.0.0.0`, `127.1.2.3` and `127.255.255.255` under OpenSSL 3.5.6 on 2026-11-25. rustls-webpki accepted the same leaves, because it ignores the CN. An IPv6 CN such as `::1` passed, because colons do not look like a host name.

Options:

1. Keep the first name as CN and accept that OpenSSL-based clients (curl, Node, Python on Linux) reject IP-only leaves.
2. Use the first DNS name as CN, and for a request with only addresses, leave the CN out.
3. Never set a CN. Browsers ignore it, but some tools still show it, and an empty subject requires the SAN extension to be critical.

## Decision

Option 2. The CN is the first DNS name in the request, wildcards included (`*.app.test`). A request with only IP addresses gets a subject of `O=homecert` and no CN.

## Consequences

- IP-only leaves verify in OpenSSL. The OpenSSL test now includes a leaf for `127.0.0.1` alone and requires it to pass.
- The subject still carries no user or host name.
- A request such as `homecert issue 127.0.0.1 app.test` gets `app.test` as CN, not the first word typed. Nothing reads the CN for matching, so this only changes what a certificate viewer shows.
