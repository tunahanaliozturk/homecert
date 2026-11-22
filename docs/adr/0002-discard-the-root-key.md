# 0002: The root key is discarded; leaves come from a constrained intermediate

Status: accepted, 2026-11-22

## Context

The project brief asks for a root whose name constraints permit only local names, and for leaves signed by that root, as mkcert does. The value of the constraint depends on consumers enforcing constraints that sit in a trust anchor, and RFC 5280 (section 6.2) leaves that to each implementation.

Reading the sources on 2026-11-22: Chrome (since 112), Firefox, Apple, OpenSSL and Go enforce them. Java does not. Its PKIX checker starts with no constraints and only collects them from certificates in the path, and the anchor is not in the path (`ConstraintsChecker.java`, `PKIX.java` in OpenJDK). Passing constraints through `TrustAnchor(cert, nameConstraints)` makes the SUN provider throw "name constraints in trust anchor not supported". Windows is unconfirmed. So with the brief's design, a stolen root key still signs `example.com` certificates that Java accepts, and perhaps Windows too.

Three options:

1. Root signs leaves; keep the root key. Simple, same as mkcert. Protection only where anchor constraints are enforced.
2. Root signs a constrained intermediate; keep both keys. The intermediate's constraints are checked by Java, but a thief of the root key makes a new intermediate without constraints.
3. Root signs a constrained intermediate, then the root key is dropped from memory without ever being written. Leaves are signed by the intermediate.

## Decision

Option 3. `install` and `rotate` create the root key in memory, sign one intermediate that carries the same name constraints with path length 0, write the root certificate, the intermediate and the intermediate's key, and drop the root key. The certificate file from `issue` holds the leaf followed by the intermediate.

## Consequences

- The only key on disk is the intermediate's, and every verifier that checks constraints in an intermediate, Java included, refuses what it signs outside the permitted names. Nobody can mint an unconstrained intermediate, because the key that could do it does not exist.
- A copy of the CA directory, in a backup or an image, is worth less than an mkcert CA directory, and cannot produce a new intermediate either.
- Constraints cannot be widened later without a new root. That is what `rotate --name` does, and the user must trust the new root again. This is intended.
- A lost or damaged `issuer-key.pem` cannot be replaced from the root; the answer is `rotate`.
- Servers must send the intermediate. Most send the whole PEM file; any that send only the first certificate would break every client. The M2 probe tests the common server stacks. If one fails, homecert also adds the intermediate to the intermediate stores (`CurrentUser\CA`, NSS with trust `,,`) so clients can build the path.
- Leaf files are a few hundred bytes larger and the chain is one certificate longer. That costs nothing that matters on a developer machine.
- The tests for anchor enforcement need a root key, so the M2 fixture generator keeps one in memory for its forged fixtures only. That code is under `tests/` or `examples/` and is not in the binary.
