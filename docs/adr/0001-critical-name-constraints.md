# 0001: Name constraints are marked critical

Status: accepted, 2026-11-22

## Context

The root and the intermediate carry a nameConstraints extension. An extension is either critical or not. A verifier that does not understand a critical extension must reject the certificate; it may ignore a non-critical one.

The two choices fail differently. With a non-critical extension, a verifier that does not implement name constraints ignores them and accepts a forged leaf for any name. With a critical one, such a verifier rejects every homecert certificate, including the good ones.

What the sources say, read on 2026-11-22:

- RFC 5280, section 4.2.1.10: "Conforming CAs MUST mark this extension as critical."
- The CA/Browser Forum Baseline Requirements (v2.3.1) say the extension "SHOULD be marked critical, but MAY be marked non-critical" for compatibility with legacy applications. That exception dates from Ballot 75 (2012). Mailing-list posts give old Apple systems and OpenSSL 0.9.8 as the reason, and say Apple has handled a critical extension since iOS 9 and macOS 10.12. These are recollections, not specifications. The forum's May 2024 working group minutes record Apple saying critical is fine now.
- No current verifier was found that rejects a certificate only because its name constraints are critical. The remaining risk is a critical extension holding a name type the verifier does not handle; homecert uses only dNSName and iPAddress, which every verifier in scope handles.
- rcgen 0.14.10 always writes the extension as critical (`certificate.rs`, `write_x509_extension(.., oid::NAME_CONSTRAINTS, true, ..)`); the caller cannot choose.

## Decision

Mark the extension critical, in the root and in the intermediate.

## Consequences

- A verifier that does not implement name constraints fails closed: it rejects the certificate instead of accepting a forgery. For a tool whose point is the constraint, that is the correct failure.
- homecert follows RFC 5280 and needs no change to rcgen.
- If a consumer the developer uses rejects homecert's certificates for this reason, it shows up as a broken certificate, not as a silent loss of protection. The M2 probe would show it first; such a consumer would be listed in the README. Switching to non-critical would then need a fork of rcgen or a different certificate builder, so this is hard to reverse.
- Java gains nothing from either choice for the root, since it ignores constraints there. [ADR 0002](0002-discard-the-root-key.md) handles Java.
