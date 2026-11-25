# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

- Repository scaffold, design document and roadmap.
- Name rules: DNS names, wildcards and IP ranges, and the `permits` check, with an 82-input table cross-checked against rustls-webpki and OpenSSL.
- Root, constrained intermediate and leaf certificates; the root key is dropped after it signs the intermediate.
- Owner-only, atomic file writes on Unix and Windows; `issue` logic with mkcert's default file names. No command line yet.
- Review fixes before the first push: `issue` no longer leaves a key behind when the certificate cannot be written; a CA directory whose intermediate does not chain to its root is refused; Windows files cannot be opened by anyone else before their DACL is set; an empty or relative `SystemRoot` is refused; leaves get random serial numbers and never outlive the intermediate; a doubled `0.0.0.0/0` exclusion is no longer read as "no IP addresses"; wildcards longer than 253 characters are refused; OpenSSL cross-checks every constraint list with only homecert's root trusted, and says when it is skipped.
- Windows owner-only files and the CA directory now get exactly one DACL entry, for the current user, even where the parent directory passes no entries down. Before, entries from the token's default DACL (SYSTEM, Administrators) stayed, which the first elevated CI run showed.
