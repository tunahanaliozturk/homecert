# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

- Repository scaffold, design document and roadmap.
- Name rules: DNS names, wildcards and IP ranges, and the `permits` check, with an 82-input table cross-checked against rustls-webpki and OpenSSL.
- Root, constrained intermediate and leaf certificates; the root key is dropped after it signs the intermediate.
- Owner-only, atomic file writes on Unix and Windows; `issue` logic with mkcert's default file names. No command line yet.
