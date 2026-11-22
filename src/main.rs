//! homecert: locally trusted HTTPS certificates for development, from a root
//! that can only sign for local names.
//!
//! Nothing is implemented yet. The binary prints its name and version and
//! exits. The design is in `docs/design.md` and the milestones are in
//! `docs/roadmap.md`.

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let line = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    match writeln!(io::stdout().lock(), "{line}") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
