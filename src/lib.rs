//! homecert: locally trusted HTTPS certificates for development, from a root
//! that can only sign for local names.
//!
//! The library holds the modules from `docs/design.md`; the binary is a thin
//! front end. Built so far: [`names`].

pub mod names;
