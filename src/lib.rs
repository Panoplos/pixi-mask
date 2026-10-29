//! Fast secret masking for text on its way into a model context.
//!
//! The ruleset is the gitleaks default config (regex + keywords + entropy),
//! compiled ASCII-only, plus hand-written rules for shapes gitleaks misses and
//! an exact-value pass over local credential files.

pub mod engine;
pub mod extra;
pub mod known;
pub mod rules;
