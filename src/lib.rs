//! Fast secret masking for text on its way into a model context.
//!
//! The ruleset is the betterleaks default config (regex + keywords + entropy),
//! compiled ASCII-only, plus hand-written rules for shapes it misses and
//! an exact-value pass over local credential files.
//!
//! # Library use
//!
//! [`Scanner`] holds no global state. [`Scanner::new`] and
//! [`Scanner::with_config`] build every automaton from static rule data and the
//! known values the caller passes; the engine never reads the environment or the
//! filesystem. Only [`known`] does, and only when a caller calls it. A service
//! that builds a scanner with an explicit list and never touches [`known`] has no
//! ambient inputs:
//!
//! ```
//! use pixi_mask::{Config, Scanner};
//!
//! let mut config = Config::new(Vec::new());
//! config.depth = 5;
//! let scanner = Scanner::checked(config).expect("every rule compiles");
//! let spans = scanner.scan_bytes(b"token sk-proj-Ab3dEf6hIj9lMn2pQr5tUv8x");
//! assert!(!spans.is_empty());
//! ```
//!
//! Rule regexes compile lazily, on the first text that carries their keyword.
//! A rule that fails to compile is skipped by `scan` without a word, so a caller
//! that needs to know uses [`Scanner::checked`] (or `verify`) at start-up and
//! refuses to run when it returns an error.
//!
//! # Decoding bounds
//!
//! An encoded run longer than [`Config::max_decode_run`] (8000 bytes by default)
//! is not decoded. [`Scanner::report`] and [`Scanner::report_bytes`] return the
//! spans of those runs in [`Report::skipped`], and set [`Report::complete`] to
//! false when the decode budget ran out. A caller that must not admit unscanned
//! text refuses on either, at any cap, instead of guessing at the cap itself.
//!
//! ```
//! use pixi_mask::{Config, Scanner};
//!
//! let mut config = Config::new(Vec::new());
//! config.extra = true;
//! config.bare_entropy = false;
//! config.depth = 5;
//! config.max_decode_run = 64 * 1024;
//! let scanner = Scanner::checked(config).expect("every rule compiles");
//! let report = scanner.report_bytes(b"OPENAI_API_KEY=sk-proj-Ab3dEf6hIj9lMn2pQr5tUv8x");
//! assert_eq!(report.spans.len(), 1);
//! assert!(report.skipped.is_empty() && report.complete);
//! ```
//!
//! [`known`]: crate::known

pub mod engine;
pub mod extra;
pub mod known;
pub mod rules;

pub use engine::{Config, Decode, Report, Scanner, Span};

/// Identity of the rule set a build carries, for a decision record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ruleset {
    pub name: &'static str,
    pub version: &'static str,
    /// sha256 of the vendored config the rules were generated from.
    pub sha256: &'static str,
    /// Vendored rules; hand-written rules in `src/extra.rs` are added on top.
    pub rules: usize,
}

pub const RULESET: Ruleset = Ruleset {
    name: rules::RULESET_NAME,
    version: rules::RULESET_VERSION,
    sha256: rules::RULESET_SHA256,
    rules: rules::RULES.len(),
};
