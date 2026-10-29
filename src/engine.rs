// Detection engine: keyword prefilter -> rule regexes -> entropy -> allowlists,
// plus exact known values, a bare high-entropy rule, and a base64 decode pass.
//
// Same shape as gitleaks (regex + keywords + entropy), with two differences
// that matter for a context guard: path-based skips are gone (we scan text),
// and matches are masked in place instead of reported.
//
// Regexes are compiled ASCII-only (`unicode(false)`). That is what RE2 does for
// gitleaks, and it keeps the whole 221-rule set under ~10 ms to compile instead
// of ~1 s: unicode `\w` expands into huge character classes.

use std::cell::OnceCell;
use std::collections::BTreeSet;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::{Regex, RegexBuilder};

use crate::extra::EXTRA;
use crate::rules::{Rule, RULES};

// generic-api-key & friends use bounded repetitions that can still expand past
// the 10 MB default in hostile cases; they are the rules that catch
// `NAME=<token>` dumps, so give them room.
const SIZE_LIMIT: usize = 64 * 1024 * 1024;

// Longest bare token the high-entropy rule will mask. Inline base64 assets and
// npm `integrity` digests (`sha512-` + 88 base64 chars) run longer, and longer
// secrets are still caught by keyword rules.
const MAX_BARE_RUN: usize = 80;

// Longest run worth trying to base64-decode.
const MAX_B64_RUN: usize = 8000;

pub const MASK: &str = "…[REDACTED]";

pub struct CompiledRule {
    rx: OnceCell<Option<Regex>>,
}

pub struct Scanner {
    all: Vec<&'static Rule>,
    keyword_ac: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    unconditional: Vec<usize>,
    rules: Vec<CompiledRule>,
    known_ac: Option<AhoCorasick>,
    extra: Regex,
    b64: Regex,
    allow: Vec<OnceCell<Option<Regex>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// Shannon entropy in bits per byte.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

impl Scanner {
    pub fn new(known: Vec<String>) -> Scanner {
        let mut keywords: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();

        let all: Vec<&'static Rule> = RULES.iter().chain(EXTRA.iter()).collect();
        for (i, r) in all.iter().enumerate() {
            if r.keywords.is_empty() {
                unconditional.push(i);
                continue;
            }
            for k in r.keywords {
                match keywords.iter().position(|x| x == k) {
                    Some(p) => {
                        if !keyword_rules[p].contains(&i) {
                            keyword_rules[p].push(i);
                        }
                    }
                    None => {
                        keywords.push((*k).to_string());
                        keyword_rules.push(vec![i]);
                    }
                }
            }
        }

        let keyword_ac = if keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&keywords)
                    .expect("keyword automaton"),
            )
        };

        let known_ac = if known.is_empty() {
            None
        } else {
            let mut vals = known;
            vals.sort_by_key(|v| std::cmp::Reverse(v.len()));
            vals.dedup();
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&vals)
                    .expect("known-value automaton"),
            )
        };

        let allow_count = all.iter().map(|r| r.allow.len()).sum();
        Scanner {
            all,
            keyword_ac,
            keyword_rules,
            unconditional,
            rules: (0..RULES.len() + EXTRA.len())
                .map(|_| CompiledRule {
                    rx: OnceCell::new(),
                })
                .collect(),
            known_ac,
            // A bare high-entropy run with no keyword near it. Maximal runs are
            // matched and then filtered by length, so a long run is skipped
            // whole rather than masked in fragments.
            // shortcut: no contextual evidence, so a random-looking 20-80 byte
            // identifier gets masked too; upgrade if that proves noisy.
            extra: bytes_regex(r"[A-Za-z0-9+/_-]+"),
            b64: bytes_regex(r"[A-Za-z0-9+/_-]+={0,2}"),
            allow: (0..allow_count).map(|_| OnceCell::new()).collect(),
        }
    }

    /// Compile every rule. Returns `(rule id, error)` for the ones that fail.
    pub fn verify(&self) -> Vec<(String, String)> {
        let mut failures = Vec::new();
        for (i, r) in self.all.iter().enumerate() {
            if let Err(e) = self.compiled(i) {
                failures.push((r.id.to_string(), e));
            }
        }
        failures
    }

    fn compiled(&self, idx: usize) -> Result<Option<&Regex>, String> {
        let slot = &self.rules[idx].rx;
        if let Some(v) = slot.get() {
            return Ok(v.as_ref());
        }
        match bytes_regex_checked(self.all[idx].regex) {
            Ok(rx) => {
                let _ = slot.set(Some(rx));
                Ok(slot.get().and_then(|o| o.as_ref()))
            }
            // An uncompilable rule is a hole in coverage, not a crash.
            Err(e) => Err(e),
        }
    }

    fn candidates(&self, hay: &[u8]) -> Vec<usize> {
        let mut set = BTreeSet::new();
        for i in &self.unconditional {
            set.insert(*i);
        }
        if let Some(ac) = &self.keyword_ac {
            for m in ac.find_iter(hay) {
                for r in &self.keyword_rules[m.pattern().as_usize()] {
                    set.insert(*r);
                }
            }
        }
        set.into_iter().collect()
    }

    fn suppressed(&self, rule_idx: usize, secret: &[u8], hay: &[u8], start: usize) -> bool {
        let allow = self.all[rule_idx].allow;
        if allow.is_empty() {
            return false;
        }
        let mut slot = 0usize;
        for prev in 0..rule_idx {
            slot += self.all[prev].allow.len();
        }
        for (k, a) in allow.iter().enumerate() {
            let cell = &self.allow[slot + k];
            let rx = cell.get_or_init(|| bytes_regex_checked(a.regex).ok());
            let Some(rx) = rx else { continue };
            let subject: &[u8] = if a.line {
                let line_start = hay[..start]
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let line_end = hay[start..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|p| start + p)
                    .unwrap_or(hay.len());
                &hay[line_start..line_end]
            } else {
                secret
            };
            if rx.is_match(subject) {
                return true;
            }
        }
        false
    }

    /// Trim an assignment-shaped match down to its value: `API_KEY=abc` masks
    /// `abc`, not the whole `API_KEY=abc`.
    fn value_start(matched: &[u8]) -> usize {
        let mut cut = 0usize;
        for (i, b) in matched.iter().enumerate() {
            if *b == b'=' || *b == b':' {
                cut = i + 1;
            }
        }
        if cut > 0 && matched.len() - cut >= 8 {
            let mut i = cut;
            while i < matched.len() {
                match matched[i] {
                    b' ' | b'\t' | b'"' | b'\'' | b'`' | b'=' => i += 1,
                    _ => break,
                }
            }
            i
        } else {
            0
        }
    }

    fn hits(&self, hay: &[u8]) -> Vec<(usize, usize, usize)> {
        let mut out = Vec::new();
        for idx in self.candidates(hay) {
            let rule = self.all[idx];
            let Ok(Some(rx)) = self.compiled(idx) else {
                continue;
            };
            for caps in rx.captures_iter(hay) {
                let whole = caps.get(0).expect("group 0");
                let (start, secret) = match rule.secret_group {
                    Some(g) => match caps.get(g) {
                        Some(m) => (m.start(), m.as_bytes()),
                        None => continue,
                    },
                    None => {
                        let cut = Self::value_start(whole.as_bytes());
                        (whole.start() + cut, &whole.as_bytes()[cut..])
                    }
                };
                let secret = match secret.iter().rposition(|b| !b.is_ascii_whitespace()) {
                    Some(p) => &secret[..=p],
                    None => continue,
                };
                if secret.len() < 8 {
                    continue;
                }
                if let Some(min) = rule.entropy {
                    if entropy(secret) < min {
                        continue;
                    }
                }
                out.push((start, start + secret.len(), idx));
            }
        }
        out
    }

    pub fn scan(&self, text: &str) -> Vec<Span> {
        let hay = text.as_bytes();
        let mut spans: Vec<Span> = Vec::new();

        if let Some(ac) = &self.known_ac {
            for m in ac.find_iter(hay) {
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    rule: "known-value",
                });
            }
        }

        for (start, end, idx) in self.hits(hay) {
            if self.suppressed(idx, &hay[start..end], hay, start) {
                continue;
            }
            spans.push(Span {
                start,
                end,
                rule: self.all[idx].id,
            });
        }

        // Bare high-entropy run, no keyword required.
        for m in self.extra.find_iter(hay) {
            let s = m.as_bytes();
            if m.len() > MAX_BARE_RUN || hash_prefixed(hay, m.start()) {
                continue;
            }
            let has_digit = s.iter().any(|b| b.is_ascii_digit());
            let mixed =
                s.iter().any(u8::is_ascii_lowercase) && s.iter().any(u8::is_ascii_uppercase);
            if has_digit && mixed && entropy(s) >= 4.5 {
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    rule: "high-entropy",
                });
            }
        }

        // Encoded payloads: mask the encoded run when the decoded form trips a rule.
        for m in self.b64.find_iter(hay) {
            if m.len() > MAX_B64_RUN {
                continue;
            }
            if let Some(decoded) = decode_b64(m.as_bytes()) {
                let decoded = String::from_utf8_lossy(&decoded);
                if self.any_hit(decoded.as_bytes(), 1) {
                    spans.push(Span {
                        start: m.start(),
                        end: m.end(),
                        rule: "base64",
                    });
                }
            }
        }

        merge(text, spans)
    }

    pub fn extra_bench(&self, hay: &[u8]) -> usize {
        self.extra.find_iter(hay).count()
    }

    pub fn b64_bench(&self, hay: &[u8]) -> usize {
        self.b64.find_iter(hay).count()
    }

    fn any_hit(&self, hay: &[u8], depth: usize) -> bool {
        if self
            .known_ac
            .as_ref()
            .map(|ac| ac.is_match(hay))
            .unwrap_or(false)
        {
            return true;
        }
        for idx in self.candidates(hay) {
            let rule = self.all[idx];
            let Ok(Some(rx)) = self.compiled(idx) else {
                continue;
            };
            for caps in rx.captures_iter(hay) {
                let whole = caps.get(0).expect("group 0");
                let secret = match rule.secret_group {
                    Some(g) => match caps.get(g) {
                        Some(m) => m.as_bytes(),
                        None => continue,
                    },
                    None => {
                        let cut = Self::value_start(whole.as_bytes());
                        &whole.as_bytes()[cut..]
                    }
                };
                if secret.len() < 8 {
                    continue;
                }
                if let Some(min) = rule.entropy {
                    if entropy(secret) < min {
                        continue;
                    }
                }
                return true;
            }
        }
        if depth < 2 {
            for m in self.b64.find_iter(hay) {
                if let Some(decoded) = decode_b64(m.as_bytes()) {
                    if self.any_hit(&decoded, depth + 1) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn bytes_regex(pattern: &str) -> Regex {
    bytes_regex_checked(pattern).expect("static regex")
}

fn bytes_regex_checked(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(SIZE_LIMIT)
        .build()
        .map_err(|e| e.to_string())
}

fn decode_b64(s: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let text = std::str::from_utf8(s).ok()?;
    let trimmed = text.trim_end_matches('=');
    if trimmed.len() < 16 {
        return None;
    }
    let bytes = STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()?;
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\t')
        .count();
    if printable * 10 < bytes.len() * 9 {
        return None;
    }
    Some(bytes)
}

/// `sha256-`, `sha512-`, `md5-`: content digests, not credentials.
fn hash_prefixed(hay: &[u8], start: usize) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"sha1-", b"sha256-", b"sha384-", b"sha512-", b"md5-", b"blake3-",
    ];
    PREFIXES.iter().any(|p| {
        let from = start.saturating_sub(p.len() + 4);
        hay[from..start].windows(p.len()).any(|w| w == *p)
    })
}

/// Sort, clamp to char boundaries and merge overlapping spans.
fn merge(text: &str, mut spans: Vec<Span>) -> Vec<Span> {
    for s in spans.iter_mut() {
        s.start = floor_boundary(text, s.start);
        s.end = ceil_boundary(text, s.end);
    }
    spans.sort_by_key(|s| (s.start, s.end));
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        if s.start >= s.end {
            continue;
        }
        match out.last_mut() {
            Some(prev) if s.start <= prev.end => {
                if s.end > prev.end {
                    prev.end = s.end;
                }
            }
            _ => out.push(s),
        }
    }
    out
}

fn floor_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(text: &str, i: usize) -> usize {
    let mut i = i.min(text.len());
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Replace every span with a 4-char prefix plus `…[REDACTED]`.
pub fn mask(text: &str, spans: &[Span]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0usize;
    for s in spans {
        if s.start < pos || s.end > text.len() {
            continue;
        }
        out.push_str(&text[pos..s.start]);
        let span = &text[s.start..s.end];
        let keep = if span.len() > 8 { 4 } else { 0 };
        let mut cut = keep.min(span.len());
        while cut > 0 && !span.is_char_boundary(cut) {
            cut -= 1;
        }
        out.push_str(&span[..cut]);
        out.push_str(MASK);
        pos = s.end;
    }
    out.push_str(&text[pos..]);
    out
}

pub fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}
