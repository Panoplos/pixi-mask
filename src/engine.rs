// Detection engine: keyword prefilter -> rule regexes -> entropy -> allowlists,
// plus exact known values, a bare high-entropy rule, and an encoded-segment pass
// that decodes base64, hex and percent runs and rescans each one in context.
//
// Same shape as betterleaks (regex + keywords + entropy), with three differences
// that matter for a text scanner: path-based skips are gone (we see text),
// matches are masked in place instead of reported, and an encoded segment is
// decoded up to `Config::depth` times with the decoded bytes substituted for the
// original, so a keyword rule still sees the name in front of the value.
//
// Regexes are compiled ASCII-only (`unicode(false)`). That is what RE2 does in
// both upstream scanners, and it keeps the whole 452-rule set under ~30 ms to
// compile instead of ~1 s: unicode `\w` expands into huge character classes.

use std::collections::BTreeSet;
use std::sync::OnceLock;

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

// Longest encoded run worth trying to decode.
const MAX_ENCODED_RUN: usize = 8000;

// Bytes of original text kept on each side of a decoded segment, so keyword
// rules see the assignment name and line-scoped allowlists see the line.
const DECODE_CONTEXT: usize = 512;

// Decode attempts allowed per scan. Nested payloads multiply, and a hostile
// input must not turn depth 5 into a quadratic walk.
const MAX_DECODE_CALLS: usize = 4096;

pub const MASK: &str = "…[REDACTED]";

/// Which encoded forms a scanner decodes. All three are on by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decode {
    pub base64: bool,
    pub hex: bool,
    pub percent: bool,
}

impl Decode {
    pub const NONE: Decode = Decode {
        base64: false,
        hex: false,
        percent: false,
    };
    pub const ALL: Decode = Decode {
        base64: true,
        hex: true,
        percent: true,
    };

    fn enabled(&self, codec: Codec) -> bool {
        match codec {
            Codec::Base64 => self.base64,
            Codec::Hex => self.hex,
            Codec::Percent => self.percent,
        }
    }
}

/// What a scanner runs on top of the vendored betterleaks rules.
///
/// `extra` adds the hand-written rules in `src/extra.rs`: `assignment-secret`,
/// `assignment-secret-letters`, `bearer-token`, `connection-string-password`
/// and the provider shapes betterleaks already covers (`hf_`, `gsk_`, `xai-`,
/// `sbp_`, `dckr_pat_`, Bitdeer). The vendored set has no generic `NAME=value`
/// rule, so turning `extra` off also drops that coverage.
///
/// `bare_entropy` adds the 20-80 byte mixed-case-with-a-digit rule that needs no
/// keyword and no prefix. It is the rule that catches letters-only keys, and the
/// one that masks prose that happens to be base64.
#[derive(Clone, Debug)]
pub struct Config {
    pub known: Vec<String>,
    pub extra: bool,
    pub bare_entropy: bool,
    pub decode: Decode,
    pub depth: usize,
}

impl Config {
    /// Every rule, every decoder, two decode rounds: what the CLI does.
    pub fn new(known: Vec<String>) -> Config {
        Config {
            known,
            extra: true,
            bare_entropy: true,
            decode: Decode::ALL,
            depth: 2,
        }
    }
}

pub struct CompiledRule {
    rx: OnceLock<Option<Regex>>,
}

pub struct Scanner {
    all: Vec<&'static Rule>,
    bare_entropy: bool,
    decode: Decode,
    depth: usize,
    keyword_ac: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    unconditional: Vec<usize>,
    rules: Vec<CompiledRule>,
    known_ac: Option<AhoCorasick>,
    bare: Regex,
    b64: Regex,
    hex: Regex,
    percent: Regex,
    allow: Vec<OnceLock<Option<Regex>>>,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Codec {
    Base64,
    Hex,
    Percent,
}

const CODECS: [Codec; 3] = [Codec::Base64, Codec::Hex, Codec::Percent];

impl Codec {
    fn rule(self) -> &'static str {
        match self {
            Codec::Base64 => "base64",
            Codec::Hex => "hex",
            Codec::Percent => "percent",
        }
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
    /// Lazy: a rule's regex is compiled the first time its keyword shows up.
    /// A rule that does not compile is skipped by `scan` without a word, so a
    /// caller that cannot run `rules --verify` in CI wants [`Scanner::checked`].
    pub fn new(known: Vec<String>) -> Scanner {
        Scanner::with_config(Config::new(known))
    }

    pub fn with_config(config: Config) -> Scanner {
        let mut all: Vec<&'static Rule> = RULES.iter().collect();
        if config.extra {
            all.extend(EXTRA.iter());
        }

        let mut keywords: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();

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
                    // Standard + overlapping iteration: `secret` and
                    // `secret_key` must both be reported. LeftmostFirst finds
                    // only the shorter one and hides every rule keyed on the
                    // longer keyword.
                    .match_kind(MatchKind::Standard)
                    .build(&keywords)
                    .expect("keyword automaton"),
            )
        };

        let known_ac = if config.known.is_empty() {
            None
        } else {
            let mut vals = config.known;
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
            rules: (0..all.len())
                .map(|_| CompiledRule {
                    rx: OnceLock::new(),
                })
                .collect(),
            all,
            bare_entropy: config.bare_entropy,
            decode: config.decode,
            depth: config.depth,
            keyword_ac,
            keyword_rules,
            unconditional,
            known_ac,
            // shortcut: no contextual evidence, so a random-looking 20-80 byte
            // identifier gets masked too; upgrade if that proves noisy.
            bare: bytes_regex(r"[A-Za-z0-9+/_-]+"),
            b64: bytes_regex(r"[A-Za-z0-9+/_-]+={0,2}"),
            hex: bytes_regex(r"[0-9A-Fa-f]{32,}"),
            percent: bytes_regex(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-])+"),
            allow: (0..allow_count).map(|_| OnceLock::new()).collect(),
        }
    }

    /// Like [`Scanner::new`], but compiles every rule up front and reports the
    /// ones that failed. An admission path should use this and refuse to start.
    pub fn checked(config: Config) -> Result<Scanner, Vec<(String, String)>> {
        let scanner = Scanner::with_config(config);
        let failures = scanner.verify();
        if failures.is_empty() {
            Ok(scanner)
        } else {
            Err(failures)
        }
    }

    /// Compile every rule and allowlist. Returns `(rule id, error)` for the
    /// ones that fail: a rule that does not compile is a hole in coverage.
    pub fn verify(&self) -> Vec<(String, String)> {
        let mut failures = Vec::new();
        for (i, r) in self.all.iter().enumerate() {
            if let Err(e) = self.compiled(i) {
                failures.push((r.id.to_string(), e));
            }
            for a in r.allow {
                if let Err(e) = bytes_regex_checked(a.regex) {
                    failures.push((r.id.to_string(), format!("allowlist: {e}")));
                }
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
            for m in ac.find_overlapping_iter(hay) {
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

    /// Scan UTF-8 text. Spans land on char boundaries, so [`mask`] can slice.
    pub fn scan(&self, text: &str) -> Vec<Span> {
        self.scan_impl(text.as_bytes(), Some(text))
    }

    /// Scan bytes, for callers that hold a file or a pipe rather than a `str`.
    pub fn scan_bytes(&self, hay: &[u8]) -> Vec<Span> {
        self.scan_impl(hay, None)
    }

    fn scan_impl(&self, hay: &[u8], text: Option<&str>) -> Vec<Span> {
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
        if self.bare_entropy {
            for m in self.bare.find_iter(hay) {
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
        }

        // Encoded payloads: mask the encoded run when its decoded form, in the
        // context it was found in, trips a rule.
        if self.depth > 0 {
            let mut budget = MAX_DECODE_CALLS;
            'codecs: for codec in CODECS {
                if !self.decode.enabled(codec) {
                    continue;
                }
                for m in self.codec_regex(codec).find_iter(hay) {
                    if m.len() > MAX_ENCODED_RUN {
                        continue;
                    }
                    let Some(decoded) = decode_run(codec, m.as_bytes()) else {
                        continue;
                    };
                    if self.decoded_hit(hay, m.start(), m.end(), &decoded, self.depth, &mut budget)
                    {
                        spans.push(Span {
                            start: m.start(),
                            end: m.end(),
                            rule: codec.rule(),
                        });
                    }
                    if budget == 0 {
                        break 'codecs;
                    }
                }
            }
        }

        match text {
            Some(t) => merge(t, spans),
            None => merge_bytes(spans),
        }
    }

    fn codec_regex(&self, codec: Codec) -> &Regex {
        match codec {
            Codec::Base64 => &self.b64,
            Codec::Hex => &self.hex,
            Codec::Percent => &self.percent,
        }
    }

    /// Decode one run, substitute the decoded bytes for it with the surrounding
    /// text kept, and rescan that window. A hit counts only if it overlaps the
    /// substituted bytes; a hit elsewhere in the window belongs to the outer
    /// scan, which already has it.
    fn decoded_hit(
        &self,
        hay: &[u8],
        start: usize,
        end: usize,
        decoded: &[u8],
        depth: usize,
        budget: &mut usize,
    ) -> bool {
        if depth == 0 || *budget == 0 {
            return false;
        }
        *budget -= 1;

        let from = start.saturating_sub(DECODE_CONTEXT);
        let to = (end + DECODE_CONTEXT).min(hay.len());
        let mut window = Vec::with_capacity((start - from) + decoded.len() + (to - end));
        window.extend_from_slice(&hay[from..start]);
        let decoded_start = window.len();
        window.extend_from_slice(decoded);
        let decoded_end = window.len();
        window.extend_from_slice(&hay[end..to]);

        if self.window_hit(&window, decoded_start, decoded_end) {
            return true;
        }
        if depth == 1 {
            return false;
        }

        for codec in CODECS {
            if !self.decode.enabled(codec) {
                continue;
            }
            for m in self.codec_regex(codec).find_iter(decoded) {
                if m.len() > MAX_ENCODED_RUN {
                    continue;
                }
                let Some(inner) = decode_run(codec, m.as_bytes()) else {
                    continue;
                };
                if self.decoded_hit(decoded, m.start(), m.end(), &inner, depth - 1, budget) {
                    return true;
                }
                if *budget == 0 {
                    return false;
                }
            }
        }
        false
    }

    fn window_hit(&self, window: &[u8], from: usize, to: usize) -> bool {
        if let Some(ac) = &self.known_ac {
            for m in ac.find_iter(window) {
                if m.start() < to && from < m.end() {
                    return true;
                }
            }
        }
        self.hits(window)
            .into_iter()
            .any(|(start, end, _)| start < to && from < end)
    }

    pub fn extra_bench(&self, hay: &[u8]) -> usize {
        self.bare.find_iter(hay).count()
    }

    pub fn b64_bench(&self, hay: &[u8]) -> usize {
        self.b64.find_iter(hay).count()
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

fn decode_run(codec: Codec, run: &[u8]) -> Option<Vec<u8>> {
    match codec {
        Codec::Base64 => decode_b64(run),
        Codec::Hex => decode_hex(run),
        Codec::Percent => decode_percent(run),
    }
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
    printable(&bytes).then_some(bytes)
}

fn decode_hex(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() < 32 || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        out.push(hex_value(pair[0])? << 4 | hex_value(pair[1])?);
    }
    printable(&out).then_some(out)
}

fn decode_percent(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() < 8 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len());
    let mut escapes = 0usize;
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            if let (Some(hi), Some(lo)) = (hex_value(s[i + 1]), hex_value(s[i + 2])) {
                out.push(hi << 4 | lo);
                escapes += 1;
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    if escapes == 0 || !printable(&out) {
        return None;
    }
    Some(out)
}

/// A decoded run is worth rescanning only if it looks like text: 90% printable
/// ASCII, the same floor betterleaks' decoder uses for base64.
fn printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let ok = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\t')
        .count();
    ok * 10 >= bytes.len() * 9
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
    merge_bytes(spans)
}

fn merge_bytes(mut spans: Vec<Span>) -> Vec<Span> {
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
