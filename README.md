<p align="center">
  <a href="https://github.com/Panoplos/pixi-mask">
    <img alt="pixi-mask" src="docs/images/pixi-mask-logo.png" width="200">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Panoplos/pixi-mask/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-5865F2?style=flat-square" /></a>
  <a href="https://github.com/betterleaks/betterleaks"><img alt="rules" src="https://img.shields.io/badge/rules-betterleaks%20default%20set-8B5CF6?style=flat-square" /></a>
  <img alt="speed" src="https://img.shields.io/badge/108%20KB-in%2012%20ms-16A34A?style=flat-square" />
</p>

# pixi-mask

Every secret your coding agent can read is a secret in a prompt, a log, a
transcript, or someone else's cache. `pixi-mask` is the gate in front of that
pipe: text goes in on stdin, the same text comes back with credentials replaced
by `…[REDACTED]`, and a JSON list of what was found goes out alongside it.

One static binary, no runtime, no network. A tool result costs about 5 ms, so
it can run on every single one.

```console
$ pixi-mask mask <<< 'OPENAI_API_KEY=d2a148efcc4470a66e6c831ec7e8559fa6272dc9'
OPENAI_API_KEY=d2a1…[REDACTED]
pixi-mask: masked 1 value(s) [assignment-secret]
```

Names survive, values don't. You keep `OPENAI_API_KEY=`, so the agent can still
reason about the code it is reading — it just can't exfiltrate the key.

## Why this one

Secret scanning is a solved problem with a known good answer.
[Gitleaks](https://github.com/gitleaks/gitleaks) froze its rule set — "feature
complete, future releases will be security patches only" — and its author moved
to [betterleaks](https://github.com/betterleaks/betterleaks): 452 matching rules
against gitleaks' 220, each ranked by confidence, with provider validation and
token-shape heuristics.

`pixi-mask` vendors the betterleaks rule set and runs it the way both tools run
it — keyword prefilter, then rule regex, then an entropy gate — with four
changes that matter for inline use:

- **ASCII-only regexes.** Compiling all 452 rules takes ~27 ms instead of
  ~1000 ms. It is also what RE2 does in both tools, so semantics stay identical.
  Rules compile lazily, and only when their keyword is present, so a text
  without keywords is essentially free.
- **Filters cut down to what a text scanner can honour.** betterleaks discards
  false positives with Expr expressions. 279 of its rules use nothing but an
  entropy floor (`entropy(finding["secret"]) <= 3.8`), which maps 1:1; the
  rest also use `tokenRatio`, path conditions or multi-statement blocks, and
  only their entropy floor survives. A dropped term can only mean fewer
  findings are discarded, so these rules mask more than betterleaks would.
- **The generic rules are replaced.** `generic-api-key`, `generic-password` and
  `generic-username` match `NAME=<value>` and lean entirely on Expr heuristics
  to throw away the noise. Without them, on 400 real source files, they add 92
  hits: `import { hasAzureOpenAICredentials }`, `CLIENT_ID = ...` and prose.
  Two tighter rules (`= | :` only, value 16+ chars with a digit, or 24+ letters
  with no dots) add one. The 18 `*-client-id` rules go too: a public OAuth
  client id is not a secret, and masking it removes a constant the agent may
  need to read.
- **A base64 pass** (depth 2), so an encoded blob is masked when its decoded
  form trips a rule.

Measured on 49 realistic provider samples and 3.3 MB of a real repository:

| | pixi-mask | gitleaks 8.30 |
|---|---|---|
| samples caught (of 49) | **47** | 33 |
| gaps against gitleaks | none | — |
| caught that gitleaks misses | 14 | — |
| findings on 400 source files | 2 | 0 |

The regex-only hook this replaced caught 31 of 49.

The two samples that survive are unlabelled high-entropy blobs: a bare 64-hex
digest and a bare 32-character base32 id. Labelled values (`NAME=<hex>`) are
caught. Neither is a hash: bare `sha*`/`md5`-prefixed runs are deliberately
skipped, because masking every checksum in a repo is worse than the risk.

The two findings on 400 files are both ours rather than provider shapes: an
entropy gate near a 34-character CamelCase type annotation, and a 62-character
alphabet literal in a classifier. Both are the price of catching letters-only
keys with no prefix, and both are listed under Known limits.

## Speed

Whole binary, process start included, on an M-series Mac:

| input | pixi-mask | gitleaks 8.30 |
|---|---|---|
| 2 KB tool result | 5 ms | — |
| 20 KB tool result | 7 ms | — |
| 47 KB prose (no keywords) | 9 ms | — |
| 108 KB TypeScript | **12 ms** | 57 ms |
| 155 KB mixed | 14 ms | 77 ms |

About 2 ms of every run is process start (`/usr/bin/true` costs 1.7 ms here).
The betterleaks refresh costs ~1 ms per 47 KB against the previous 220-rule
set.

Regex is linear-time, so a hostile tool result cannot blow it up. The worst
case is linear; gitleaks' own fast rules still show 145 ms spikes on 20 KB of
junk.

## Install

```bash
cargo install --git https://github.com/Panoplos/pixi-mask
# or from a checkout:
cargo build --release && ln -sf "$PWD/target/release/pixi-mask" ~/.local/bin/pixi-mask
```

## Usage

```
pixi-mask mask [options]     stdin -> masked text on stdout
pixi-mask scan [options]     stdin -> findings; exit 1 if any
pixi-mask rules [--verify]   list rule ids; --verify compiles every rule

Options
  --json                 machine-readable output (mask: {text, findings})
  -q, --quiet            no findings line on stderr
  --no-known             skip exact values from auth.json, .env, ...
  --known-file <path>    add a file of known values (repeatable)
  --known <value>        add one known value (repeatable)
```

`mask --json` prints one object on stdout and nothing on stderr, which is what
a hook wants:

```json
{"text": "OPENAI_API_KEY=d2a1…[REDACTED]", "findings": [{"rule": "assignment-secret", "line": 1, "start": 15, "len": 48}]}
```

`scan` is the same engine with exit codes, for CI and for checking a file
before you decide to gate it:

```console
$ git ls-files -z | xargs -0 cat | pixi-mask scan --json | jq '.findings | length'
```

## Wiring it into an agent

Anything that can pipe text can use it: `pixi-mask mask` reads stdin and writes
masked text to stdout.

For [Pixi](https://github.com/Panoplos/Pixi) / [pi](https://github.com/earendil-works/pi)
there is a ready-made hook,
[`key-guard.ts`](https://github.com/Panoplos/Pixi/blob/main/packages/coding-agent/examples/extensions/key-guard.ts).
It masks every tool result and every user message before either reaches the
model:

```console
$ curl -o ~/.pi/agent/extensions/key-guard.ts \
    https://raw.githubusercontent.com/Panoplos/Pixi/main/packages/coding-agent/examples/extensions/key-guard.ts
```

On each hook call it runs `pixi-mask mask --json` (~5 ms), puts the returned
`text` in place of the original, and warns once per session when `findings` is
not empty. A tool result that was fully masked still reaches the model, so the
model sees `sk-p…[REDACTED]` and can reason about it, but not the key.

The hook keeps an in-process fallback for machines without the binary, so a
missing `pixi-mask` degrades instead of breaking the session. Set
`PIXI_MASK_BIN` to point at a non-standard build. `/reload` re-reads the file;
keys rotated in `auth.json` are picked up on the next process start.

## What it knows

Beyond the vendored rules:

- Bitdeer keys and connection-string passwords (`postgres://user:pw@host`),
  which no upstream rule set catches. Hugging Face, Groq, xAI, Supabase and
  Docker tokens the gitleaks set missed are now part of the betterleaks rules
  themselves.
- Any 20-80 byte run with mixed case, a digit and entropy >= 4.5, no keyword
  needed.
- Exact values from `~/.pi/agent/auth.json`, `~/.aws/credentials`,
  `~/.config/gh/hosts.yml`, `~/.npmrc`, `.env`, and `PIXI_MASK_KNOWN`
  (colon-separated paths), matched as literal substrings.
- Values are re-read every run, so a key rotated in `auth.json` is current
  immediately. No restart, no daemon, no cache to invalidate.

## Known limits

- An unlabelled 64-hex or base32 blob is not caught. Labelled values
  (`NAME=<hex>`) are.
- Bare runs longer than 80 bytes are skipped whole rather than masked in
  fragments, so inline base64 assets and npm `integrity` digests stay readable.
- betterleaks' `tokenRatio` and `failsTokenEfficiency` heuristics are not
  ported, so the ~149 rules that use them mask a little more than betterleaks
  would: natural-language values that pass the entropy floor are still masked.
- Nobody validates a credential against the provider's API, on purpose. A
  masking hook must not make network calls, so a revoked or fake key looks the
  same as a live one.
- Path-, commit- and stopword-scoped conditions cannot apply to free text, so a
  few code-shaped false positives remain (`CLIENT_ID`-style identifiers,
  letters-only CamelCase type names next to an assignment).
- It is a mask, not a sandbox. Text that never passes through the pipe is not
  covered; the point is to make the pipe the default path.

## Rules

`rules/betterleaks.toml` is the betterleaks default config, unmodified.
`tools/gen-rules.py` turns it into `src/rules.rs`:

```bash
python3 tools/gen-rules.py          # regenerate
python3 tools/gen-rules.py --check  # fail if src/rules.rs is stale
```

452 of its 474 rules survive the translation. Dropped: five path-only rules,
`pkcs12-file`, the three generic rules (replaced in `src/extra.rs`) and the 18
`*-client-id` rules. Each rule's Expr filter is reduced to its entropy floor
plus allowlist regexes — `matchesAny`/`containsAny`/`startsWithAny` calls on
`finding["secret"]`, which is what an allowlist is — and everything else in
the expression is left out. Doubled braces in Go-oriented patterns are escaped
so they compile in Rust. Output goes through `rustfmt`, so `cargo fmt --check`
never fights it, and `pixi-mask rules --verify` compiles every rule and every
allowlist.

Updating the ruleset: drop in a fresh `betterleaks.toml`, regenerate, run
`cargo test --release` and `rules --verify`.

## Development

```bash
cargo build --release
cargo test --release        # shapes, benign content, boundaries, CLI
python3 tools/gen-rules.py --check
cargo clippy --release --all-targets
```

Test fixtures are generated by a deterministic filler, not copied from real
credentials — no live key has ever been in this repository, and `pixi-mask`
itself is what checks that.

## License

MIT. The vendored rule set is betterleaks', also MIT; that attribution is at
the top of `src/rules.rs`.
