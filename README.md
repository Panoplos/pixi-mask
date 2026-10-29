<p align="center">
  <a href="https://github.com/Panoplos/pixi-mask">
    <img alt="pixi-mask" src="docs/images/pixi-mask-logo.png" width="200">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Panoplos/pixi-mask/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-5865F2?style=flat-square" /></a>
  <a href="https://github.com/gitleaks/gitleaks"><img alt="rules" src="https://img.shields.io/badge/rules-gitleaks%20default%20set-8B5CF6?style=flat-square" /></a>
  <img alt="speed" src="https://img.shields.io/badge/108%20KB-in%206%20ms-16A34A?style=flat-square" />
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

Secret scanning is a solved problem with a known good answer:
[gitleaks](https://github.com/gitleaks/gitleaks) and its 220-rule default set.
The hard part is running it *inline*, on text, at millisecond cost, without
flooding the agent with false positives and without rewriting code that isn't
secret.

`pixi-mask` vendors that ruleset and runs it the way gitleaks runs it — keyword
prefilter, then rule regex, then a Shannon entropy gate — with three changes
that matter for inline use:

- **ASCII-only regexes.** Compiling all 220 rules takes ~11 ms instead of
  ~1000 ms. It is also what RE2 does in gitleaks, so semantics stay identical.
  Rules compile lazily, and only when their keyword is present, so a text
  without keywords is essentially free.
- **`generic-api-key` replaced.** The vendored rule accepts `,`, `>` and `||` as
  separators, so it fires on `import { hasAzureOpenAICredentials, y }` and
  `"api": "openai-completions"`. In 400 real files that was 322 hits. Two
  tighter rules (`= | :` only, value 16+ chars with a digit, or 24+ letters with
  no dots) bring it to 2.
- **A base64 pass** (depth 2), so an encoded blob is masked when its decoded
  form trips a rule.

Measured on 38 realistic provider samples and 3.9 MB of a real repository:

| | pixi-mask | gitleaks |
|---|---|---|
| samples caught (of 38) | **36** | 28 |
| gaps against gitleaks | none | — |
| false positives, 400 files / 102K lines | 2 | 322 |

The hook this replaced caught 15 of 38.

The two that survive are a 62-character alphabet string in a classifier and a
fixture id in a test. Neither is a hash: bare `sha*`/`md5`-prefixed runs and
unlabelled 64-hex are deliberately skipped, because masking every checksum in a
repo is worse than the risk.

## Speed

Whole binary, process start included, on an M-series Mac:

| input | pixi-mask | gitleaks |
|---|---|---|
| 47 KB prose (no keywords) | 4 ms | — |
| 108 KB TypeScript | **6 ms** | 47 ms |
| 159 KB mixed | 7 ms | — |

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

- `hf_`, `gsk_`, `xai-`, `sbp_`/`sbr_`, `dckr_pat_`, Bitdeer keys and
  connection-string passwords (`postgres://user:pw@host`), none of which the
  gitleaks set catches.
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
- Allowlists that need a file path, a commit or a stopword list cannot apply to
  free text, so a few code-shaped false positives remain.
- It is a mask, not a sandbox. Text that never passes through the pipe is not
  covered; the point is to make the pipe the default path.

## Rules

`rules/gitleaks.toml` is the gitleaks default config, unmodified.
`tools/gen-rules.py` turns it into `src/rules.rs`:

```bash
python3 tools/gen-rules.py          # regenerate
python3 tools/gen-rules.py --check  # fail if src/rules.rs is stale
```

The generator drops path-only rules and path/commit-scoped allowlists (free
text has no path) and keeps everything else. Output goes through `rustfmt`, so
`cargo fmt --check` never fights it. Updating the ruleset: drop in a fresh
`gitleaks.toml`, regenerate, re-run the tests.

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

MIT. The vendored ruleset is gitleaks, also MIT; that attribution is at the top
of `src/rules.rs`.
