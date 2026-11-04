#!/usr/bin/env python3
"""Generate src/rules.rs from rules/betterleaks.toml.

The betterleaks default config is one TOML table per rule. Only the fields that
decide "does this text contain a secret" are kept; provider validation,
component assembly and path rules are not, so a hand-rolled parser keeps the
toolchain to std + a few crates.

betterleaks filters false positives with Expr. Two constructs from those
expressions survive the translation into this scanner's own filter model:

  entropy(finding["secret"]) < X   -> the rule's entropy floor, X
  matchesAny(finding["secret"], [..]) containedAny(...) startsWithAny(...)
                                   -> allowlist regexes (filter true = skip)

Everything else in a filter is dropped: `tokenRatio` and
`failsTokenEfficiency` (tokenizer heuristics), negated matches, path and
multi-line context conditions, and multi-statement `let` blocks. A dropped
term only ever means fewer findings are discarded, and this scanner still
gates every rule on length, entropy and its own allowlists.

Usage: python3 tools/gen-rules.py [--check]
  --check  exit 1 if src/rules.rs is stale instead of rewriting it
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "rules" / "betterleaks.toml"
OUT = ROOT / "src" / "rules.rs"

# The three generic rules match `NAME=<value>` with no notion of what the value
# looks like, and lean on Expr heuristics to throw away the false positives.
# Without those they mask ordinary code (`import { hasAzureOpenAICredentials }`),
# usernames and prose. src/extra.rs carries a tightened replacement for the
# first; a username is not a secret, so the other two have none.
DROP = {"generic-api-key", "generic-password", "generic-username"}

# `*-client-id` rules match public OAuth client identifiers: they ship inside
# client apps and are not secrets, so masking them eats real code
# (`const CLIENT_ID = "17e5f671-…"`) for nothing.
DROP_PATTERN = re.compile(r"^[a-z0-9.-]*client-id(?:\.\d+)?$")

# Expressions betterleaks uses to discard a match, keyed by the function name.
ALLOW_CALLS = ("matchesAny", "containsAny", "startsWithAny")


def blocks(text):
    return re.split(r"(?m)^\[\[rules\]\]\s*$", text)[1:]


def quoted(body, key):
    """A TOML string value: literal '''...''', basic "..." or literal '...'."""
    m = re.search(r"(?ms)^" + key + r"\s*=\s*'''(.*?)'''", body)
    if m:
        return m.group(1)
    m = re.search(r"""(?m)^""" + key + r"""\s*=\s*("(?:[^"\\]|\\.)*")\s*$""", body)
    if m:
        return unquote(m.group(1))
    m = re.search(r"(?m)^" + key + r"\s*=\s*'([^']*)'\s*$", body)
    if m:
        return m.group(1)
    return None


def unquote(s):
    """Decode a double-quoted TOML basic string, leaving regex escapes alone."""
    if not (s.startswith('"') and s.endswith('"') and len(s) >= 2):
        return s
    out = []
    i = 1
    while i < len(s) - 1:
        c = s[i]
        if c == "\\" and i + 1 < len(s) - 1:
            n = s[i + 1]
            if n == '"':
                out.append('"')
                i += 2
                continue
            if n == "\\":
                out.append("\\")
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def literals(text, i):
    """Read string literals from a TOML/Expr array starting at `text[i] == '['`.

    A pattern can contain `]` inside a character class, so the end of the array
    cannot be found by looking for the first `]`; walk the literals instead.
    Returns (items, index after the closing bracket).
    """
    items = []
    while i < len(text):
        c = text[i]
        if text.startswith("'''", i):
            end = text.find("'''", i + 3)
            if end < 0:
                raise SystemExit("unterminated ''' in array")
            items.append(text[i + 3 : end])
            i = end + 3
        elif c in "\"'`":
            quote = c
            j = i + 1
            while j < len(text) and text[j] != quote:
                j += 2 if (text[j] == "\\" and quote == '"') else 1
            body = text[i + 1 : j]
            items.append(unquote(body) if quote == '"' else body)
            i = j + 1
        elif c == "]":
            return items, i + 1
        elif c in " \t\r\n,":
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        else:
            raise SystemExit("unexpected %r in array at %d" % (c, i))
    raise SystemExit("unterminated array")


def string_array(body, key):
    m = re.search(r"(?m)^" + key + r"\s*=\s*\[", body)
    if not m:
        return []
    return literals(body, m.end())[0]


def allow_calls(expr, pos):
    """Translate `matchesAny/containsAny/startsWithAny` calls at `pos`.

    A negated call (`!matchesAny(...)`) means "skip when the secret does *not*
    look like this", which is a requirement rather than an allowlist, so it is
    left out. So is any call on a subject other than the secret: this scanner
    has no path and no match context to test against.
    """
    out = []
    for m in re.finditer(r"\b(" + "|".join(ALLOW_CALLS) + r')\(\s*finding\["(\w+)"\]\s*,\s*\[', expr):
        before = expr[: m.start()].rstrip()
        if before.endswith("!"):
            continue
        if m.group(2) != "secret":
            continue
        items, _ = literals(expr, m.end())
        for item in items:
            if not item.strip():
                continue
            if m.group(1) == "matchesAny":
                out.append(item)
            elif m.group(1) == "containsAny":
                out.append(re.escape(item))
            else:
                out.append("^" + re.escape(item))
    return out


def translate(rid, expr):
    """Rule fields this scanner can act on, read out of a betterleaks filter."""
    if not expr or not expr.strip():
        return None, []
    m = re.search(r'entropy\(finding\["secret"\]\)\s*(?:<=|<)\s*([0-9.]+)', expr)
    entropy = float(m.group(1)) if m else None
    allow = [rust_regex(rx) for rx in allow_calls(expr, 0)]
    for rx in allow:
        if not rx.strip():
            raise SystemExit("empty allowlist regex in rule %s" % rid)
    return entropy, allow


def rustfmt(source):
    """Format through rustfmt so `cargo fmt` never makes the output stale."""
    try:
        res = subprocess.run(
            ["rustfmt", "--edition", "2021", "--emit", "stdout"],
            input=source,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return source
    if res.returncode != 0 or not res.stdout.strip():
        raise SystemExit("rustfmt failed: %s" % res.stderr.strip())
    return res.stdout


def rust_regex(pattern):
    """Make a Go/RE2 pattern compile in the Rust regex crate.

    Go treats `{` that does not start a valid repetition as a literal, so the
    rules write template placeholders as `{{ VAR }}`; Rust rejects the doubled
    brace as a malformed quantifier. A doubled brace is never a quantifier, so
    escaping it is safe.
    """
    return pattern.replace("{{", r"\{\{").replace("}}", r"\}\}")


def rust_str(s):
    if '"#' not in s:
        return 'r#"' + s + '"#'
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    text = CONFIG.read_text()
    rules = []
    dropped = []
    for block in blocks(text):
        raw_id = quoted(block, "id")
        if not raw_id:
            continue
        rid = raw_id
        regex = quoted(block, "regex")
        if not regex:
            # Path-only rules: this scanner sees text, not file names.
            dropped.append(rid)
            continue
        if rid in DROP or DROP_PATTERN.match(rid):
            dropped.append(rid)
            continue
        if not regex.strip():
            raise SystemExit("empty regex in rule %s" % rid)
        regex = rust_regex(regex)

        entropy, allow = translate(rid, quoted(block, "filter"))
        group = quoted(block, "valueGroup")
        keywords = [k.lower() for k in string_array(block, "keywords")]

        rules.append(
            {
                "id": rid,
                "regex": regex,
                "entropy": entropy,
                "secret_group": int(group) if group else None,
                "keywords": keywords,
                "allow": allow,
            }
        )

    out = []
    out.append("// @generated by tools/gen-rules.py from rules/betterleaks.toml - do not edit.\n")
    out.append("// Rules: betterleaks default config (MIT, github.com/betterleaks/betterleaks).\n")
    out.append("// Path-only rules are dropped: this scanner sees text, not paths.\n")
    out.append("// Filters are reduced to an entropy floor plus allowlist regexes; provider\n")
    out.append("// validation and token-ratio heuristics are not carried over.\n\n")
    out.append("pub struct Allow {\n    pub regex: &'static str,\n    pub line: bool,\n}\n\n")
    out.append("pub struct Rule {\n")
    out.append("    pub id: &'static str,\n")
    out.append("    pub regex: &'static str,\n")
    out.append("    pub entropy: Option<f64>,\n")
    out.append("    pub secret_group: Option<usize>,\n")
    out.append("    pub keywords: &'static [&'static str],\n")
    out.append("    pub allow: &'static [Allow],\n")
    out.append("}\n\n")
    out.append("pub static RULES: &[Rule] = &[\n")
    for r in rules:
        out.append("    Rule {\n")
        out.append("        id: %s,\n" % rust_str(r["id"]))
        out.append("        regex: %s,\n" % rust_str(r["regex"]))
        out.append(
            "        entropy: %s,\n"
            % ("None" if r["entropy"] is None else "Some(%r)" % r["entropy"])
        )
        out.append(
            "        secret_group: %s,\n"
            % ("None" if r["secret_group"] is None else "Some(%d)" % r["secret_group"])
        )
        out.append("        keywords: &[%s],\n" % ", ".join(rust_str(k) for k in r["keywords"]))
        if r["allow"]:
            out.append("        allow: &[\n")
            for rx in r["allow"]:
                out.append("            Allow { regex: %s, line: false },\n" % rust_str(rx))
            out.append("        ],\n")
        else:
            out.append("        allow: &[],\n")
        out.append("    },\n")
    out.append("];\n")

    generated = rustfmt("".join(out))
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != generated:
            print("src/rules.rs is stale; run python3 tools/gen-rules.py", file=sys.stderr)
            return 1
        print("src/rules.rs is up to date (%d rules)" % len(rules))
        return 0
    OUT.write_text(generated)
    print(
        "wrote %s: %d rules, %d dropped (%s)"
        % (OUT, len(rules), len(dropped), ", ".join(dropped))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
