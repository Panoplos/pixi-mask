#!/usr/bin/env python3
"""Generate src/rules.rs from rules/gitleaks.toml.

The gitleaks default config is one TOML table per rule. Only the fields that
matter for scanning text are kept (no paths, no commits, no decode settings),
so a hand-rolled parser keeps the toolchain to std + a few crates.

Usage: python3 tools/gen-rules.py [--check]
  --check  exit 1 if src/rules.rs is stale instead of rewriting it
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "rules" / "gitleaks.toml"
OUT = ROOT / "src" / "rules.rs"


def parse_scalar(body, key):
    m = re.search(r"(?m)^" + key + r"\s*=\s*(.+)$", body)
    return m.group(1).strip() if m else None


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


def parse_regex(body):
    m = re.search(r"(?ms)^regex\s*=\s*'''(.*?)'''", body)
    if m:
        return m.group(1)
    m = re.search(r"""(?m)^regex\s*=\s*(".*")\s*$""", body)
    if m:
        return unquote(m.group(1))
    m = re.search(r"(?m)^regex\s*=\s*'(.*)'\s*$", body)
    if m:
        return m.group(1)
    return None


def parse_string_array(body, key):
    """Scan a TOML array of strings.

    A regex can contain `]` inside a character class, so the end of the array
    cannot be found by looking for the first `]`; walk the literals instead.
    """
    m = re.search(r"(?m)^" + key + r"\s*=\s*\[", body)
    if not m:
        return []
    text = body[m.end() :]
    items = []
    i = 0
    while i < len(text):
        c = text[i]
        if text.startswith("'''", i):
            end = text.find("'''", i + 3)
            if end < 0:
                raise SystemExit("unterminated ''' in %s array" % key)
            items.append(text[i + 3 : end])
            i = end + 3
        elif c in "\"'":
            quote = c
            j = i + 1
            while j < len(text) and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            items.append(unquote(text[i : j + 1]))
            i = j + 1
        elif c == "]":
            break
        elif c in " \t\r\n,":
            i += 1
        else:
            raise SystemExit("unexpected %r in %s array at %d" % (c, key, i))
    return items


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


def rust_str(s):
    if '"#' not in s:
        return 'r#"' + s + '"#'
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# gitleaks' generic-api-key accepts `,`, `>` and `||` as separators, which
# fires on ordinary code (`import { hasXCredentials, y }`) and on metadata
# (`"api": "openai-completions"`). src/extra.rs carries a tightened version.
DROP = {"generic-api-key"}


def main():
    text = CONFIG.read_text()
    blocks = re.split(r"(?m)^\[\[rules\]\]\s*$", text)[1:]
    rules = []
    skipped = []
    for block in blocks:
        head, *allow_blocks = block.split("[[rules.allowlists]]")
        raw_id = parse_scalar(head, "id")
        if not raw_id:
            continue
        rid = unquote(raw_id)
        regex = parse_regex(head)
        if not regex or rid in DROP:
            skipped.append(rid)
            continue
        if not regex.strip():
            raise SystemExit("empty regex in rule %s" % rid)

        entropy = parse_scalar(head, "entropy")
        entropy = float(entropy) if entropy else None
        sg = parse_scalar(head, "secretGroup")
        keywords = [k.lower() for k in parse_string_array(head, "keywords")]

        allow = []
        for ab in allow_blocks:
            # Path-, commit- and stopword-scoped allowlists need more than the
            # text to decide, so they cannot be applied here.
            if any(re.search(r"(?m)^" + k + r"\s*=", ab) for k in ("paths", "commits", "condition", "stopwords")):
                continue
            target = unquote(parse_scalar(ab, "regexTarget") or '"match"')
            if target == "secret":
                target = "match"
            for rx in parse_string_array(ab, "regexes"):
                if not rx.strip():
                    raise SystemExit("empty allowlist regex in rule %s" % rid)
                allow.append((rx, target))

        rules.append(
            {
                "id": rid,
                "regex": regex,
                "entropy": entropy,
                "secret_group": int(sg) if sg else None,
                "keywords": keywords,
                "allow": allow,
            }
        )

    out = []
    out.append("// @generated by tools/gen-rules.py from rules/gitleaks.toml - do not edit.\n")
    out.append("// Rules: gitleaks default config (MIT, github.com/gitleaks/gitleaks).\n")
    out.append("// Path-only rules and path-scoped allowlists are dropped: this\n")
    out.append("// scanner sees text, not file paths.\n\n")
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
            "        entropy: %s,\n" % ("None" if r["entropy"] is None else "Some(%r)" % r["entropy"])
        )
        out.append(
            "        secret_group: %s,\n"
            % ("None" if r["secret_group"] is None else "Some(%d)" % r["secret_group"])
        )
        out.append("        keywords: &[%s],\n" % ", ".join(rust_str(k) for k in r["keywords"]))
        if r["allow"]:
            out.append("        allow: &[\n")
            for rx, target in r["allow"]:
                out.append(
                    "            Allow { regex: %s, line: %s },\n"
                    % (rust_str(rx), "true" if target == "line" else "false")
                )
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
    print("wrote %s: %d rules, %d skipped (path-only)" % (OUT, len(rules), len(skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
