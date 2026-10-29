use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use pixi_mask::{engine, extra, known, rules};

const USAGE: &str = "\
pixi-mask — mask secrets in text before it reaches a model context

Usage:
  pixi-mask mask [options]     stdin -> masked text on stdout
  pixi-mask scan [options]     stdin -> findings; exit 1 if any
  pixi-mask rules [--verify]   list rule ids; --verify compiles every rule

Options:
  --json                 machine-readable output (mask: {text, findings})
  -q, --quiet            no findings line on stderr
  --no-known             skip exact values from auth.json, .env, ...
  --known-file <path>    add a file of known values (repeatable)
  --known <value>        add one known value (repeatable)
  -h, --help             this text
  -V, --version          version

Env: PIXI_MASK_KNOWN — colon-separated known-value files
     PI_CODING_AGENT_DIR — where auth.json lives (default ~/.pi/agent)
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "-V" | "--version" => {
            println!("pixi-mask {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let mut json = false;
    let mut quiet = false;
    let mut no_known = false;
    let mut known_files: Vec<PathBuf> = Vec::new();
    let mut known_inline: Vec<String> = Vec::new();
    let mut verify = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => json = true,
            "-q" | "--quiet" => quiet = true,
            "--no-known" => no_known = true,
            "--verify" => verify = true,
            "--known-file" => {
                i += 1;
                match argv.get(i) {
                    Some(p) => known_files.push(PathBuf::from(p)),
                    None => return fail("--known-file needs a path"),
                }
            }
            "--known" => {
                i += 1;
                match argv.get(i) {
                    Some(v) => known_inline.push(v.clone()),
                    None => return fail("--known needs a value"),
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("pixi-mask {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unknown option: {other}")),
        }
        i += 1;
    }

    match cmd.as_str() {
        "rules" => run_rules(json, verify),
        "mask" | "scan" => {
            let mut known = if no_known {
                Vec::new()
            } else {
                let mut files = known::files_from_env();
                files.extend(known_files);
                let mut v = known::load(&files);
                v.extend(known_inline);
                v
            };
            known.retain(|v| v.len() >= 8);
            if std::io::stdin().is_terminal() {
                return fail("no input: pipe text on stdin");
            }
            let text = match read_stdin() {
                Ok(t) => t,
                Err(e) => return fail(&format!("reading stdin: {e}")),
            };
            let scanner = engine::Scanner::new(known);
            let spans = scanner.scan(&text);
            if cmd == "scan" {
                return run_scan(&text, &spans, json, quiet);
            }
            run_mask(&text, &spans, &scanner, json, quiet)
        }
        other => fail(&format!("unknown command: {other}")),
    }
}

fn read_stdin() -> std::io::Result<String> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn run_mask(
    text: &str,
    spans: &[engine::Span],
    _scanner: &engine::Scanner,
    json: bool,
    quiet: bool,
) -> ExitCode {
    let masked = engine::mask(text, spans);
    let mut out = std::io::stdout().lock();
    if json {
        let findings: Vec<serde_json::Value> = spans
            .iter()
            .map(|s| {
                serde_json::json!({
                    "rule": s.rule,
                    "line": engine::line_of(text, s.start),
                    "start": s.start,
                    "len": s.len(),
                })
            })
            .collect();
        let payload = serde_json::json!({ "text": masked, "findings": findings });
        let _ = writeln!(out, "{payload}");
        return ExitCode::SUCCESS;
    }
    let _ = out.write_all(masked.as_bytes());
    let _ = out.flush();
    drop(out);
    if !quiet && !spans.is_empty() {
        let rules: Vec<&str> = {
            let mut v: Vec<&str> = spans.iter().map(|s| s.rule).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        eprintln!(
            "pixi-mask: masked {} value(s) [{}]",
            spans.len(),
            rules.join(", ")
        );
    }
    ExitCode::SUCCESS
}

fn run_scan(text: &str, spans: &[engine::Span], json: bool, quiet: bool) -> ExitCode {
    if json {
        let findings: Vec<serde_json::Value> = spans
            .iter()
            .map(|s| {
                serde_json::json!({
                    "rule": s.rule,
                    "line": engine::line_of(text, s.start),
                    "start": s.start,
                    "len": s.len(),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "findings": findings }));
    } else if !quiet {
        for s in spans {
            eprintln!(
                "line {}: {} ({} chars)",
                engine::line_of(text, s.start),
                s.rule,
                s.len()
            );
        }
    }
    if spans.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_rules(json: bool, verify: bool) -> ExitCode {
    if verify {
        let scanner = engine::Scanner::new(Vec::new());
        let failures = scanner.verify();
        if json {
            let v: Vec<serde_json::Value> = failures
                .iter()
                .map(|(id, e)| serde_json::json!({ "id": id, "error": e }))
                .collect();
            println!(
                "{}",
                serde_json::json!({ "rules": rules::RULES.len() + extra::EXTRA.len(), "failed": v })
            );
        } else {
            for (id, e) in &failures {
                eprintln!("{id}: {e}");
            }
            println!(
                "{} rules, {} failed to compile",
                rules::RULES.len() + extra::EXTRA.len(),
                failures.len()
            );
        }
        return if failures.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    if json {
        let ids: Vec<&str> = rules::RULES
            .iter()
            .chain(extra::EXTRA.iter())
            .map(|r| r.id)
            .collect();
        println!("{}", serde_json::json!({ "rules": ids }));
    } else {
        for r in rules::RULES.iter().chain(extra::EXTRA.iter()) {
            println!("{}", r.id);
        }
    }
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("pixi-mask: {msg}");
    ExitCode::from(2)
}
