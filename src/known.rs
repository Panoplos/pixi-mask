// Exact known secret values (auth.json, ~/.aws/credentials, .env, ...).
//
// Values are matched as literal substrings, so they are masked even when they
// carry no recognisable prefix. Rotation still needs a restart, as before.

use std::path::PathBuf;

use regex::Regex;

pub fn default_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let agent = std::env::var("PI_CODING_AGENT_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("{home}/.pi/agent"));
    vec![
        PathBuf::from(format!("{agent}/auth.json")),
        PathBuf::from(format!("{home}/.aws/credentials")),
        PathBuf::from(format!("{home}/.config/gh/hosts.yml")),
        PathBuf::from(format!("{home}/.npmrc")),
        PathBuf::from(format!("{home}/.config/pypi/credentials.toml")),
        PathBuf::from(".env"),
    ]
}

pub fn files_from_env() -> Vec<PathBuf> {
    std::env::var("PIXI_MASK_KNOWN")
        .ok()
        .map(|v| {
            v.split(':')
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    [
        "example",
        "xxxx",
        "your",
        "changeme",
        "change_me",
        "placeholder",
        "redacted",
        "dummy",
        "sample",
        "1234",
    ]
    .iter()
    .any(|p| l.contains(p))
}

pub fn extract(text: &str) -> Vec<String> {
    let rx = Regex::new(
        r#"(?i)(?:key|token|secret|password|passwd|pat|credential|access_key|secret_key)s?["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,})"#,
    )
    .expect("known regex");
    let mut out = Vec::new();
    for caps in rx.captures_iter(text) {
        let v = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let v = v.trim_end_matches('.');
        if v.len() < 16 || placeholder(v) {
            continue;
        }
        if crate::engine::entropy(v.as_bytes()) < 2.5 {
            continue;
        }
        out.push(v.to_string());
    }
    out
}

pub fn load(extra: &[PathBuf]) -> Vec<String> {
    let mut values = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut paths = default_paths();
    paths.extend(extra.iter().cloned());
    for p in paths {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        for v in extract(&text) {
            if seen.insert(v.clone()) {
                values.push(v);
            }
        }
    }
    values
}
