// Behaviour tests: values we must mask, values we must leave alone.

use pixi_mask::engine::{self, Scanner};

/// Deterministic filler so no test fixture looks like a real credential.
fn tok(seed: u64, len: usize, alphabet: &[u8]) -> String {
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut s = String::new();
    for _ in 0..len {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(alphabet[((x >> 33) as usize) % alphabet.len()] as char);
    }
    s
}

fn alnum() -> &'static [u8] {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
}

fn scanner() -> Scanner {
    Scanner::new(Vec::new())
}

fn masked(text: &str) -> String {
    let sc = scanner();
    let spans = sc.scan(text);
    engine::mask(text, &spans)
}

#[test]
fn every_rule_compiles() {
    let failed = scanner().verify();
    assert!(failed.is_empty(), "rules that do not compile: {failed:?}");
}

#[test]
fn provider_shapes_are_masked() {
    let cases: Vec<(&str, String)> = vec![
        ("openai", format!("sk-proj-{}", tok(1, 40, alnum()))),
        (
            "anthropic",
            format!("sk-ant-api03-{}AA", tok(2, 93, alnum())),
        ),
        ("github-pat", format!("ghp_{}", tok(3, 36, alnum()))),
        (
            "github-fine-grained",
            format!("github_pat_{}", tok(4, 82, alnum())),
        ),
        (
            "aws-access-key",
            format!("AKIA{}", tok(5, 16, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")),
        ),
        ("google-api-key", format!("AIza{}", tok(6, 35, alnum()))),
        (
            "slack-bot",
            format!("xoxb-{}-{}", tok(7, 12, b"0123456789"), tok(8, 24, alnum())),
        ),
        ("stripe", format!("sk_live_{}", tok(9, 24, alnum()))),
        (
            "sendgrid",
            format!("SG.{}.{}", tok(10, 22, alnum()), tok(11, 43, alnum())),
        ),
        ("npm", format!("npm_{}", tok(12, 36, alnum()))),
        ("gitlab", format!("glpat-{}", tok(13, 20, alnum()))),
        // Providers gitleaks has no rule for.
        ("huggingface", format!("hf_{}", tok(14, 34, alnum()))),
        ("groq", format!("gsk_{}", tok(15, 52, alnum()))),
        ("xai", format!("xai-{}", tok(16, 80, alnum()))),
        ("supabase", format!("sbp_{}", tok(17, 40, alnum()))),
        ("docker", format!("dckr_pat_{}", tok(18, 27, alnum()))),
        (
            "postgres-dsn",
            format!(
                "postgres://app:{}@db.internal:5432/app",
                tok(19, 24, alnum())
            ),
        ),
        (
            "bearer-header",
            format!("Authorization: Bearer {}", tok(20, 40, alnum())),
        ),
        (
            "env-dump-uppercase-name",
            format!("OPENAI_API_KEY={}", tok(21, 48, b"0123456789abcdef")),
        ),
        (
            "env-dump-suffix-name",
            format!("BITDEER_API_KEY={}", tok(22, 48, b"0123456789abcdef")),
        ),
        (
            "yaml-nested-name",
            format!("aws_secret_access_key = \"{}\"", tok(23, 40, alnum())),
        ),
        (
            "client-secret",
            format!("client_secret=\"{}\"", tok(24, 40, alnum())),
        ),
    ];

    for (label, secret) in cases {
        let text = format!("config: {secret}\nnext line\n");
        let out = masked(&text);
        assert_ne!(out, text, "{label} was not masked");
        assert!(
            out.contains("…[REDACTED]"),
            "{label}: no mask marker in {out:?}"
        );
        assert!(
            !out.contains(&secret),
            "{label}: value still readable after masking"
        );
    }
}

#[test]
fn pem_block_is_masked() {
    let body = tok(31, 200, alnum());
    let text =
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n");
    let out = masked(&text);
    assert!(!out.contains(&body));
}

#[test]
fn base64_wrapped_key_is_masked() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let inner = format!("OPENAI_API_KEY={}", tok(32, 48, b"0123456789ABCDEF"));
    let wrapped = STANDARD.encode(inner.as_bytes());
    let text = format!("payload: {wrapped}\n");
    let out = masked(&text);
    assert_ne!(out, text, "base64-wrapped key was not masked");
    assert!(!out.contains(&wrapped));
}

#[test]
fn assignment_name_survives_masking() {
    let value = tok(33, 48, b"0123456789abcdef");
    let text = format!("OPENAI_API_KEY={value}");
    let out = masked(&text);
    assert_eq!(out, format!("OPENAI_API_KEY={}…[REDACTED]", &value[..4]));
}

/// Things that look random but are not credentials. Masking these would eat
/// real content out of the model's context.
#[test]
fn benign_content_is_untouched() {
    let sha = tok(41, 40, b"0123456789abcdef");
    let sha256 = tok(42, 64, b"0123456789abcdef");
    let integrity = format!("sha512-{}", tok(43, 88, alnum()));
    let cases: Vec<(&str, String)> = vec![
        ("git-sha1", format!("commit {sha}\nAuthor: someone\n")),
        (
            "npm-integrity",
            format!("{{\"integrity\": \"{integrity}\", \"version\": \"1.2.3\"}}"),
        ),
        ("sha256-digest", format!("checksum: {sha256}\n")),
        (
            "prose",
            "The token bucket refills at 100 tokens per second; each API call costs one key. "
                .to_string(),
        ),
        (
            "placeholder",
            "api_key = \"your-api-key-here\"\nsecret: changeme-please-value\n".to_string(),
        ),
        (
            "code",
            "fn handle(req: &Request) -> Result<Response> {\n    let api_key = req.header(\"x-api-key\");\n    auth_check(&ctx, &api_key)?;\n    Ok(Response::new())\n}\n".to_string(),
        ),
        (
            "long-base64-asset",
            format!("data:image/png;base64,{}\n", tok(44, 400, alnum())),
        ),
        (
            "shard-ids",
            "shard-a1b2c3d4e5f6 worker-7f3c9a2b\n".to_string(),
        ),
    ];
    for (label, text) in cases {
        let out = masked(&text);
        assert_eq!(out, text, "{label} should not be masked");
    }
}

#[test]
fn masks_keep_char_boundaries() {
    let secret = format!("sk-proj-{}", tok(51, 40, alnum()));
    let text = format!("ünïcødé 秘密 🎉 {secret} tail\n");
    let out = masked(&text);
    assert!(!out.contains(&secret));
    assert!(out.starts_with("ünïcødé 秘密 🎉 "));
    assert!(out.ends_with(" tail\n"));
}

#[test]
fn known_values_are_masked_anywhere() {
    let value = "Zx8Kq2Lm4Np6Rt9Vw1Yb3C".to_string();
    let sc = Scanner::new(vec![value.clone()]);
    let text = format!("log line: using {value} for auth\n");
    let spans = sc.scan(&text);
    let out = engine::mask(&text, &spans);
    assert!(!out.contains(&value));
    assert!(out.contains("Zx8K…[REDACTED]"));
}

#[test]
fn findings_carry_line_numbers() {
    let secret = format!("ghp_{}", tok(61, 36, alnum()));
    let text = format!("line one\nline two\nkey {secret}\n");
    let spans = scanner().scan(&text);
    assert_eq!(spans.len(), 1);
    assert_eq!(engine::line_of(&text, spans[0].start), 3);
}

#[test]
fn entropy_basics() {
    assert!((engine::entropy(b"aaaaaaaa") - 0.0).abs() < 1e-9);
    assert!((engine::entropy(b"ab") - 1.0).abs() < 1e-9);
    let hex = tok(71, 64, b"0123456789abcdef");
    assert!(engine::entropy(hex.as_bytes()) <= 4.0);
}
