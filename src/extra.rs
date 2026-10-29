// Hand-written rules: shapes gitleaks does not cover, covers worse, or covers
// too loosely for a context guard.
//
// A bare high-entropy token with no prefix and no keyword is not caught here on
// purpose: unlabelled 64-hex is indistinguishable from a sha256 checksum, and
// masking every hash in a repo is worse than the risk.

use crate::rules::Rule;

const ASSIGN_KEYWORDS: &[&str] = &[
    "access",
    "auth",
    "api",
    "credential",
    "creds",
    "key",
    "passwd",
    "password",
    "secret",
    "token",
];

pub static EXTRA: &[Rule] = &[
    // Tightened replacement for gitleaks' `generic-api-key`, which accepts `,`,
    // `>` and `||` as separators and masks ordinary code:
    //   import { hasAzureOpenAICredentials, x }   <- keyword "," value
    // `=` and `:` only, and the value has to look like a credential: 16+ chars
    // with a digit somewhere, or (next rule) 24+ letters-only chars with no
    // separators, which rules out dotted code paths like
    // `SETTINGS_DEFAULTS.compaction.reserveTokens`.
    Rule {
        id: "assignment-secret",
        regex: r#"(?i)[\w.-]{0,50}?(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)[ \t\w.-]{0,10}["'\s]{0,3}(?:=|:|:=)[\x60"'\s=]{0,5}([A-Za-z0-9_\-./+=]{15,}[0-9][A-Za-z0-9_\-./+=]*)"#,
        entropy: Some(3.2),
        secret_group: Some(1),
        keywords: ASSIGN_KEYWORDS,
        allow: &[],
    },
    Rule {
        id: "assignment-secret-letters",
        regex: r#"(?i)[\w.-]{0,50}?(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)[ \t\w.-]{0,10}["'\s]{0,3}(?:=|:|:=)[\x60"'\s=]{0,5}([A-Za-z\-+/=]{24,150})"#,
        entropy: Some(4.2),
        secret_group: Some(1),
        keywords: ASSIGN_KEYWORDS,
        allow: &[],
    },
    Rule {
        id: "bearer-token",
        regex: r"(?i)\bBearer[ \t]+[A-Za-z0-9_\-.=+/]{20,}",
        entropy: Some(3.5),
        secret_group: None,
        keywords: &["bearer"],
        allow: &[],
    },
    Rule {
        id: "huggingface-token",
        regex: r"\bhf_[A-Za-z0-9]{30,}\b",
        entropy: None,
        secret_group: None,
        keywords: &["hf_"],
        allow: &[],
    },
    Rule {
        id: "groq-api-key",
        regex: r"\bgsk_[A-Za-z0-9]{40,}\b",
        entropy: None,
        secret_group: None,
        keywords: &["gsk_"],
        allow: &[],
    },
    Rule {
        id: "xai-api-key",
        regex: r"\bxai-[A-Za-z0-9]{40,}\b",
        entropy: None,
        secret_group: None,
        keywords: &["xai-"],
        allow: &[],
    },
    Rule {
        id: "supabase-key",
        regex: r"\bsb[pr]_[A-Za-z0-9_-]{30,}\b",
        entropy: None,
        secret_group: None,
        keywords: &["sbp_", "sbr_"],
        allow: &[],
    },
    Rule {
        id: "docker-pat",
        regex: r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b",
        entropy: None,
        secret_group: None,
        keywords: &["dckr_pat_"],
        allow: &[],
    },
    Rule {
        id: "bitdeer-api-key",
        regex: r#"(?i)\bbitdeer[_a-z]{0,16}(?:key|token|secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})"#,
        entropy: Some(3.0),
        secret_group: Some(1),
        keywords: &["bitdeer"],
        allow: &[],
    },
    Rule {
        id: "connection-string-password",
        regex: r"(?i)\b(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s:@/]{1,64}:[^\s@/]{6,64}@",
        entropy: Some(2.5),
        secret_group: None,
        keywords: &[
            "postgresql://",
            "postgres://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "rediss://",
            "amqp://",
            "amqps://",
            "mariadb://",
        ],
        allow: &[],
    },
];
