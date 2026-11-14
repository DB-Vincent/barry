//! Secret redaction for the session log (PLAN 6.7).
//!
//! Redaction applies **only** to the audit log. The model still receives the
//! real tool output.

use regex::Regex;
use serde_json::Value;

/// Replaces recognised secrets with `[REDACTED]`.
pub struct Redactor {
    patterns: Vec<Regex>,
    /// Literal secret values, longest first, collected from the environment.
    literals: Vec<String>,
}

impl Redactor {
    /// Build a redactor from the built-in patterns and the values of
    /// environment variables whose names look sensitive (PLAN 6.7).
    pub fn from_env() -> Self {
        let mut literals = Vec::new();
        for (name, value) in std::env::vars_os() {
            let (Some(name), Some(value)) = (name.to_str(), value.to_str()) else {
                continue;
            };
            let name = name.to_ascii_uppercase();
            let sensitive = name.contains("KEY")
                || name.contains("TOKEN")
                || name.contains("SECRET")
                || name.contains("PASSWORD");
            if sensitive && value.len() >= 8 {
                literals.push(value.to_string());
            }
        }
        Self::new(literals)
    }

    /// Build a redactor with explicit literal values (tests, custom setups).
    pub fn new(mut literals: Vec<String>) -> Self {
        let patterns = [
            r"sk-[A-Za-z0-9_-]{20,}",
            r"gh[pousr]_[A-Za-z0-9]{36,}",
            r"AKIA[0-9A-Z]{16}",
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("valid redaction regex"))
        .collect();

        // Longest first so a shorter literal cannot split a longer match.
        literals.sort_by_key(|value| std::cmp::Reverse(value.len()));
        literals.dedup();

        Self { patterns, literals }
    }

    /// Redact every recognised secret in `text`.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for pattern in &self.patterns {
            out = pattern.replace_all(&out, "[REDACTED]").into_owned();
        }
        for literal in &self.literals {
            if out.contains(literal.as_str()) {
                out = out.replace(literal.as_str(), "[REDACTED]");
            }
        }
        out
    }

    /// Redact every string inside a JSON value, in place.
    pub fn redact_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.redact(text),
            Value::Array(items) => {
                for item in items {
                    self.redact_value(item);
                }
            }
            Value::Object(map) => {
                for item in map.values_mut() {
                    self.redact_value(item);
                }
            }
            _ => {}
        }
    }
}
