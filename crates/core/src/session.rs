//! Session and audit log (PLAN 6.7).
//!
//! The log is JSONL: one object per line. Each entry carries a `prev` field
//! holding the SHA-256 of the previous line's bytes (64 zeros for the first
//! line), so the entries form a hash chain.
//!
//! Each line additionally ends with a `hash` field covering that line's own
//! bytes. A `prev` chain alone can only detect a changed line when the *next*
//! line is read (and never detects a change to the last line), so the self
//! hash lets `verify` name the exact edited line.
//!
//! The chain is tamper-evident against edits and middle deletions, but not
//! against truncation: deleting trailing entries (or the whole file) leaves a
//! shorter chain that still verifies. Anchor the head hash elsewhere if
//! truncation must be detectable.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use barry_policy::Policy;
use barry_protocol::{DecidedBy, Decision, Message};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::redact::Redactor;

/// `prev` value for the first entry: 64 zeroes.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const HASH_FIELD: &str = ",\"hash\":\"";

/// Errors from the session log.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session log io error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("session log format error: {0}")]
    Format(String),
}

/// One audit entry, minus the envelope fields (`seq`, `ts`, `prev`, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntryKind {
    SessionStart {
        cwd: String,
        model: String,
        barry_version: String,
        policy_sha256: String,
    },
    Message {
        message: Message,
    },
    ToolDecision {
        call_id: String,
        tool: String,
        input: Value,
        /// The resolved decision: `allow` or `deny: <reason>`. Approvals are
        /// resolved before logging; `decided_by` records who resolved them.
        decision: String,
        /// `rule:<id>`, `user`, `hook:<id>` or `default`.
        decided_by: String,
    },
    ToolResult {
        call_id: String,
        ok: bool,
        bytes: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
    Grant {
        dir: String,
    },
    PrefixApproved {
        prefix: String,
    },
    Compaction {
        removed_seq_range: [u64; 2],
        summary: String,
    },
    Hook {
        event: String,
        command: String,
        exit_code: i32,
    },
    Notice {
        text: String,
    },
}

/// A fully parsed log line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub prev: String,
    pub agent_id: String,
    pub hash: String,
    #[serde(flatten)]
    pub kind: EntryKind,
}

/// The result of verifying a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    /// The 1-based line number where the chain breaks, if any.
    pub broken_at: Option<usize>,
}

/// An append-only, hash-chained session log.
pub struct SessionLog {
    path: PathBuf,
    file: File,
    agent_id: String,
    next_seq: u64,
    prev: String,
    redactor: Redactor,
}

impl SessionLog {
    /// Create a new log file inside `dir`. The directory is `0700` and the
    /// file `0600` (BC-5.4).
    pub fn create_in(dir: &Path, agent_id: &str) -> Result<Self, SessionError> {
        create_private_dir(dir)?;
        let name = format!("{}-{}.jsonl", timestamp_for_name(), uuid::Uuid::new_v4());
        let path = dir.join(name);
        let file = open_private_file(&path)?;
        Ok(Self {
            path,
            file,
            agent_id: agent_id.to_string(),
            next_seq: 0,
            prev: ZERO_HASH.to_string(),
            redactor: Redactor::from_env(),
        })
    }

    /// Create a log under `$XDG_STATE_HOME` (or `~/.local/state`).
    pub fn create_default(agent_id: &str) -> Result<Self, SessionError> {
        Self::create_in(&default_session_dir(), agent_id)
    }

    /// Open an existing log and continue its chain. Used by `--resume`.
    pub fn open_append(path: &Path) -> Result<Self, SessionError> {
        let content = fs::read_to_string(path).map_err(|source| SessionError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let mut next_seq = 0;
        let mut prev = ZERO_HASH.to_string();
        let mut agent_id = "main".to_string();
        if let Some(last) = content.split('\n').rfind(|line| !line.is_empty()) {
            let entry: Entry = serde_json::from_str(last)
                .map_err(|err| SessionError::Format(format!("last line: {err}")))?;
            next_seq = entry.seq + 1;
            prev = sha256_hex(last.as_bytes());
            agent_id = entry.agent_id;
        }

        let file = open_private_file(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            agent_id,
            next_seq,
            prev,
            redactor: Redactor::from_env(),
        })
    }

    /// The file this log writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry, redact it, hash-chain it, and fsync.
    pub fn append(&mut self, kind: EntryKind) -> Result<(), SessionError> {
        let mut value =
            serde_json::to_value(&kind).map_err(|err| SessionError::Format(err.to_string()))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| SessionError::Format("entry is not a JSON object".into()))?;
        object.insert("seq".to_string(), json!(self.next_seq));
        object.insert("ts".to_string(), json!(rfc3339_now()));
        object.insert("prev".to_string(), json!(self.prev));
        object.insert("agent_id".to_string(), json!(self.agent_id));

        // Redact before hashing and writing (PLAN 6.7).
        self.redactor.redact_value(&mut value);

        let body =
            serde_json::to_string(&value).map_err(|err| SessionError::Format(err.to_string()))?;
        // The self hash covers the line up to the `,"hash"` suffix, so
        // `verify` can recompute it from the bytes that precede the suffix.
        let prefix = &body[..body.len() - 1];
        let hash = sha256_hex(prefix.as_bytes());
        // Append the self hash as the last field. The line is
        // `<body without closing brace>,"hash":"<hex>"}`.
        let line = format!("{prefix}{HASH_FIELD}{hash}\"}}");

        writeln!(self.file, "{line}").map_err(|source| SessionError::Io {
            path: self.path.display().to_string(),
            source,
        })?;
        self.file.flush().map_err(|source| SessionError::Io {
            path: self.path.display().to_string(),
            source,
        })?;
        self.file.sync_data().map_err(|source| SessionError::Io {
            path: self.path.display().to_string(),
            source,
        })?;

        self.prev = sha256_hex(line.as_bytes());
        self.next_seq += 1;
        Ok(())
    }
}

/// Verify the hash chain of a log file.
pub fn verify(path: &Path) -> Result<VerifyReport, SessionError> {
    let content = fs::read_to_string(path).map_err(|source| SessionError::Io {
        path: path.display().to_string(),
        source,
    })?;

    let mut lines: Vec<&str> = content.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }

    let mut prev = ZERO_HASH.to_string();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let broken = || VerifyReport {
            entries: lines.len(),
            broken_at: Some(number),
        };

        let Ok(entry) = serde_json::from_str::<Entry>(line) else {
            return Ok(broken());
        };

        let Some((body, hash)) = split_self_hash(line) else {
            return Ok(broken());
        };
        if sha256_hex(body.as_bytes()) != hash {
            return Ok(broken());
        }
        if entry.prev != prev || entry.seq != index as u64 {
            return Ok(broken());
        }

        prev = sha256_hex(line.as_bytes());
    }

    Ok(VerifyReport {
        entries: lines.len(),
        broken_at: None,
    })
}

/// Rebuild conversation history from `message` entries, applying `compaction`
/// entries (PLAN 6.7, BC-5.5).
pub(crate) fn replay_history(path: &Path) -> Result<Vec<Message>, SessionError> {
    let content = fs::read_to_string(path).map_err(|source| SessionError::Io {
        path: path.display().to_string(),
        source,
    })?;

    let mut messages: Vec<(u64, Message)> = Vec::new();
    let mut removed: Vec<(u64, u64)> = Vec::new();

    for (index, line) in content
        .split('\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let entry: Entry = serde_json::from_str(line)
            .map_err(|err| SessionError::Format(format!("line {}: {err}", index + 1)))?;
        match entry.kind {
            EntryKind::Message { message } => {
                if !matches!(message, Message::System { .. }) {
                    messages.push((entry.seq, message));
                }
            }
            EntryKind::Compaction {
                removed_seq_range, ..
            } => removed.push((removed_seq_range[0], removed_seq_range[1])),
            _ => {}
        }
    }

    messages.retain(|(seq, _)| {
        !removed
            .iter()
            .any(|(start, end)| seq >= start && seq <= end)
    });
    Ok(messages.into_iter().map(|(_, message)| message).collect())
}

/// The directory where sessions live: `$XDG_STATE_HOME/barry/sessions` or
/// `~/.local/state/barry/sessions`.
pub fn default_session_dir() -> PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    state.join("barry").join("sessions")
}

/// Resolve a `--resume` argument: an existing file path, or a filename
/// fragment (timestamp or UUID prefix) inside the default session directory.
///
/// An ambiguous prefix is an error rather than an arbitrary pick.
pub fn resolve_session(spec: &str) -> Result<PathBuf, SessionError> {
    let direct = PathBuf::from(spec);
    if direct.is_file() {
        return Ok(direct);
    }

    let mut matches = Vec::new();
    if let Ok(entries) = fs::read_dir(default_session_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".jsonl") && name.contains(spec) {
                matches.push(entry.path());
            }
        }
    }
    matches.sort();

    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(SessionError::Format(format!(
            "no session log matches {spec:?}"
        ))),
        count => Err(SessionError::Format(format!(
            "{spec:?} matches {count} session logs; use a longer prefix or a path"
        ))),
    }
}

/// A stable fingerprint of the effective policy, for `session_start`.
pub(crate) fn policy_fingerprint(policy: Option<&Policy>) -> String {
    /// Hash one field with its length, so concatenated values cannot collide.
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    field(&mut hasher, b"barry-policy-v1");
    match policy {
        None => field(&mut hasher, b"no-policy"),
        Some(policy) => {
            field(&mut hasher, policy.cwd().display().to_string().as_bytes());
            for path in policy.writable_roots() {
                field(&mut hasher, path.display().to_string().as_bytes());
            }
            for path in policy.grants() {
                field(&mut hasher, path.display().to_string().as_bytes());
            }
            for path in policy.read_deny_paths() {
                field(&mut hasher, path.display().to_string().as_bytes());
            }
            for component in policy.protected() {
                field(&mut hasher, component.as_bytes());
            }
            for rule in policy.rules() {
                field(&mut hasher, rule.id.as_bytes());
                field(&mut hasher, rule.r#match.as_bytes());
                field(&mut hasher, format!("{:?}", rule.decision).as_bytes());
            }
            field(&mut hasher, &[u8::from(policy.network())]);
        }
    }
    hex_digest(hasher.finalize())
}

/// Render a decision for the audit log.
pub(crate) fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::Ask { reason } => format!("ask: {reason}"),
        Decision::Deny { reason } => format!("deny: {reason}"),
    }
}

/// Render who decided, for the audit log.
pub(crate) fn decided_by_label(decided_by: &DecidedBy) -> String {
    match decided_by {
        DecidedBy::Rule(id) => format!("rule:{id}"),
        DecidedBy::User => "user".to_string(),
        DecidedBy::Hook(id) => format!("hook:{id}"),
        DecidedBy::Default => "default".to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Split a line into `(hashed body, self hash)`.
fn split_self_hash(line: &str) -> Option<(&str, &str)> {
    let index = line.rfind(HASH_FIELD)?;
    let hash = line[index + HASH_FIELD.len()..].strip_suffix("\"}")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((&line[..index], hash))
}

fn create_private_dir(dir: &Path) -> Result<(), SessionError> {
    fs::create_dir_all(dir).map_err(|source| SessionError::Io {
        path: dir.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
            SessionError::Io {
                path: dir.display().to_string(),
                source,
            }
        })?;
    }
    Ok(())
}

fn open_private_file(path: &Path) -> Result<File, SessionError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|source| SessionError::Io {
        path: path.display().to_string(),
        source,
    })?;

    // Hold an exclusive advisory lock for the life of the log so two barry
    // processes cannot interleave appends and break the chain. Filesystems
    // without advisory locking keep working.
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(SessionError::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "session log is already open by another barry process",
                ),
            });
        }
        Err(_) => {}
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten an existing file too; `mode` only applies on creation.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            SessionError::Io {
                path: path.display().to_string(),
                source,
            }
        })?;
    }
    Ok(file)
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn timestamp_for_name() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}
