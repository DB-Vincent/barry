//! Read-only `glob`, `grep` and `ls` tools.
//!
//! These replace searching through `bash`, which sits behind the weakest
//! policy layer. Every path the tools touch goes through `Policy::check_read`,
//! so read-deny entries apply exactly as they do for `read`. Entries the policy
//! denies are skipped silently: their names are not revealed. Symlinks are
//! never followed, so a link cannot lead the walk out of the searched tree.
//! All output is bounded.

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use barry_policy::Policy;
use barry_protocol::Decision;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::json;

use super::read::read_gate;
use super::{Tool, ToolCtx, ToolResult};
use crate::CoreError;

pub(super) struct GlobTool;
pub(super) struct GrepTool;
pub(super) struct LsTool;

impl Tool for GlobTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "glob".to_string(),
            description:
                "List files whose path matches a glob pattern (read-only, at most 1000 results)"
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob such as \"*.rs\" (any depth) or \"src/**/*.rs\""
                    },
                    "path": { "type": "string", "description": "Directory to search (default: current directory)" }
                },
                "required": ["pattern"]
            }),
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run_search(ctx, "glob"))
    }
}

impl Tool for GrepTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "grep".to_string(),
            description: "Search file contents with a regex and return path:line: text (read-only, at most 200 matches)".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regular expression" },
                    "path": { "type": "string", "description": "File or directory to search (default: current directory)" },
                    "glob": { "type": "string", "description": "Only search files whose path matches this glob" },
                    "case_insensitive": { "type": "boolean", "description": "Ignore case (default false)" }
                },
                "required": ["pattern"]
            }),
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run_search(ctx, "grep"))
    }
}

impl Tool for LsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "ls".to_string(),
            description: "List the entries of a directory; directories end in / (read-only)"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory to list (default: current directory)" }
                },
                "required": []
            }),
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run_search(ctx, "ls"))
    }
}

/// Run `glob`, `grep` or `ls`. The search root goes through the read gate
/// (one logged decision per call); the walk then applies the read policy to
/// every entry it visits.
async fn run_search(mut ctx: ToolCtx<'_>, tool: &'static str) -> Result<ToolResult, CoreError> {
    let root = ctx.str_arg("path");
    let root = if root.is_empty() {
        ".".to_string()
    } else {
        root
    };
    if let Some(denied) = read_gate(&mut ctx, tool, &root)? {
        return Ok(denied);
    }
    // The walk is blocking filesystem work: keep it off the async workers.
    let arguments = ctx.arguments.clone();
    let policy = ctx.policy.clone();
    tokio::task::spawn_blocking(move || match tool {
        "glob" => run_glob(&arguments, &policy),
        "grep" => run_grep(&arguments, &policy),
        _ => run_ls(&arguments, &policy),
    })
    .await
    .map_err(|e| CoreError::Provider(format!("search task failed: {e}")))
}

/// Longest glob/ls listing, in entries.
const MAX_ENTRIES: usize = 1_000;
/// Longest grep result, in matching lines.
const MAX_MATCHES: usize = 200;
/// Files visited before a walk gives up.
const MAX_FILES_VISITED: usize = 50_000;
/// Files larger than this are skipped by grep.
const MAX_GREP_FILE_BYTES: u64 = 1_048_576;
/// Longest matched line kept in grep output, in characters.
const MAX_LINE_CHARS: usize = 300;
/// Directories never searched: version-control internals only add noise.
const SKIPPED_DIRS: &[&str] = &[".git"];

fn fail(message: String) -> ToolResult {
    ToolResult::new(false, message.clone(), message)
}

fn ok(content: String) -> ToolResult {
    ToolResult::new(true, content.clone(), content)
}

fn readable(policy: &Policy, path: &Path) -> bool {
    matches!(policy.check_read(path), Decision::Allow)
}

/// How a path is shown to the model: relative to the search root, joined
/// onto the root as the model gave it.
fn display_path(root: &Path, rel: &Path) -> String {
    let joined = if root == Path::new(".") {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    joined.display().to_string()
}

/// Translates a glob into an anchored regex over `/`-separated relative paths.
/// Supports `*`, `**`, `?` and `[...]` classes (with `!` or `^` negation). A
/// pattern without `/` matches at any depth, as in `*.rs`.
pub(super) fn glob_to_regex(glob: &str) -> Result<Regex, String> {
    let glob = if glob.contains('/') {
        glob.trim_start_matches("./").to_string()
    } else {
        format!("**/{glob}")
    };
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::from("^");
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                if chars.get(i + 2) == Some(&'/') {
                    out.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    out.push_str(".*");
                    i += 2;
                }
            }
            '*' => {
                out.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            '[' => match chars[i + 1..].iter().position(|c| *c == ']') {
                // A `]` right after `[` or `[!` would be a literal member;
                // treat that as unclosed to keep the translation simple.
                Some(end) if end > 0 => {
                    let body: String = chars[i + 1..i + 1 + end].iter().collect();
                    let body = match body.strip_prefix(['!', '^']) {
                        Some(rest) => format!("^{}", escape_class(rest)),
                        None => escape_class(&body),
                    };
                    out.push('[');
                    out.push_str(&body);
                    out.push(']');
                    i += end + 2;
                }
                _ => {
                    out.push_str("\\[");
                    i += 1;
                }
            },
            c => {
                out.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    Regex::new(&out).map_err(|e| format!("invalid glob '{glob}': {e}"))
}

/// Escapes the characters that are special inside a regex class, keeping `-`
/// so ranges like `a-z` work.
fn escape_class(body: &str) -> String {
    body.chars()
        .flat_map(|c| match c {
            '\\' | '[' | ']' | '^' | '&' | '~' => vec!['\\', c],
            _ => vec![c],
        })
        .collect()
}

/// One file found by [`walk_files`].
struct Found {
    /// Path relative to the walk root.
    rel: PathBuf,
    /// Path to open (root joined with `rel`).
    full: PathBuf,
}

/// Outcome of a walk.
struct Walk {
    files: Vec<Found>,
    /// The visit cap was hit before the tree was exhausted.
    capped: bool,
}

/// Walks `root` depth-first in name order, collecting readable regular files.
/// Read-denied directories are not entered. Symlinks are skipped.
fn walk_files(root: &Path, policy: &Policy) -> Walk {
    let mut walk = Walk {
        files: Vec::new(),
        capped: false,
    };
    let mut stack: Vec<PathBuf> = vec![PathBuf::new()];
    while let Some(rel_dir) = stack.pop() {
        let Ok(read_dir) = fs::read_dir(root.join(&rel_dir)) else {
            continue;
        };
        let mut entries: Vec<_> = read_dir.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        // Push directories in reverse so they pop in name order.
        let mut dirs = Vec::new();
        for entry in entries {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let rel = rel_dir.join(entry.file_name());
            let full = root.join(&rel);
            if file_type.is_symlink() || !readable(policy, &full) {
                continue;
            }
            if file_type.is_dir() {
                if !SKIPPED_DIRS.iter().any(|d| entry.file_name() == *d) {
                    dirs.push(rel);
                }
            } else if file_type.is_file() {
                if walk.files.len() >= MAX_FILES_VISITED {
                    walk.capped = true;
                    return walk;
                }
                walk.files.push(Found { rel, full });
            }
        }
        stack.extend(dirs.into_iter().rev());
    }
    walk
}

/// Checks the search root: it must exist, be readable under the policy.
fn check_root(tool: &str, root: &Path, policy: &Policy) -> Result<(), ToolResult> {
    if !readable(policy, root) {
        return Err(fail(format!("{tool} denied: path is read-denied")));
    }
    if !root.exists() {
        return Err(fail(format!(
            "{tool} failed: no such path: {}",
            root.display()
        )));
    }
    Ok(())
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn root_arg(args: &Value) -> PathBuf {
    PathBuf::from(
        str_arg(args, "path")
            .filter(|p| !p.is_empty())
            .unwrap_or("."),
    )
}

/// `glob`: files whose path under `path` matches `pattern`.
fn run_glob(args: &Value, policy: &Policy) -> ToolResult {
    let Some(pattern) = str_arg(args, "pattern").filter(|p| !p.is_empty()) else {
        return fail("glob failed: missing pattern".to_string());
    };
    let root = root_arg(args);
    if let Err(result) = check_root("glob", &root, policy) {
        return result;
    }
    let re = match glob_to_regex(pattern) {
        Ok(re) => re,
        Err(message) => return fail(format!("glob failed: {message}")),
    };
    let walk = walk_files(&root, policy);
    let mut matches: Vec<String> = walk
        .files
        .iter()
        .filter(|f| re.is_match(&f.rel.to_string_lossy().replace('\\', "/")))
        .map(|f| display_path(&root, &f.rel))
        .collect();
    matches.sort();
    let total = matches.len();
    matches.truncate(MAX_ENTRIES);
    let mut out = matches.join("\n");
    if total == 0 {
        out = "no files matched".to_string();
    }
    if total > MAX_ENTRIES {
        let _ = write!(
            out,
            "\n[truncated: showing {MAX_ENTRIES} of {total} matches]"
        );
    }
    if walk.capped {
        let _ = write!(out, "\n[search stopped after {MAX_FILES_VISITED} files]");
    }
    ok(out)
}

/// `grep`: lines under `path` matching the regex `pattern`.
fn run_grep(args: &Value, policy: &Policy) -> ToolResult {
    let Some(pattern) = str_arg(args, "pattern").filter(|p| !p.is_empty()) else {
        return fail("grep failed: missing pattern".to_string());
    };
    let root = root_arg(args);
    if let Err(result) = check_root("grep", &root, policy) {
        return result;
    }
    let case_insensitive = args
        .get("case_insensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let re = match RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
    {
        Ok(re) => re,
        Err(e) => return fail(format!("grep failed: invalid regex: {e}")),
    };
    let file_filter = match str_arg(args, "glob").filter(|g| !g.is_empty()) {
        Some(g) => match glob_to_regex(g) {
            Ok(re) => Some(re),
            Err(message) => return fail(format!("grep failed: {message}")),
        },
        None => None,
    };

    // A file root is searched alone; a directory root is walked.
    let (files, capped) = if root.is_file() {
        (
            vec![Found {
                rel: PathBuf::new(),
                full: root.clone(),
            }],
            false,
        )
    } else {
        let walk = walk_files(&root, policy);
        (walk.files, walk.capped)
    };

    let mut lines: Vec<String> = Vec::new();
    let mut total = 0usize;
    for file in files {
        if let Some(filter) = &file_filter
            && !filter.is_match(&file.rel.to_string_lossy().replace('\\', "/"))
        {
            continue;
        }
        let Some(text) = read_text(&file.full) else {
            continue;
        };
        let shown = if file.rel.as_os_str().is_empty() {
            root.display().to_string()
        } else {
            display_path(&root, &file.rel)
        };
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                total += 1;
                if lines.len() < MAX_MATCHES {
                    lines.push(format!("{shown}:{}: {}", i + 1, clip(line)));
                }
            }
        }
    }
    let mut out = if total == 0 {
        "no matches".to_string()
    } else {
        lines.join("\n")
    };
    if total > MAX_MATCHES {
        let _ = write!(
            out,
            "\n[truncated: showing {MAX_MATCHES} of {total} matches]"
        );
    }
    if capped {
        let _ = write!(out, "\n[search stopped after {MAX_FILES_VISITED} files]");
    }
    ok(out)
}

/// Reads a text file for grep. Large and binary (NUL-containing) files are skipped.
fn read_text(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_GREP_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_GREP_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn clip(line: &str) -> String {
    let line = line.trim_end();
    match line.char_indices().nth(MAX_LINE_CHARS) {
        Some((idx, _)) => format!("{}...", &line[..idx]),
        None => line.to_string(),
    }
}

/// `ls`: the direct entries of a directory. Directories end in `/`.
fn run_ls(args: &Value, policy: &Policy) -> ToolResult {
    let root = root_arg(args);
    if let Err(result) = check_root("ls", &root, policy) {
        return result;
    }
    let read_dir = match fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) => return fail(format!("ls failed: {}: {e}", root.display())),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in read_dir.filter_map(Result::ok) {
        if !readable(policy, &root.join(entry.file_name())) {
            continue;
        }
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            name.push('/');
        }
        names.push(name);
    }
    names.sort();
    let total = names.len();
    names.truncate(MAX_ENTRIES);
    let mut out = names.join("\n");
    if total == 0 {
        out = "(empty)".to_string();
    }
    if total > MAX_ENTRIES {
        let _ = write!(
            out,
            "\n[truncated: showing {MAX_ENTRIES} of {total} entries]"
        );
    }
    ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use barry_policy::PolicyConfig;
    use serde_json::json;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::create_dir_all(p.join("src/deep")).unwrap();
        fs::create_dir_all(p.join("secret")).unwrap();
        fs::create_dir_all(p.join(".git")).unwrap();
        fs::write(p.join("src/main.rs"), "fn main() {}\nlet Needle = 1;\n").unwrap();
        fs::write(p.join("src/deep/lib.rs"), "pub fn needle() {}\n").unwrap();
        fs::write(p.join("README.md"), "needle in readme\n").unwrap();
        fs::write(p.join("secret/key.txt"), "needle-secret\n").unwrap();
        fs::write(p.join(".git/config"), "needle-git\n").unwrap();
        fs::write(p.join("bin.dat"), b"needle\0binary").unwrap();
        dir
    }

    fn policy(dir: &Path) -> Policy {
        Policy::new(PolicyConfig {
            cwd: dir.to_path_buf(),
            home: dir.to_path_buf(),
            extra_writable: vec![],
            read_deny: vec![dir.join("secret").display().to_string()],
            protected: vec![],
            rules: vec![],
            network: true,
        })
        .unwrap()
    }

    fn root(dir: &Path) -> String {
        dir.canonicalize().unwrap().display().to_string()
    }

    #[test]
    fn glob_regex_forms() {
        let re = glob_to_regex("*.rs").unwrap();
        assert!(re.is_match("a.rs") && re.is_match("src/deep/a.rs") && !re.is_match("a.rsx"));
        let re = glob_to_regex("src/**/*.rs").unwrap();
        assert!(
            re.is_match("src/a.rs") && re.is_match("src/deep/a.rs") && !re.is_match("x/src/a.rs")
        );
        let re = glob_to_regex("src/*.rs").unwrap();
        assert!(re.is_match("src/a.rs") && !re.is_match("src/deep/a.rs"));
        let re = glob_to_regex("file?.[ab]").unwrap();
        assert!(re.is_match("file1.a") && !re.is_match("file1.c"));
        let re = glob_to_regex("[!a]x").unwrap();
        assert!(re.is_match("bx") && !re.is_match("ax"));
        // Regex metacharacters in the glob are literal.
        assert!(glob_to_regex("a+b(1).txt").unwrap().is_match("a+b(1).txt"));
    }

    #[test]
    fn glob_finds_files_skips_git_and_denied() {
        let dir = tree();
        let r = run_glob(
            &json!({"pattern": "*", "path": root(dir.path())}),
            &policy(dir.path()),
        );
        assert!(r.ok);
        assert!(r.content.contains("README.md"));
        assert!(r.content.contains("src/deep/lib.rs"));
        assert!(!r.content.contains("key.txt"), "read-denied: {}", r.content);
        assert!(!r.content.contains(".git"), "skipped: {}", r.content);
    }

    #[test]
    fn glob_pattern_filters_and_no_match_is_ok() {
        let dir = tree();
        let p = policy(dir.path());
        let r = run_glob(&json!({"pattern": "*.rs", "path": root(dir.path())}), &p);
        assert_eq!(r.content.lines().count(), 2, "{}", r.content);
        let r = run_glob(&json!({"pattern": "*.zzz", "path": root(dir.path())}), &p);
        assert!(r.ok && r.content == "no files matched");
    }

    #[test]
    fn glob_output_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(MAX_ENTRIES + 5) {
            fs::write(dir.path().join(format!("f{i:05}.txt")), "").unwrap();
        }
        let r = run_glob(
            &json!({"pattern": "*.txt", "path": root(dir.path())}),
            &policy(dir.path()),
        );
        assert_eq!(r.content.lines().count(), MAX_ENTRIES + 1);
        assert!(r.content.contains("[truncated: showing 1000 of 1005"));
    }

    #[test]
    fn grep_finds_lines_with_numbers_and_skips_binary_git_denied() {
        let dir = tree();
        let r = run_grep(
            &json!({"pattern": "needle", "path": root(dir.path())}),
            &policy(dir.path()),
        );
        assert!(r.ok);
        assert!(r.content.contains("lib.rs:1: pub fn needle() {}"));
        assert!(r.content.contains("README.md:1: needle in readme"));
        assert!(!r.content.contains("secret"), "{}", r.content);
        assert!(!r.content.contains("needle-git"), "{}", r.content);
        assert!(!r.content.contains("bin.dat"), "{}", r.content);
    }

    #[test]
    fn grep_options_and_errors() {
        let dir = tree();
        let p = policy(dir.path());
        let base = root(dir.path());
        let r = run_grep(&json!({"pattern": "NEEDLE", "path": base}), &p);
        assert_eq!(r.content, "no matches");
        let r = run_grep(
            &json!({"pattern": "NEEDLE", "path": base, "case_insensitive": true, "glob": "*.md"}),
            &p,
        );
        assert!(r.content.contains("README.md:1") && !r.content.contains("lib.rs"));
        let r = run_grep(&json!({"pattern": "(", "path": base}), &p);
        assert!(!r.ok && r.content.contains("invalid regex"));
        let r = run_grep(&json!({"path": base}), &p);
        assert!(!r.ok && r.content.contains("missing pattern"));
    }

    #[test]
    fn grep_single_file_and_output_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big.txt");
        let long = format!("x{}\n", "y".repeat(1000));
        fs::write(&file, long.repeat(MAX_MATCHES + 10)).unwrap();
        let r = run_grep(
            &json!({"pattern": "x", "path": file.display().to_string()}),
            &policy(dir.path()),
        );
        assert!(r.ok);
        assert_eq!(r.content.lines().count(), MAX_MATCHES + 1);
        assert!(r.content.contains("[truncated: showing 200 of 210"));
        assert!(r.content.lines().next().unwrap().len() < MAX_LINE_CHARS + 200);
    }

    #[test]
    fn ls_lists_entries_hides_denied() {
        let dir = tree();
        let r = run_ls(&json!({"path": root(dir.path())}), &policy(dir.path()));
        assert!(r.ok);
        let lines: Vec<&str> = r.content.lines().collect();
        assert!(lines.contains(&"src/") && lines.contains(&"README.md"));
        assert!(!lines.contains(&"secret/"), "{}", r.content);
    }

    #[test]
    fn denied_root_is_refused_and_missing_root_fails() {
        let dir = tree();
        let p = policy(dir.path());
        let secret = dir.path().join("secret").display().to_string();
        for r in [
            run_ls(&json!({"path": secret}), &p),
            run_glob(&json!({"pattern": "*", "path": secret}), &p),
            run_grep(&json!({"pattern": "n", "path": secret}), &p),
        ] {
            assert!(!r.ok);
            assert!(r.content.contains("denied"), "{}", r.content);
            assert!(!r.content.contains("needle-secret"));
        }
        let r = run_ls(
            &json!({"path": dir.path().join("nope").display().to_string()}),
            &p,
        );
        assert!(!r.ok && r.content.contains("no such path"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let dir = tree();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("o.txt"), "needle-outside\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let r = run_grep(
            &json!({"pattern": "needle", "path": root(dir.path())}),
            &policy(dir.path()),
        );
        assert!(!r.content.contains("needle-outside"), "{}", r.content);
        let r = run_glob(
            &json!({"pattern": "*.txt", "path": root(dir.path())}),
            &policy(dir.path()),
        );
        assert!(!r.content.contains("o.txt"), "{}", r.content);
    }
}
