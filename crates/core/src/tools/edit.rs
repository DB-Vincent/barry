//! The `edit` tool: argument parsing, applying edits in memory, and
//! unified-diff output.

use std::fmt::Write as _;
use std::path::Path;

use barry_protocol::ToolSpec;
use futures::future::BoxFuture;
use serde_json::{Value, json};

use super::write::write_file;
use super::{Tool, ToolCtx, ToolResult, authorise_write};
use crate::CoreError;
use crate::context::truncate::truncate;

pub(super) struct EditTool;

impl Tool for EditTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "edit".to_string(),
            description: "Replace text in a file you have read. Give old_string and new_string, or an edits array applied in order (all or nothing). old_string must match exactly once unless replace_all is true. Returns a unified diff. Fails if the file was not read first or changed since.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the file" },
                    "old_string": { "type": "string", "description": "Text to replace" },
                    "new_string": { "type": "string", "description": "Replacement text" },
                    "replace_all": {
                        "type": "boolean",
                        "description": "Replace every occurrence of old_string (default false)"
                    },
                    "edits": {
                        "type": "array",
                        "description": "Several replacements, applied in order. Use instead of old_string/new_string.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_string": { "type": "string" },
                                "new_string": { "type": "string" },
                                "replace_all": { "type": "boolean" }
                            },
                            "required": ["old_string", "new_string"]
                        }
                    }
                },
                "required": ["path"]
            }),
        }
    }

    fn execute<'a>(&'a self, ctx: ToolCtx<'a>) -> BoxFuture<'a, Result<ToolResult, CoreError>> {
        Box::pin(run(ctx))
    }
}

async fn run(mut ctx: ToolCtx<'_>) -> Result<ToolResult, CoreError> {
    let path = ctx.str_arg("path");
    match authorise_write(&mut ctx, "edit", &path).await? {
        Ok(target) => edit_file(&mut ctx, &target).await,
        Err(denied) => Ok(denied),
    }
}

async fn edit_file(ctx: &mut ToolCtx<'_>, path: &Path) -> Result<ToolResult, CoreError> {
    let shown = path.display().to_string();
    let fail = |message: String| ToolResult::new(false, message.clone(), message);
    let edits = match parse_edits(&ctx.arguments) {
        Ok(edits) => edits,
        Err(message) => return Ok(fail(format!("edit failed: {message}"))),
    };
    // Stale-edit guard: the model must have read the file, and it must not
    // have changed since (by the user, a formatter, or a bash command).
    if let Err(message) = ctx.reads.check_fresh(path) {
        return Ok(fail(message));
    }
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(CoreError::Io)?;
    let (new_content, replacements) = match apply_edits(&content, &edits) {
        Ok(applied) => applied,
        Err(message) => {
            return Ok(fail(format!("{message} in {shown}; no changes made")));
        }
    };
    write_file(path, &new_content)
        .await
        .map_err(CoreError::Io)?;
    ctx.reads.record(path);

    let diff = unified_diff(&shown, &content, &new_content);
    let diff = truncate(&diff, 10_000);
    let noun = if replacements == 1 {
        "replacement"
    } else {
        "replacements"
    };
    let mut result = ToolResult::new(
        true,
        format!("edited {shown}: {replacements} {noun}\n{diff}"),
        format!("edited {shown}: {replacements} {noun}"),
    );
    result.changed = Some(path.to_path_buf());
    Ok(result)
}

/// One replacement.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Edit {
    pub(super) old_string: String,
    pub(super) new_string: String,
    pub(super) replace_all: bool,
}

/// Lines of unchanged context around each hunk.
const CONTEXT: usize = 3;
/// Above this many cells the line diff falls back to one whole-block hunk.
const MAX_LCS_CELLS: usize = 4_000_000;

fn parse_one(v: &Value, label: &str) -> Result<Edit, String> {
    let get = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("{label}missing string '{key}'"))
    };
    Ok(Edit {
        old_string: get("old_string")?,
        new_string: get("new_string")?,
        replace_all: v
            .get("replace_all")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Reads the edits out of the tool arguments: either a single
/// `old_string`/`new_string` pair (with optional `replace_all`) or an `edits`
/// array of such pairs, never both.
pub(super) fn parse_edits(args: &Value) -> Result<Vec<Edit>, String> {
    match (args.get("edits"), args.get("old_string")) {
        (Some(_), Some(_)) => {
            Err("give either old_string/new_string or edits, not both".to_string())
        }
        (Some(edits), None) => {
            let list = edits.as_array().ok_or("'edits' must be an array")?;
            if list.is_empty() {
                return Err("'edits' is empty".to_string());
            }
            list.iter()
                .enumerate()
                .map(|(i, v)| parse_one(v, &format!("edit {}: ", i + 1)))
                .collect()
        }
        (None, _) => parse_one(args, "").map(|e| vec![e]),
    }
}

/// Applies the edits in order, each to the result of the previous one.
/// All-or-nothing: the first failure returns an error naming the edit, and the
/// caller writes nothing. On success returns the new content and the number
/// of replacements made.
pub(super) fn apply_edits(content: &str, edits: &[Edit]) -> Result<(String, usize), String> {
    let mut current = content.to_string();
    let mut replacements = 0;
    for (i, edit) in edits.iter().enumerate() {
        let label = if edits.len() > 1 {
            format!("edit {}: ", i + 1)
        } else {
            String::new()
        };
        if edit.old_string.is_empty() {
            return Err(format!("{label}old_string is empty"));
        }
        if edit.old_string == edit.new_string {
            return Err(format!("{label}old_string and new_string are identical"));
        }
        let count = current.matches(edit.old_string.as_str()).count();
        match count {
            0 => return Err(format!("{label}no matches found for '{}'", edit.old_string)),
            1 => current = current.replacen(&edit.old_string, &edit.new_string, 1),
            n if edit.replace_all => {
                current = current.replace(&edit.old_string, &edit.new_string);
                replacements += n - 1;
            }
            n => {
                return Err(format!(
                    "{label}found {n} matches for '{}'; add context to make it unique or set replace_all",
                    edit.old_string
                ));
            }
        }
        replacements += 1;
    }
    Ok((current, replacements))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// Line-level diff of `old` against `new`, as `(op, line)` pairs. Common
/// prefix and suffix are trimmed first so the quadratic part only sees the
/// changed middle.
fn diff_lines<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(Op, &'a str)> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let max_suffix = old.len().min(new.len()) - prefix;
    let suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(max_suffix)
        .take_while(|(a, b)| a == b)
        .count();
    let (om, nm) = (
        &old[prefix..old.len() - suffix],
        &new[prefix..new.len() - suffix],
    );

    let mut ops: Vec<(Op, &str)> = old[..prefix].iter().map(|l| (Op::Equal, *l)).collect();
    if om.len().saturating_mul(nm.len()) > MAX_LCS_CELLS {
        ops.extend(om.iter().map(|l| (Op::Delete, *l)));
        ops.extend(nm.iter().map(|l| (Op::Insert, *l)));
    } else {
        // table[i][j] = LCS length of om[i..] and nm[j..].
        let w = nm.len() + 1;
        let mut table = vec![0u32; (om.len() + 1) * w];
        for i in (0..om.len()).rev() {
            for j in (0..nm.len()).rev() {
                table[i * w + j] = if om[i] == nm[j] {
                    table[(i + 1) * w + j + 1] + 1
                } else {
                    table[(i + 1) * w + j].max(table[i * w + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < om.len() && j < nm.len() {
            if om[i] == nm[j] {
                ops.push((Op::Equal, om[i]));
                i += 1;
                j += 1;
            } else if table[(i + 1) * w + j] >= table[i * w + j + 1] {
                ops.push((Op::Delete, om[i]));
                i += 1;
            } else {
                ops.push((Op::Insert, nm[j]));
                j += 1;
            }
        }
        ops.extend(om[i..].iter().map(|l| (Op::Delete, *l)));
        ops.extend(nm[j..].iter().map(|l| (Op::Insert, *l)));
    }
    ops.extend(old[old.len() - suffix..].iter().map(|l| (Op::Equal, *l)));
    ops
}

/// A unified diff of `old` to `new` with three lines of context, headed by
/// `path`. Returns an empty string when nothing changed.
pub(super) fn unified_diff(path: &str, old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = diff_lines(&old_lines, &new_lines);
    if ops.iter().all(|(op, _)| *op == Op::Equal) {
        return String::new();
    }

    // Line numbers (0-based) in old/new at the start of each op.
    let mut positions = Vec::with_capacity(ops.len());
    let (mut o, mut n) = (0usize, 0usize);
    for (op, _) in &ops {
        positions.push((o, n));
        match op {
            Op::Equal => {
                o += 1;
                n += 1;
            }
            Op::Delete => o += 1,
            Op::Insert => n += 1,
        }
    }

    // Hunk ranges over ops: each change widened by CONTEXT, overlaps merged.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (idx, (op, _)) in ops.iter().enumerate() {
        if *op == Op::Equal {
            continue;
        }
        let start = idx.saturating_sub(CONTEXT);
        let end = (idx + CONTEXT + 1).min(ops.len());
        match ranges.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => ranges.push((start, end)),
        }
    }

    let mut out = format!("--- {path}\n+++ {path}\n");
    for (start, end) in ranges {
        let slice = &ops[start..end];
        let old_len = slice.iter().filter(|(op, _)| *op != Op::Insert).count();
        let new_len = slice.iter().filter(|(op, _)| *op != Op::Delete).count();
        let (os, ns) = positions[start];
        // An empty range is reported one line earlier, as `diff -u` does.
        let old_start = if old_len == 0 { os } else { os + 1 };
        let new_start = if new_len == 0 { ns } else { ns + 1 };
        let _ = writeln!(out, "@@ -{old_start},{old_len} +{new_start},{new_len} @@");
        for (op, line) in slice {
            out.push(match op {
                Op::Equal => ' ',
                Op::Delete => '-',
                Op::Insert => '+',
            });
            out.push_str(line.strip_suffix('\n').unwrap_or(line));
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn e(old: &str, new: &str, all: bool) -> Edit {
        Edit {
            old_string: old.into(),
            new_string: new.into(),
            replace_all: all,
        }
    }

    #[test]
    fn parses_single_and_multi_forms() {
        let single = parse_edits(&json!({"old_string":"a","new_string":"b","replace_all":true}));
        assert_eq!(single.unwrap(), vec![e("a", "b", true)]);
        let multi = parse_edits(&json!({"edits":[
            {"old_string":"a","new_string":"b"},
            {"old_string":"c","new_string":"d","replace_all":true}]}));
        assert_eq!(multi.unwrap(), vec![e("a", "b", false), e("c", "d", true)]);
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse_edits(&json!({})).is_err());
        assert!(parse_edits(&json!({"edits": []})).is_err());
        assert!(parse_edits(&json!({"edits": "x"})).is_err());
        assert!(
            parse_edits(&json!({"edits":[{"old_string":"a"}]}))
                .unwrap_err()
                .contains("edit 1: missing string 'new_string'")
        );
        assert!(
            parse_edits(&json!({"old_string":"a","new_string":"b","edits":[]}))
                .unwrap_err()
                .contains("not both")
        );
    }

    #[test]
    fn unique_match_replaces_once() {
        let (out, n) = apply_edits("x a y", &[e("a", "b", false)]).unwrap();
        assert_eq!((out.as_str(), n), ("x b y", 1));
    }

    #[test]
    fn ambiguous_match_needs_replace_all() {
        let err = apply_edits("a a a", &[e("a", "b", false)]).unwrap_err();
        assert!(err.contains("found 3 matches"), "{err}");
        let (out, n) = apply_edits("a a a", &[e("a", "b", true)]).unwrap();
        assert_eq!((out.as_str(), n), ("b b b", 3));
    }

    #[test]
    fn edits_apply_in_order_and_are_all_or_nothing() {
        let (out, n) =
            apply_edits("one", &[e("one", "two", false), e("two", "three", false)]).unwrap();
        assert_eq!((out.as_str(), n), ("three", 2));
        let err = apply_edits("one", &[e("one", "two", false), e("zzz", "q", false)]).unwrap_err();
        assert!(err.starts_with("edit 2: no matches"), "{err}");
    }

    #[test]
    fn degenerate_edits_are_rejected() {
        assert!(apply_edits("a", &[e("", "b", false)]).is_err());
        assert!(apply_edits("a", &[e("a", "a", false)]).is_err());
    }

    #[test]
    fn diff_shows_hunk_with_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        let new = "1\n2\n3\n4\nFIVE\n6\n7\n8\n9\n10\n";
        let diff = unified_diff("f.txt", old, new);
        assert_eq!(
            diff,
            "--- f.txt\n+++ f.txt\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+FIVE\n 6\n 7\n 8\n"
        );
    }

    #[test]
    fn diff_merges_close_changes_and_splits_far_ones() {
        let old: String = (1..=30).map(|i| format!("{i}\n")).collect();
        let new = old
            .replace("\n3\n", "\nthree\n")
            .replace("\n28\n", "\ntwenty-eight\n");
        let diff = unified_diff("f", &old, &new);
        assert_eq!(diff.matches("@@ -").count(), 2, "{diff}");
        assert!(diff.contains("-3\n+three\n") && diff.contains("-28\n+twenty-eight\n"));
    }

    #[test]
    fn diff_handles_insert_delete_and_empty_files() {
        let diff = unified_diff("f", "a\nb\n", "a\nx\nb\n");
        assert_eq!(diff, "--- f\n+++ f\n@@ -1,2 +1,3 @@\n a\n+x\n b\n");
        let diff = unified_diff("f", "a\nb\nc\n", "a\nc\n");
        assert_eq!(diff, "--- f\n+++ f\n@@ -1,3 +1,2 @@\n a\n-b\n c\n");
        let diff = unified_diff("f", "", "a\n");
        assert_eq!(diff, "--- f\n+++ f\n@@ -0,0 +1,1 @@\n+a\n");
        assert_eq!(unified_diff("f", "same\n", "same\n"), "");
    }

    #[test]
    fn diff_marks_a_changed_last_line_without_newline() {
        let diff = unified_diff("f", "a\nb", "a\nb\n");
        assert!(diff.contains("-b\n+b\n"), "{diff}");
    }
}
