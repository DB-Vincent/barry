//! Bash command analysis for the rule layer (PLAN 6.1.2).
//!
//! Substring matching on a command string is trivially bypassable
//! (`env bash -c ...`, `ls\nrm x`, `find -exec`). Instead, the command is
//! parsed into an actual syntax tree and only a small, fully understood subset
//! is accepted:
//!
//! - commands joined by `&&`, `||`, `;`, `|` or newlines
//! - plain words and single- or double-quoted strings without expansions
//! - redirections to file paths
//!
//! Anything else — `$(...)`, backticks, `$VAR`, subshells, heredocs, process
//! substitution, assignments, functions, control flow — is reported as
//! [`Analysis::Complex`] and the caller fails closed with an `Ask`.

use tree_sitter::{Node, Parser};

/// The result of analysing a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Analysis {
    /// The command is understood: every sub-command is listed in order.
    Simple(Vec<SimpleCmd>),
    /// The command uses syntax this layer refuses to reason about.
    Complex(String),
}

/// One command in a simple command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCmd {
    /// The command's words, after stripping wrapper commands.
    pub argv: Vec<String>,
    /// Files the command redirects into (`> file`, `>> file`).
    pub redirect_targets: Vec<String>,
}

/// Analyse `command`.
///
/// A parse error, a syntax error node, or an unknown node kind all yield
/// [`Analysis::Complex`]: the rule layer never guesses.
#[must_use]
pub fn analyse(command: &str) -> Analysis {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return Analysis::Complex("bash grammar unavailable".to_string());
    }
    let Some(tree) = parser.parse(command, None) else {
        return Analysis::Complex("command could not be parsed".to_string());
    };
    let root = tree.root_node();
    if root.has_error() {
        return Analysis::Complex("command has a syntax error".to_string());
    }

    let mut commands = Vec::new();
    match walk(root, command.as_bytes(), &mut commands) {
        Ok(()) if !commands.is_empty() => Analysis::Simple(commands),
        Ok(()) => Analysis::Complex("empty command".to_string()),
        Err(reason) => Analysis::Complex(reason),
    }
}

/// Visit one node, appending every command it contains.
fn walk(node: Node<'_>, src: &[u8], out: &mut Vec<SimpleCmd>) -> Result<(), String> {
    let mut cursor = node.walk();
    match node.kind() {
        // A program is a sequence of commands separated by newlines; `list`
        // and `pipeline` separate them with `&&`, `||`, `;`, `|`. All of them
        // are safe to flatten into their commands.
        "program" | "list" | "pipeline" => {
            for child in node.named_children(&mut cursor) {
                walk(child, src, out)?;
            }
            Ok(())
        }
        "redirected_statement" => {
            let mut targets = Vec::new();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "file_redirect" {
                    targets.push(redirect_target(child, src)?);
                } else {
                    walk(child, src, out)?;
                }
            }
            // In `a && b > f` the redirect belongs to the last command.
            let Some(last) = out.last_mut() else {
                return Err("redirect without a command".to_string());
            };
            last.redirect_targets.extend(targets);
            Ok(())
        }
        "command" => {
            out.push(parse_command(node, src)?);
            Ok(())
        }
        "comment" => Ok(()),
        other => Err(format!("unsupported shell syntax: {other}")),
    }
}

/// The file a `file_redirect` writes to.
fn redirect_target(node: Node<'_>, src: &[u8]) -> Result<String, String> {
    let destination = node
        .child_by_field_name("destination")
        .ok_or_else(|| "redirect without a destination".to_string())?;
    match destination.kind() {
        "word" | "number" => text(destination, src),
        "raw_string" => unquote(&text(destination, src)?, '\''),
        "string" if is_literal_string(destination) => unquote(&text(destination, src)?, '"'),
        other => Err(format!("unsupported redirect destination: {other}")),
    }
}

/// Turn one `command` node into argv.
fn parse_command(node: Node<'_>, src: &[u8]) -> Result<SimpleCmd, String> {
    let mut argv = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_name" | "word" | "number" => argv.push(text(child, src)?),
            "raw_string" => argv.push(unquote(&text(child, src)?, '\'')?),
            // Double quotes are fine only without expansion inside them.
            "string" if is_literal_string(child) => {
                argv.push(unquote(&text(child, src)?, '"')?);
            }
            "comment" => {}
            other => return Err(format!("unsupported shell syntax: {other}")),
        }
    }
    strip_wrappers(&mut argv);
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    Ok(SimpleCmd {
        argv,
        redirect_targets: Vec::new(),
    })
}

/// Remove wrapper commands so `timeout 5 cargo test` is judged as
/// `cargo test` (PLAN 6.1.2): `timeout`, `nice`, `nohup`, `command`, and `env`
/// with plain `K=V` words.
fn strip_wrappers(argv: &mut Vec<String>) {
    loop {
        let Some(head) = argv.first().map(String::as_str) else {
            return;
        };
        match head {
            "timeout" => {
                argv.remove(0);
                // Drop the duration if it looks like one ("5", "5s", "1m").
                if argv
                    .first()
                    .is_some_and(|a| a.starts_with(|c: char| c.is_ascii_digit()))
                {
                    argv.remove(0);
                }
            }
            "nice" => {
                argv.remove(0);
                if argv.first().map(String::as_str) == Some("-n") {
                    argv.remove(0);
                }
            }
            "nohup" | "command" => {
                argv.remove(0);
            }
            "env" => {
                // Bare `env` only prints the environment; keep it so the rule
                // layer can see it. With more words it runs a command.
                if argv.len() == 1 {
                    return;
                }
                argv.remove(0);
                while argv
                    .first()
                    .is_some_and(|a| a.contains('=') && !a.starts_with('-'))
                {
                    argv.remove(0);
                }
            }
            _ => return,
        }
    }
}

/// Returns `true` when `argv` starts with `prefix`, compared word by word.
pub(crate) fn has_prefix(argv: &[String], prefix: &[String]) -> bool {
    argv.len() >= prefix.len() && argv.iter().zip(prefix).all(|(word, want)| word == want)
}

/// Whether a `string` node is literal: its only children are text content,
/// with no expansions or substitutions.
fn is_literal_string(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
    children
        .iter()
        .all(|child| child.kind() == "string_content")
}

fn text(node: Node<'_>, src: &[u8]) -> Result<String, String> {
    node.utf8_text(src)
        .map(str::to_string)
        .map_err(|_| "command is not valid UTF-8".to_string())
}

fn unquote(text: &str, quote: char) -> Result<String, String> {
    text.strip_prefix(quote)
        .and_then(|t| t.strip_suffix(quote))
        .map(str::to_string)
        .ok_or_else(|| "unterminated quoted string".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(command: &str) -> Vec<Vec<String>> {
        match analyse(command) {
            Analysis::Simple(cmds) => cmds.into_iter().map(|c| c.argv).collect(),
            Analysis::Complex(reason) => panic!("{command}: unexpected complex: {reason}"),
        }
    }

    #[test]
    fn plain_commands_are_simple() {
        assert_eq!(simple("ls -la"), vec![vec!["ls", "-la"]]);
        assert_eq!(
            simple("git status && ls"),
            vec![vec!["git", "status"], vec!["ls"]]
        );
        assert_eq!(simple("ls\npwd"), vec![vec!["ls"], vec!["pwd"]]);
    }

    #[test]
    fn quoted_strings_are_unquoted() {
        assert_eq!(
            simple("git commit -m 'a b'"),
            vec![vec!["git", "commit", "-m", "a b"]]
        );
        assert_eq!(simple("echo \"a b\""), vec![vec!["echo", "a b"]]);
    }

    #[test]
    fn wrappers_are_stripped() {
        assert_eq!(simple("timeout 5 cargo test"), vec![vec!["cargo", "test"]]);
        assert_eq!(simple("env FOO=1 ls"), vec![vec!["ls"]]);
    }

    #[test]
    fn redirects_are_collected() {
        match analyse("echo hi > out.txt") {
            Analysis::Simple(cmds) => {
                assert_eq!(cmds[0].redirect_targets, vec!["out.txt"]);
            }
            Analysis::Complex(reason) => panic!("unexpected complex: {reason}"),
        }
    }

    #[test]
    fn dangerous_syntax_is_complex() {
        for command in [
            "ls $(rm -rf x)",
            "echo `ls`",
            "echo $HOME",
            "echo ${HOME}",
            "(ls)",
            "{ ls; }",
            "if true; then ls; fi",
            "for f in a; do ls; done",
            "f() { ls; }",
            "cat <<EOF\nhi\nEOF",
            "diff <(a) <(b)",
            "FOO=1 ls",
            "echo \"a $x\"",
        ] {
            assert!(
                matches!(analyse(command), Analysis::Complex(_)),
                "{command} should be complex"
            );
        }
    }
}
