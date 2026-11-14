# barry

A security-first coding agent harness written in Rust.

barry is a terminal coding agent, in the same family as Claude Code, Codex and Pi. It runs in your terminal, inspects and edits files, runs commands, and calls tools on your behalf — with security as the first design goal.

## Goals

- **Simplicity** — a minimal line REPL, no TUI. Keep the loop simple.
- **Efficiency** — fast startup, low per-turn overhead, fat-LTO release build.
- **Security** — every command runs in an OS sandbox (Seatbelt on macOS, bubblewrap + seccomp on Linux). Credential paths are read-denied where configured. Rule precedence is deny > ask > allow. Every action is recorded in an append-only, hash-chained audit log with secrets redacted.

## Platforms

- macOS (Seatbelt sandbox)
- Linux (bubblewrap + seccomp sandbox)

Windows is not supported in v1.

## Providers

barry speaks OpenAI-compatible Chat Completions, so it works with OpenAI, vLLM, LM Studio, llama.cpp server, and Ollama (local). No Anthropic or Bedrock in v1. There is no MCP in v1.

Point it at a server with `BARRY_BASE_URL` (default `http://localhost:11434/v1`).

## Installation

```bash
git clone <repo-url>
cd barry
cargo build --release
```

The release binary is at `target/release/barry`. Copy it onto your `PATH`. The workspace pins a stable toolchain via `rust-toolchain.toml`.

## Usage

### Headless mode

Run a single prompt and exit:

```bash
barry -p "Fix the failing test in src/lib.rs"
```

Options:

| Option | Meaning |
|--------|---------|
| `--json` | Emit each event as one JSONL line instead of pretty output |
| `--model <name>` | Override the model id sent to the provider |
| `--resume <file\|prefix>` | Continue a session from its log file, or a timestamp/UUID prefix in the default session directory |

Exit codes: `0` on success, `1` on error/aborted, `2` on config error, `3` on turn limit.

Headless mode never prompts for approval: an action that needs approval is denied, and the model is told that approval is unavailable in headless mode.

### Other commands

```bash
barry --version                 # print version and exit
barry rules check "<command>"   # print the policy decision and the deciding rule id
barry log verify <file>         # verify the hash chain of a session log
```

`log verify` prints `ok (<n> entries)` and exits 0. If a line was edited, it prints `broken at line <k>` and exits 1.

### Interactive REPL (not implemented yet)

Running `barry` with no `-p` currently exits 2 with an error. The planned REPL is a minimal line interface in the current working directory with these slash commands:

| Command | Meaning |
|---------|---------|
| `/exit` | Quit |
| `/compact` | Force context compaction |
| `/grants` | List path grants |
| `/model <name>` | Switch model |

## Configuration

User config is read from the file named by `$BARRY_CONFIG`; if the variable is unset or the file does not exist, built-in defaults apply. Supported keys today:

```toml
[sandbox]
network = true   # false: sandboxed commands cannot use the network

[fs]
read_deny = []   # paths the model may not read, through the read tool or bash
protected = []   # path components that always require approval to write
```

The model id comes from `--model` (default `local`) and the endpoint from `BARRY_BASE_URL` (default `http://localhost:11434/v1`).

The rest of the config schema in PLAN 6.8 — `~/.config/barry/config.toml` as the default path, `default_model`/`max_turns`, model profiles, `fs.extra_writable`, `sandbox.env_passthrough`, user rules, and trusted project config — is not implemented yet.

## Security model

Two independent layers:

1. **Policy layer** — path checks for reads and writes, plus a bash rule table. Default deny rules cover `sudo`, `rm -rf /`, `curl ... | sh`, `git push --force`, etc. Default allow rules cover `ls`, `cargo test`, `git status`, etc.
2. **Sandbox layer** — each command is re-executed inside the sandbox. On Linux this requires `bwrap`; if `bwrap` is missing, commands fail closed and never run unsandboxed. Network access can be switched off with `sandbox.network = false`.

File writes stay inside the current directory unless you grant a path. Configured read-deny paths are refused without a prompt, so their contents never reach the model.

Every session appends to `~/.local/state/barry/sessions/` (or `$XDG_STATE_HOME/barry/sessions`) as JSONL. Each line carries the SHA-256 of the previous line and a hash of itself, so `barry log verify` can name the first edited line. Lines are `0600` in a `0700` directory, and one writer at a time is enforced with an advisory lock. Entries cover the session start (cwd, model, version, policy fingerprint), conversation messages, tool decisions (with the deciding rule id, user or default), tool results, grants, approved bash prefixes and notices. Decisions are written before the tool runs, so a crash cannot lose the audit trail.

Secrets are redacted before an entry is hashed: built-in patterns (`sk-…`, GitHub tokens, AWS keys, JWTs, private keys) and the values of environment variables whose names contain `KEY`, `TOKEN`, `SECRET` or `PASSWORD`. Redaction applies only to the log; the model still sees real tool output. `barry --resume` verifies the chain before appending and refuses a broken log. The chain detects edits and middle deletions, but not truncation: deleting trailing entries (or the whole file) leaves a shorter chain that still verifies. Anchor the head hash elsewhere if you need to detect truncation.

## Business cases and testing

barry is built **business-case first** (BC-first). A business case is a statement of something a user or the user's security posture needs to be true, checked through observable outcomes — never through "the code I wrote works the way I wrote it."

Before any production code is written for a milestone, its business cases are turned into tests. The tests must fail first (compile error or assertion failure), then the code is written to make them pass. A test may only change if the business case changes. If a behaviour isn't covered by a business case, it isn't written.

Tests check observable outcomes only: files on disk, events received, what the model saw, approval requests, session-log contents, and process exit codes — never internal struct fields or private functions.

## Milestones

barry is under active development. Each milestone is a separate branch and PR with its business-case tests written first. M0–M5 are implemented; M6 is next (the REPL part of M2 is still pending).

| Milestone | Focus |
|-----------|-------|
| M0 | Skeleton, testkit, config loading, `--version`, `rules check` |
| M1 | LLM client (wire level, `FakeLlm`) |
| M2 | Agent loop, tools, REPL, headless |
| M3 | Policy engine |
| M4 | OS sandbox |
| M5 | Session and audit log |
| M6 | Instructions, skills, compaction |
| M7 | Hooks and project trust |
| M8 | Sub-agents |
| M9 | Hardening (fuzzing, threat model) |

## Current state

Implemented so far:

- `barry --version` — prints `barry <semver>` and exits 0
- `barry rules check "<command>"` — prints the policy decision and the deciding rule id
- Config loading from `$BARRY_CONFIG` with clean error messages (exit 2 on malformed config, no backtrace)
- Streaming OpenAI-compatible client and the agent loop with `read`, `write`, `edit`, `bash` and the `agent` placeholder (the placeholder refuses clearly; sub-agents are M8)
- Headless `-p` mode with `--json`, wrapped tool results and the PLAN 5.2 system prompt
- Policy approvals with session grants, and the Linux/macOS OS sandbox
- Every session logged as hash-chained, redacted JSONL: `barry log verify <file>` and `barry --resume <file|prefix>`
- Test utilities (`Workspace`, `ScriptedProvider`, `ScriptedApprover`, `FakeLlm`)

Not implemented yet:

- The interactive REPL, context compaction, AGENTS.md/skills, hooks, project trust and sub-agents
- Model profiles and the rest of the config schema: only `sandbox.network`, `fs.read_deny` and `fs.protected` are read today
- Built-in path defaults: with no `fs.read_deny` / `fs.protected` entries, no credential path is read-denied and no path component is protected

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

CI runs on Ubuntu and macOS. Linux sandbox tests require `bubblewrap (bwrap)` and `kernel.apparmor_restrict_unprivileged_userns=0`.

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 Vincent De Borger.
