# barry

A security-first coding agent harness written in Rust.

barry is a terminal coding agent, in the same family as Claude Code, Codex and Pi. It runs in your terminal, inspects and edits files, runs commands, and calls tools on your behalf — with security as the first design goal.

## Goals

- **Simplicity** — a minimal line REPL, no TUI. Keep the loop simple.
- **Efficiency** — fast startup, low per-turn overhead, fat-LTO release build.
- **Security** — every command runs in an OS sandbox (Seatbelt on macOS, bubblewrap + seccomp on Linux). Credential paths are read-denied by default. Rule precedence is deny > ask > allow. Every action is recorded in an append-only, hash-chained audit log with secrets redacted.

## Platforms

- macOS (Seatbelt sandbox)
- Linux (bubblewrap + seccomp sandbox)

Windows is not supported in v1.

## Providers

barry speaks OpenAI-compatible Chat Completions, so it works with OpenAI, vLLM, LM Studio, llama.cpp server, and Ollama (local). No Anthropic or Bedrock in v1. There is no MCP in v1.

## Installation

```bash
git clone <repo-url>
cd barry
cargo build --release
```

The release binary is at `target/release/barry`. Copy it onto your `PATH`. The workspace pins a stable toolchain via `rust-toolchain.toml`.

## Usage

### Interactive REPL

```bash
cd my-project
barry
```

barry starts a REPL in the current working directory. Slash commands:

| Command | Meaning |
|---------|---------|
| `/exit` | Quit |
| `/compact` | Force context compaction |
| `/grants` | List path grants |
| `/model <name>` | Switch model |

### Headless mode

Run a single prompt and exit:

```bash
barry -p "Fix the failing test in src/lib.rs"
```

Options:

| Option | Meaning |
|--------|---------|
| `--json` | Emit each event as one JSONL line instead of pretty output |
| `--model <name>` | Override the default model |
| `--resume <id\|uuid-prefix>` | Rebuild history from a session log |

Exit codes: `0` on success, `1` on error/aborted, `2` on config error, `3` on turn limit.

### Other commands

```bash
barry --version                 # print version and exit
barry rules check "<command>"   # print the policy decision for a command
barry log verify <file>         # verify the hash chain of a session log
```

## Configuration

User config lives at `~/.config/barry/config.toml` (or `$BARRY_CONFIG` if set):

```toml
default_model = "local"
max_turns = 50

[models.local]
id = "qwen2.5-coder:14b"
base_url = "http://localhost:11434/v1"
context_window = 32768
max_output_tokens = 8192
compat = { reasoning_field = "reasoning", supports_parallel_tool_calls = true, supports_stream_usage = true }

[sandbox]
network = true
env_passthrough = []

[fs]
extra_writable = []
read_deny = []
protected = []
```

Project config at `<git root>/.barry/config.toml` can tighten rules without trust; loosening rules and hooks require explicit user trust.

## Security model

Two independent layers:

1. **Policy layer** — parses commands and applies allow/deny/ask rules. Default deny rules cover `sudo`, `rm -rf /`, `curl ... | sh`, `git push --force`, etc. Default allow rules cover `ls`, `cargo test`, `git status`, etc.
2. **Sandbox layer** — each command runs re-executed inside a sandbox. On Linux this requires `bwrap`; if `bwrap` is missing, commands fail closed and never run unsandboxed.

File writes stay inside the current directory unless you grant a path. Credential paths (`~/.ssh`, `~/.aws`, etc.) are read-denied by default, so their contents never reach the model or the log unredacted.

Every session is logged to `~/.local/state/barry/sessions/` (or `$XDG_STATE_HOME`) as hash-chained JSONL. Run `barry log verify` to check integrity.

## Business cases and testing

barry is built **business-case first** (BC-first). A business case is a statement of something a user or the user's security posture needs to be true, checked through observable outcomes — never through "the code I wrote works the way I wrote it."

Before any production code is written for a milestone, its business cases are turned into tests. The tests must fail first (compile error or assertion failure), then the code is written to make them pass. A test may only change if the business case changes. If a behaviour isn't covered by a business case, it isn't written.

Tests check observable outcomes only: files on disk, events received, what the model saw, approval requests, session-log contents, and process exit codes — never internal struct fields or private functions.

## Milestones

barry is under active development. Each milestone is a separate branch and PR with its business-case tests written first.

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
- `barry rules check "<command>"` — prints the policy decision for a command
- Config loading with clean error messages (exit 2 on malformed config, no backtrace)
- Test utilities (`Workspace`, `ScriptedProvider`, `ScriptedApprover`, `FakeLlm`)

The agent loop, LLM client streaming, OS sandbox, and audit log are planned but not yet implemented.

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