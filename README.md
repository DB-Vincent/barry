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

barry speaks OpenAI-compatible Chat Completions, so it works with OpenAI, vLLM, LM Studio, llama.cpp server, and Ollama (local). It also has an Anthropic Messages API provider (see below). There is no Bedrock adapter and no MCP in v1. The native CLI launcher described below is separate from this provider interface.

Point it at a server with `BARRY_BASE_URL` (default `http://localhost:11434/v1`).

### Anthropic (Claude) provider

Sign in once, then select the provider:

```bash
barry auth login anthropic
BARRY_PROVIDER=anthropic barry --model claude-sonnet-5-5
```

Barry asks the official `ant` CLI for the profile's access token on every request (`ant auth print-credentials --access-token`), so it never stores or refreshes credentials. `BARRY_ANTHROPIC_PROFILE` selects the profile (default `barry`). `BARRY_BASE_URL` overrides `https://api.anthropic.com`. Inside the REPL, a successful `/auth login anthropic` switches to this provider, and `/provider [openai|anthropic]` switches either way (the model name is kept; use `/model` to change it). `/provider codex` selects the Codex provider (below). Requests spend the signed-in Console organization's API credits, not a Claude subscription. Barry's sandbox, policy and audit log apply as with any provider.

## Installation

```bash
git clone <repo-url>
cd barry
cargo build --release
```

The release binary is at `target/release/barry`. Copy it onto your `PATH`, or use `./target/release/barry` in place of `barry` in the examples below. The workspace pins a stable toolchain via `rust-toolchain.toml`.

## Usage

### OpenAI API key

Set `OPENAI_API_KEY` and point Barry at OpenAI:

```bash
OPENAI_API_KEY=... BARRY_BASE_URL=https://api.openai.com/v1 barry --model <model>
```

The key is sent as a bearer token only over https or to a loopback server, never over plain http to another host. It bills API credits, not a ChatGPT subscription.

### Codex provider (ChatGPT subscription)

```bash
barry auth login codex
BARRY_PROVIDER=codex barry
```

Each turn runs `codex exec --json --sandbox read-only` with the conversation on stdin and uses Codex's own stored login (`OPENAI_API_KEY` and `CODEX_ACCESS_TOKEN` are removed from the child's environment). **Codex runs its own agent loop and tools. Barry's policy, sandbox and audit log do not govern what Codex does inside a turn, and Barry's tools are not offered to it.** Use `/model <name>` to pass a model to Codex; the default `default` lets Codex choose. In the REPL, a successful `/auth login codex` selects this provider, and `/provider codex` switches to it.

### Account sign-in

Barry can run the official Codex and Anthropic Console sign-in flows and show their configured authentication state. These commands perform authentication only; they do not send chat prompts or generate model responses.

For Codex, install the official [Codex CLI](https://developers.openai.com/codex/cli), then use:

```bash
barry auth login codex
barry auth status codex
barry auth logout codex
```

Codex uses its existing native credential store and respects `CODEX_HOME`. Its authentication is not managed through Anthropic profiles, so `--profile` is rejected for Codex. The child ignores `OPENAI_API_KEY` and `CODEX_ACCESS_TOKEN` so environment credentials do not shadow its stored login. To use Codex's device-code flow, run `barry auth login codex --no-browser`.

For Anthropic Console, install the official `ant` CLI first:

```bash
brew install anthropics/tap/ant
```

Then sign in, inspect the profile, or sign out:

```bash
barry auth login anthropic
barry auth status anthropic
barry auth logout anthropic
```

Login opens the official Console OAuth flow, where you choose an organization and workspace. On a machine without a local browser, use `barry auth login anthropic --no-browser` and follow the printed instructions. Barry uses a dedicated `barry` profile by default. All three commands accept `--profile NAME` to select another native profile explicitly; logout affects only that selected profile. The official CLI handles callback validation, credential storage and logout; Barry does not read or print access tokens. Barry run flags cannot be combined with `auth` commands.

If you already signed in using `ant auth login`, inspect its `default` profile without signing in again:

```bash
barry auth status anthropic --profile default
```

The same commands are available inside Barry's REPL:

```text
/auth login anthropic
/auth status anthropic
/auth logout anthropic
/auth status anthropic --profile default
/auth login codex
/auth status codex
/auth logout codex
```

The REPL remains open when authentication finishes or is cancelled with Ctrl-C. Standalone auth commands return to your shell.

For Anthropic, `status` displays the official CLI's configured credential source and workspace; it is not a live token-health or model-access check. The auth child ignores `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_PROFILE` so those variables cannot shadow the selected OAuth profile. `ANTHROPIC_CONFIG_DIR` is still respected. This Console profile is separate from a Claude Code subscription login. Signing in alone spends no credits; select the Anthropic provider (above) to send prompts. See Anthropic's [authentication documentation](https://platform.claude.com/docs/en/cli-sdks-libraries/cli/authentication).

### Native subscription CLI launcher

`barry subscription` launches an installed native CLI; it is **not a Barry Provider**. The selected CLI owns its agent loop, tools, sandbox and approvals, history and logs, and usage budgets. **Barry policy, sandbox, audit logging and run budgets do not apply to these sessions.** The security model and headless/REPL options elsewhere in this README describe Barry's own agent runs.

Install Codex or Claude Code separately using their official [Codex installation instructions](https://developers.openai.com/codex/cli) or [Claude Code setup instructions](https://code.claude.com/docs/en/setup). The chosen executable (`codex` or `claude`) must be on `PATH`. Barry does not install a missing CLI or fall back to another provider.

Sign in through the native CLI, choosing an eligible subscription account:

```bash
codex login
# Or, for Claude Code:
claude auth login
```

Existing native logins work unchanged. Eligible subscription use requires no API token; the native CLI determines the active authentication method and account eligibility. Barry does not copy, proxy or store credentials, and does not force subscription authentication if the CLI is configured to use an API key. See [Codex authentication](https://developers.openai.com/codex/auth) and [Claude Code authentication](https://code.claude.com/docs/en/authentication) for supported accounts and authentication configuration. Subscription usage limits still apply; this launcher does not make subscriptions compatible with Barry's API provider.

Check the active login through the launcher:

```bash
barry subscription codex -- login status
barry subscription claude -- auth status
```

With no native arguments, start an interactive session in the current working directory:

```bash
barry subscription codex
barry subscription claude
```

Pass native arguments only after `--`. Barry directly replaces its process with the chosen executable, passes those arguments unchanged without a shell, and preserves the working directory and terminal streams. For a single prompt and exit, use the selected CLI's own syntax:

```bash
barry subscription codex -- exec "Explain this repository"
barry subscription claude -- -p "Explain this repository"
```

Barry run flags cannot be combined with `subscription`: for example, `barry --max-tokens 1000 subscription codex` is rejected before launching anything. To select a native model or permission setting, pass the chosen CLI's flags after `--` and consult its help:

```bash
barry subscription codex -- --help
barry subscription claude -- --help
```

Barry's default OpenAI-compatible endpoint workflow remains unchanged: set `BARRY_BASE_URL` and run `barry` or `barry -p "..."` to use Barry's own agent and security controls.

### Headless mode

Run a single prompt and exit:

```bash
barry -p "Fix the failing test in src/lib.rs"
```

Options:

| Option | Meaning |
|--------|---------|
| `--json` | Emit each event as one JSONL line instead of pretty output, ending with a `RunSummary` line |
| `--model <name>` | Override the model id sent to the provider |
| `--resume <file\|prefix>` | Continue a session from its log file, or a timestamp/UUID prefix in the default session directory |
| `--approval-file <file>` | Approve only the actions listed in a TOML file; deny everything else that needs approval |
| `--max-tokens <n>` | Stop after `n` input plus output tokens |
| `--max-cost-usd <usd>` | Stop after an estimated cost; needs token prices in `[budgets]` |
| `--max-wall-secs <n>` | Stop after `n` wall-clock seconds |
| `--max-bash-secs <n>` | Stop after `n` cumulative seconds of bash commands |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | The model finished and no action was denied |
| `1` | Error or aborted |
| `2` | Config error; nothing ran |
| `3` | Turn limit reached |
| `4` | A run budget (tokens, cost, wall-clock or bash time) was exceeded |
| `5` | The model finished, but at least one action was denied by policy, a hook or the approver |

If several apply, error wins over turn limit, which wins over denied.

With `--json`, the last line is a `RunSummary` event. It is not printed when barry exits with `2` before a run starts.

```json
{"RunSummary":{"stop_reason":"Stop","exit_code":5,"turn_limit_reached":false,"denied_actions":1,"usage":{"input_tokens":2140,"output_tokens":310},"files_changed":["/work/src/lib.rs"]}}
```

`usage` is summed over the run and is `null` when the provider reports none. `files_changed` lists absolute paths changed through the write and edit tools; files changed by bash commands are not tracked. On an error, `stop_reason` is `{"Error":"<message>"}`.

Headless mode never prompts for approval: an action that needs approval is denied, and the model is told that approval is unavailable in headless mode.

#### Scoped approvals for autonomous runs

`--approval-file` lets a headless run approve a fixed list of actions. The default is deny: anything not listed is refused, an empty file approves nothing, and there is no allow-all setting. A typo or unknown key is a config error (exit 2).

```toml
[[allow]]
id = "build"              # optional; appears in the audit log
tool = "bash"
command = "cargo build"   # the whole command, word for word

[[allow]]
tool = "bash"
command = "cargo test"
allow_extra_args = true   # also allow plain extra words, e.g. `cargo test -p core`

[[allow]]
tool = "write"            # or "edit"
path_under = "/tmp/out"   # relative paths resolve against the cwd
```

Rules only apply to actions that would otherwise need approval, so deny rules, read-deny paths and the sandbox still apply. Further limits:

- A bash command matches only if it is plain words. Quotes, `$`, backticks, `;`, `&`, `|`, `<`, `>` and globs never match, so `cargo test; rm x` is not covered by a `cargo test` rule.
- Paths are canonicalised before matching; `..` and symlinks that leave the rule's directory do not match.
- A path with a protected component (see `fs.protected`) is never approved.
- A request to widen the sandbox after a blocked command is never approved.
- An approval covers one action. Unlike an interactive approval it does not grant a command prefix or a directory for the rest of the session.

Approved actions are logged with `decided_by` set to `rule:approval-file:<id>`.

### Other commands

```bash
barry --version                 # print version and exit
barry rules check "<command>"   # print the policy decision and the deciding rule id
barry log verify <file>         # verify the hash chain of a session log
```

`log verify` prints `ok (<n> entries)` and exits 0. If a line was edited, it prints `broken at line <k>` and exits 1.

### Interactive REPL

Running `barry` with no `-p` starts a minimal line REPL in the current working directory. Answers stream to stdout, tool calls print as `● bash: cargo test` followed by `✓`/`✗`, and actions that need approval prompt over the same input stream for `[o]nce / [a]lways this session / [d]eny`. Ctrl-C cancels the current turn, and twice at an empty prompt exits. Slash commands:

| Command | Meaning |
|---------|---------|
| `/exit` | Quit |
| `/compact` | Force context compaction (not implemented until M6) |
| `/grants` | List path grants |
| `/model <name>` | Switch model for the next request |
| `/auth login\|status\|logout anthropic\|codex` | Manage account sign-in without sending a model request |

## Configuration

User config is read from the file named by `$BARRY_CONFIG`; when that variable is unset, `$XDG_CONFIG_HOME/barry/config.toml` (or `~/.config/barry/config.toml`) is used. If no file exists, built-in defaults apply. `barry config show` prints the configuration in effect and the file it came from. Supported keys today:

```toml
[sandbox]
network = false     # default; true lets sandboxed commands use the network
unsandboxed = false # default; true runs bash without the OS sandbox (logged,
                    # and not recommended: rules and approvals still apply)

[fs]
# defaults shown; [] opts out of the credential paths
read_deny = ["~/.ssh", "~/.aws", "~/.config/gcloud", "~/.kube", "~/.docker", "~/.gnupg"]
protected = [".git", ".barry", ".env"]

[redaction]
tool_output = true  # default false; mask secrets in tool output sent to the model
```

Budgets limit one run (one prompt) and are off by default. The flags above override the config file:

```toml
[budgets]
max_total_tokens = 200000
max_wall_secs = 1800
max_bash_secs = 600
max_cost_usd = 2.5
price_input_per_mtok = 1.0    # USD per million input tokens
price_output_per_mtok = 3.0   # USD per million output tokens
```

When a limit is exceeded the run ends with a notice and `StopReason::BudgetExceeded` (`{"BudgetExceeded":"Tokens"|"Cost"|"WallClock"|"BashTime"}` in `--json` output). Limits are checked between steps, so a run can overshoot by one model request or one command; tool calls that were pending are answered as not run. Token counts come from the provider's usage report, or are estimated at four bytes per token when the provider reports none. `max_cost_usd` without both prices is a config error (exit 2), because it could never trigger.

The model id comes from `--model` (default `local`) and the endpoint from `BARRY_BASE_URL` (default `http://localhost:11434/v1`).

The rest of the config schema in PLAN 6.8 — `~/.config/barry/config.toml` as the default path, `default_model`/`max_turns`, model profiles, `fs.extra_writable`, `sandbox.env_passthrough`, user rules, and trusted project config — is not implemented yet.

## Security model

This model applies to Barry agent runs; `barry subscription` sessions use the selected native CLI's controls instead.

Two independent layers:

1. **Policy layer** — path checks for reads and writes, plus a bash rule table. Default deny rules cover `sudo`, `rm -rf /`, `curl ... | sh`, `git push --force`, etc. Default allow rules cover `ls`, `cargo test`, `git status`, etc.
2. **Sandbox layer** — each command is re-executed inside the sandbox. On Linux this requires `bwrap`; if `bwrap` is missing, commands fail closed and never run unsandboxed. Network access can be switched off with `sandbox.network = false`.

File writes stay inside the current directory unless you grant a path. Configured read-deny paths are refused without a prompt, so their contents never reach the model.

Every session appends to `~/.local/state/barry/sessions/` (or `$XDG_STATE_HOME/barry/sessions`) as JSONL. Each line carries the SHA-256 of the previous line and a hash of itself, so `barry log verify` can name the first edited line. Lines are `0600` in a `0700` directory, and one writer at a time is enforced with an advisory lock. Entries cover the session start (cwd, model, version, policy fingerprint), conversation messages, tool decisions (with the deciding rule id, user or default), tool results, grants, approved bash prefixes and notices. Decisions are written before the tool runs, so a crash cannot lose the audit trail.

Secrets are redacted before an entry is hashed: built-in patterns (`sk-…`, GitHub tokens, AWS keys, JWTs, private keys) and the values of environment variables whose names contain `KEY`, `TOKEN`, `SECRET` or `PASSWORD`. Redaction applies to the log always; the model sees real tool output unless `redaction.tool_output = true` is set, which masks the same secrets in tool results before they are sent to the provider. `barry --resume` verifies the chain before appending and refuses a broken log. The chain detects edits and middle deletions, but not truncation: deleting trailing entries (or the whole file) leaves a shorter chain that still verifies. Anchor the head hash elsewhere if you need to detect truncation.

## Business cases and testing

barry is built **business-case first** (BC-first). A business case is a statement of something a user or the user's security posture needs to be true, checked through observable outcomes — never through "the code I wrote works the way I wrote it."

Before any production code is written for a milestone, its business cases are turned into tests. The tests must fail first (compile error or assertion failure), then the code is written to make them pass. A test may only change if the business case changes. If a behaviour isn't covered by a business case, it isn't written.

Tests check observable outcomes only: files on disk, events received, what the model saw, approval requests, session-log contents, and process exit codes — never internal struct fields or private functions.

## Milestones

barry is under active development. Each milestone is a separate branch and PR with its business-case tests written first. M0–M5 are implemented, including the REPL; M6 is next.

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

- `barry auth login|status|logout anthropic|codex` and `/auth` in the REPL — manage Anthropic Console and Codex authentication through the official CLIs
- `barry subscription codex|claude -- [native args...]` — launches the installed native CLI with its own authentication and controls
- `barry --version` — prints `barry <semver>` and exits 0
- `barry rules check "<command>"` — prints the policy decision and the deciding rule id
- `barry config show` — prints the effective config (path defaults, network, redaction, rules, hooks) and the file it came from
- Streaming OpenAI-compatible client and the agent loop with `read`, `write`, `edit` and `bash` (sub-agents, and their tool, arrive in M8)
- Interactive REPL with streaming output, tool lines, stdin approvals, `/exit`, `/grants`, `/model` and Ctrl-C cancellation (`/compact` is a stub until M6)
- Headless `-p` mode with `--json`, wrapped tool results and the PLAN 5.2 system prompt
- Policy approvals with session grants, and the Linux/macOS OS sandbox
- Every session logged as hash-chained, redacted JSONL: `barry log verify <file>` and `barry --resume <file|prefix>`
- Test utilities (`Workspace`, `ScriptedProvider`, `ScriptedApprover`, `FakeLlm`)

Not implemented yet:

- Context compaction, AGENTS.md/skills, hooks, project trust and sub-agents
- Model profiles and the rest of the config schema: only `sandbox.network`, `fs.read_deny`, `fs.protected` and `redaction.tool_output` are read today
- Globs in `fs.read_deny`: entries are paths, matched by prefix, so a `.env*` pattern does not match anything; `.env` is covered by `fs.protected` instead

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
