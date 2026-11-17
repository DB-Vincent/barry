# Threat model

Barry runs a language model that proposes tool calls. The model is treated as
untrusted: a prompt injection in a repository, a web page pasted into the
conversation, or a malicious dependency in a fetched file can all turn into
tool calls.

## Assets

- The user's home directory and credentials (`~/.ssh`, `~/.aws`, cloud and
  VCS tokens, `~/.config/gh`, `~/.git-credentials`).
- Repository integrity: `.git`, hooks, attributes, submodule configuration.
- The user's machine outside the project: arbitrary writes, process execution,
  network access.
- The conversation itself: secrets accidentally streamed to the provider.
- The Anthropic OAuth access token and its credential file
  (`~/.config/anthropic/credentials/<profile>.json`), when the Anthropic
  provider is used.

## Attacker

Two shapes of attacker, both driving the same interface:

1. **A prompt-injected model.** It emits whatever tool calls the injected text
   asks for: read `~/.ssh/id_rsa`, write `.git/hooks/pre-commit`, run
   `curl … | sh`.
2. **A malicious repository.** It ships `.envrc`, `AGENTS.md`, `.barry/skills`,
   hooks, or build scripts that try to steer the model or the tools.

## Layers

Two independent layers must both fail before a call is dangerous.

### Policy (software, `barry-policy`)

- `read` is denied under `fs.read_deny`; `write` and `edit` ask for approval
  outside the writable roots, and always ask when a path component matches
  `fs.protected` (`.git`, `.envrc`, …).
- Bash is matched against a parsed command, not a substring: allow-listed
  prefixes, deny rules, session grants, and redirect targets that need the same
  approval a write does.
- Bash approvals are scoped: "once" means once, and a prefix grant covers only
  the argv prefix the user saw.

### Sandbox (OS, `barry-sandbox`)

- Linux: `bwrap` with `/` read-only, writable roots and grants bind-mounted,
  protected paths re-mounted read-only *after* the writable roots, read-deny
  paths masked last, user and network namespaces, seccomp, `--die-with-parent`.
- macOS: `sandbox-exec` with a Seatbelt profile that grants writes only under
  the writable roots and grants, and denies reads under the read-deny list.
- The sandbox environment is `env -i` plus a small allowlist; `*KEY*`,
  `*TOKEN*`, `*SECRET*` and `*PASSWORD*` variables never enter it.

Protected paths are collected under every writable root, including nested
repositories (submodules, vendored crates), because a top-level `.git` alone
does not describe where git metadata lives. Seatbelt rules are path-based and
apply to a path that appears after the session starts; `bwrap` can only mask a
path that exists or whose parent is writable inside the sandbox, so a missing
read-deny entry under a read-only root is skipped until the next command, when
it exists.

## Accepted residual risks

These are known and deliberate; mitigations exist but are not complete.

- **Network access is on by default.** A command may exfiltrate any file it can
  read that is not read-denied. Setting `sandbox.network = false` removes the
  path; an egress allowlist is future work.
- **The model can read anything not read-denied.** Read-deny is a blocklist.
  Secrets outside the list (a stray token in a project file) are readable.
- **Build scripts stay editable.** `Makefile`, `package.json` scripts, and
  similar files are ordinary source. A model that edits them can cause code to
  run later, outside the sandbox, when the user builds.
- **Protection is computed when the policy is created.** A repository cloned
  into a writable root mid-session is protected on the next start, not
  immediately.
- **`sandbox-exec` / SBPL is deprecated** by Apple and may stop working on a
  future macOS release. The Linux `bwrap` path has no such dependency.
- **Hooks run outside the sandbox.** A hook the user installs is trusted code
  with the user's environment minus secret variables.
- **The Anthropic provider holds a bearer token in Barry's memory.** Barry runs
  `ant auth print-credentials --access-token` for every request and keeps the
  token only for that request. It is not exported to the environment, so
  sandboxed commands and hooks cannot inherit it, and it never appears in logs
  or errors (the `sk-` redaction pattern covers it as a backstop). `ant` runs
  outside the sandbox as the user. The credential file lives under
  `~/.config/anthropic`, which is read-denied by default; setting
  `fs.read_deny = []` or replacing the list without that entry exposes it to
  the model. The model does not reach the token through Barry, but an
  unsandboxed hook or a user-approved command can read it. Requests spend the
  organization's API credits.
- **The Codex provider hands a turn to another agent.** `/provider codex` runs
  `codex exec --sandbox read-only` with the conversation as the prompt. Codex
  applies its own sandbox and approvals; Barry's policy, sandbox and audit log
  do not see its tool calls, and the audit log records only the prompt and the
  final answer. Barry removes `OPENAI_API_KEY` and `CODEX_ACCESS_TOKEN` from
  the child's environment and never reads Codex's credential store. Codex
  keeps session files under `~/.codex`.
- **`OPENAI_API_KEY` is read from the environment** and sent only over https or
  to a loopback server. A key in a repository `.env` is not read.
