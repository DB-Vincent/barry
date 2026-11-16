# Patched `tree-sitter-bash` 0.25.1

This directory is a vendored copy of the published crate
[`tree-sitter-bash` 0.25.1](https://crates.io/crates/tree-sitter-bash) (MIT,
LICENSE alongside), trimmed to the files its build needs and patched with one
fix. It is wired in from the workspace root:

```toml
[patch.crates-io]
tree-sitter-bash = { path = "vendor/tree-sitter-bash" }
```

## The patch

`src/scanner.c`, in the `brace_start` branch of `scan()` (two sites):
`isdigit(lexer->lookahead)` → `iswdigit(lexer->lookahead)`.

`lexer->lookahead` is a Unicode code point (`int32_t`, up to `0x10FFFF`).
`isdigit` from `<ctype.h>` is only defined for values representable as
`unsigned char`, or `EOF`; glibc indexes a 384-entry table, so a large code
point reads megabytes past it. That is undefined behaviour, and it faults on
some machines: parsing `{<U+10FFFF>}` — or any command with `{` immediately
followed by a non-ASCII code point — segfaulted the whole process. Every other
character classification in this file already uses the wide variant
(`iswspace`, `iswdigit`, `iswalnum`), which accepts any `wint_t`.

The crash surfaced as an intermittent SIGSEGV in the `barry-policy` unit tests
(`bash_parse` parses every command string), and it is reachable at runtime:
the command string comes from the model, so a command like `ls {😀}` could
kill the agent.

## Removing it

Delete this directory and the `[patch.crates-io]` entry, run `cargo update -p
tree-sitter-bash`, and confirm the two `isdigit` calls are gone from the
released `src/scanner.c` (checked: 0.25.1 is still the latest release and
upstream `master` still has them). Report it upstream if that is still true.
