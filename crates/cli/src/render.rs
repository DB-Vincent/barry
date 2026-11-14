//! Shared terminal rendering for the REPL and headless output.

use std::io::{IsTerminal, Write};

/// Renders streamed reasoning (PLAN 6.9) as a single `thinking:` line on
/// stderr.
///
/// Providers stream reasoning one token at a time, so prefixing every delta
/// would print `thinking:` once per token. The prefix is written once, the
/// deltas follow inline, and the line is closed before any other output. On a
/// terminal the text is dimmed so the answer stays the focus.
pub(crate) struct Thinking {
    /// Whether a reasoning line is currently open.
    active: bool,
    /// Whether stderr is a terminal and can take ANSI dimming.
    dim: bool,
}

impl Thinking {
    pub(crate) fn new() -> Self {
        Self {
            active: false,
            dim: std::io::stderr().is_terminal(),
        }
    }

    /// Stream one reasoning delta.
    pub(crate) fn delta(&mut self, text: &str) {
        let mut err = std::io::stderr().lock();
        if !self.active {
            self.active = true;
            if self.dim {
                let _ = write!(err, "\x1b[2m");
            }
            let _ = write!(err, "thinking: ");
        }
        let _ = write!(err, "{text}");
        let _ = err.flush();
    }

    /// End the reasoning line before other output. Idempotent, and the next
    /// delta starts a fresh line (a new request after tool results).
    pub(crate) fn finish(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut err = std::io::stderr().lock();
        if self.dim {
            let _ = write!(err, "\x1b[0m");
        }
        let _ = writeln!(err);
        let _ = err.flush();
    }
}

impl Default for Thinking {
    fn default() -> Self {
        Self::new()
    }
}
