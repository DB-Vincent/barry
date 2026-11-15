//! Run budgets for autonomous runs: tokens, estimated cost, wall-clock time
//! and cumulative bash time.
//!
//! Budgets are per `run_turn` call (one prompt). Limits are checked between
//! steps: before each model request and between tool calls. A request or a
//! command that is already running is not interrupted, so a run can overshoot
//! a limit by one step. Bash commands keep their own per-command timeout.

use std::time::{Duration, Instant};

use barry_protocol::{BudgetKind, Usage};

/// Optional limits for one run. `None` means unlimited.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Budgets {
    /// Maximum input plus output tokens.
    pub max_total_tokens: Option<u64>,
    /// Maximum estimated cost in USD. Needs both prices below.
    pub max_cost_usd: Option<f64>,
    /// Maximum wall-clock seconds since the run started.
    pub max_wall_secs: Option<u64>,
    /// Maximum cumulative seconds spent in bash commands.
    pub max_bash_secs: Option<u64>,
    /// USD per million input tokens, used for the cost estimate.
    pub price_input_per_mtok: Option<f64>,
    /// USD per million output tokens, used for the cost estimate.
    pub price_output_per_mtok: Option<f64>,
}

impl Budgets {
    /// Reject settings that cannot be enforced. A cost limit without prices
    /// would silently never trigger, so it is an error instead.
    ///
    /// # Errors
    ///
    /// Returns a message naming the setting that cannot be enforced.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("max_cost_usd", self.max_cost_usd),
            ("price_input_per_mtok", self.price_input_per_mtok),
            ("price_output_per_mtok", self.price_output_per_mtok),
        ] {
            if let Some(v) = value
                && (!v.is_finite() || v < 0.0)
            {
                return Err(format!("budgets.{name} must be a non-negative number"));
            }
        }
        if self.max_cost_usd.is_some()
            && (self.price_input_per_mtok.is_none() || self.price_output_per_mtok.is_none())
        {
            return Err("budgets.max_cost_usd needs price_input_per_mtok and \
                 price_output_per_mtok to estimate cost"
                .to_string());
        }
        Ok(())
    }
}

/// Which budget ran out, with a message for the user.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Exceeded {
    pub(crate) kind: BudgetKind,
    pub(crate) message: String,
}

/// Running totals for one run, measured against [`Budgets`].
pub(crate) struct BudgetTracker {
    budgets: Budgets,
    start: Instant,
    usage: Usage,
    bash: Duration,
}

impl BudgetTracker {
    pub(crate) fn new(budgets: Budgets) -> Self {
        Self {
            budgets,
            start: Instant::now(),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
            bash: Duration::ZERO,
        }
    }

    pub(crate) fn add_usage(&mut self, usage: &Usage) {
        self.usage.input_tokens = self.usage.input_tokens.saturating_add(usage.input_tokens);
        self.usage.output_tokens = self.usage.output_tokens.saturating_add(usage.output_tokens);
    }

    pub(crate) fn add_bash(&mut self, elapsed: Duration) {
        self.bash += elapsed;
    }

    pub(crate) fn usage(&self) -> Usage {
        self.usage.clone()
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "token counts stay far below 2^52, so the f64 estimate is exact"
    )]
    fn cost_usd(&self) -> Option<f64> {
        let input = self.budgets.price_input_per_mtok?;
        let output = self.budgets.price_output_per_mtok?;
        Some(
            (self.usage.input_tokens as f64 * input + self.usage.output_tokens as f64 * output)
                / 1_000_000.0,
        )
    }

    /// The first budget that is exceeded, if any.
    pub(crate) fn exceeded(&self) -> Option<Exceeded> {
        let b = &self.budgets;
        let total = self
            .usage
            .input_tokens
            .saturating_add(self.usage.output_tokens);
        if let Some(max) = b.max_total_tokens
            && total > max
        {
            return Some(Exceeded {
                kind: BudgetKind::Tokens,
                message: format!("token budget exceeded: used {total} of {max}"),
            });
        }
        if let (Some(max), Some(cost)) = (b.max_cost_usd, self.cost_usd())
            && cost > max
        {
            return Some(Exceeded {
                kind: BudgetKind::Cost,
                message: format!("cost budget exceeded: ${cost:.4} of ${max:.4}"),
            });
        }
        if let Some(max) = b.max_wall_secs {
            let elapsed = self.start.elapsed();
            if elapsed > Duration::from_secs(max) {
                return Some(Exceeded {
                    kind: BudgetKind::WallClock,
                    message: format!(
                        "wall-clock budget exceeded: {}s of {max}s",
                        elapsed.as_secs()
                    ),
                });
            }
        }
        if let Some(max) = b.max_bash_secs
            && self.bash > Duration::from_secs(max)
        {
            return Some(Exceeded {
                kind: BudgetKind::BashTime,
                message: format!(
                    "bash-time budget exceeded: {}s of {max}s",
                    self.bash.as_secs()
                ),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, output: u64) -> Usage {
        Usage {
            input_tokens: input,
            output_tokens: output,
        }
    }

    #[test]
    fn no_limits_never_exceeds() {
        let mut t = BudgetTracker::new(Budgets::default());
        t.add_usage(&usage(u64::MAX, u64::MAX));
        t.add_bash(Duration::from_secs(10_000));
        assert!(t.exceeded().is_none());
    }

    #[test]
    fn tokens_exceed_only_above_the_limit() {
        let mut t = BudgetTracker::new(Budgets {
            max_total_tokens: Some(100),
            ..Budgets::default()
        });
        t.add_usage(&usage(60, 40));
        assert!(t.exceeded().is_none());
        t.add_usage(&usage(1, 0));
        assert_eq!(t.exceeded().unwrap().kind, BudgetKind::Tokens);
    }

    #[test]
    fn cost_uses_the_configured_prices() {
        let mut t = BudgetTracker::new(Budgets {
            max_cost_usd: Some(1.0),
            price_input_per_mtok: Some(1.0),
            price_output_per_mtok: Some(3.0),
            ..Budgets::default()
        });
        t.add_usage(&usage(500_000, 100_000)); // 0.5 + 0.3
        assert!(t.exceeded().is_none());
        t.add_usage(&usage(0, 100_000)); // +0.3 = 1.1
        assert_eq!(t.exceeded().unwrap().kind, BudgetKind::Cost);
    }

    #[test]
    fn bash_time_accumulates() {
        let mut t = BudgetTracker::new(Budgets {
            max_bash_secs: Some(5),
            ..Budgets::default()
        });
        t.add_bash(Duration::from_secs(3));
        assert!(t.exceeded().is_none());
        t.add_bash(Duration::from_secs(3));
        assert_eq!(t.exceeded().unwrap().kind, BudgetKind::BashTime);
    }

    #[test]
    fn cost_limit_without_prices_is_invalid() {
        let budgets = Budgets {
            max_cost_usd: Some(1.0),
            ..Budgets::default()
        };
        assert!(budgets.validate().is_err());
    }

    #[test]
    fn negative_values_are_invalid() {
        let budgets = Budgets {
            price_input_per_mtok: Some(-1.0),
            ..Budgets::default()
        };
        assert!(budgets.validate().is_err());
    }
}
