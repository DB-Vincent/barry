//! Process exit codes of a headless run.
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | The model finished and nothing was denied |
//! | 1 | Error, aborted, or an unexpected stop reason |
//! | 2 | Config error, nothing ran |
//! | 3 | Turn limit reached |
//! | 4 | A run budget was exceeded |
//! | 5 | The model finished, but at least one action was denied |
//!
//! When several apply, precedence is error, then turn limit, then denied.
//! A denied action is not an error: the model saw the refusal and
//! carried on, but the caller should know the task may be incomplete.

use barry_protocol::StopReason;

pub(crate) const SUCCESS: u8 = 0;
pub(crate) const FAILURE: u8 = 1;
pub(crate) const CONFIG: u8 = 2;
pub(crate) const TURN_LIMIT: u8 = 3;
pub(crate) const BUDGET: u8 = 4;
pub(crate) const DENIED: u8 = 5;

/// The exit code for a finished headless run.
pub(crate) fn for_run(stop: &StopReason, turn_limited: bool, denied_actions: u64) -> u8 {
    match stop {
        StopReason::Stop if turn_limited => TURN_LIMIT,
        StopReason::Stop if denied_actions > 0 => DENIED,
        StopReason::Stop => SUCCESS,
        StopReason::BudgetExceeded(_) => BUDGET,
        // StopReason is non-exhaustive: an unknown reason is a failure. A turn
        // stopped for lack of context did not answer the request either.
        _ => FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_stop_is_success() {
        assert_eq!(for_run(&StopReason::Stop, false, 0), SUCCESS);
    }

    #[test]
    fn denials_change_a_stop_but_not_an_error() {
        assert_eq!(for_run(&StopReason::Stop, false, 2), DENIED);
        assert_eq!(for_run(&StopReason::Error("x".into()), false, 2), FAILURE);
        assert_eq!(for_run(&StopReason::Aborted, false, 2), FAILURE);
    }

    #[test]
    fn an_exceeded_budget_is_its_own_code() {
        let stop = StopReason::BudgetExceeded(barry_protocol::BudgetKind::Tokens);
        assert_eq!(for_run(&stop, false, 2), BUDGET);
    }

    #[test]
    fn the_turn_limit_wins_over_denials() {
        assert_eq!(for_run(&StopReason::Stop, true, 2), TURN_LIMIT);
    }

    #[test]
    fn codes_are_distinct() {
        let codes = [SUCCESS, FAILURE, CONFIG, TURN_LIMIT, BUDGET, DENIED];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
