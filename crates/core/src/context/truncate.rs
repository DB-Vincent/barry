use std::borrow::Cow;

const HEAD_BYTES: usize = 12_000;
const TAIL_BYTES: usize = 12_000;

/// Returns `s` unchanged (without copying) when it fits in `max_bytes`.
/// Otherwise keeps the first 12,000 and last 12,000 bytes, joined by a marker
/// that states how many bytes were cut and the original size.
pub fn truncate(s: &str, max_bytes: usize) -> Cow<'_, str> {
    if s.len() <= max_bytes {
        return Cow::Borrowed(s);
    }

    let total = s.len();
    let head_end = floor_char_boundary(s, HEAD_BYTES);
    let tail_start = ceil_char_boundary(s, total.saturating_sub(TAIL_BYTES));
    let cut = total - head_end - (total - tail_start);

    Cow::Owned(format!(
        "{}\n[... truncated {cut} of {total} bytes ...]\n{}",
        &s[..head_end],
        &s[tail_start..],
    ))
}

/// Largest index `<= i` that is a UTF-8 char boundary in `s`.
fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Smallest index `>= i` that is a UTF-8 char boundary in `s`.
fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_input_is_borrowed_not_copied() {
        let out = truncate("hello", 30_000);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "hello");
    }

    #[test]
    fn long_input_keeps_head_and_tail_and_states_the_cut() {
        let s = "a".repeat(60_000);
        let out = truncate(&s, 30_000);

        assert!(out.starts_with(&"a".repeat(12_000)));
        assert!(out.ends_with(&"a".repeat(12_000)));
        assert!(out.contains("[... truncated 36000 of 60000 bytes ...]"));
    }

    #[test]
    fn cut_never_splits_a_utf8_char() {
        // 'é' is two bytes; put it so that byte 12_000 is its second half.
        let mut s = "a".repeat(11_999);
        s.push('é');
        s.push_str(&"b".repeat(60_000));

        let out = truncate(&s, 30_000);

        // The head stops one byte early, at 11_999, to keep 'é' whole.
        assert!(out.starts_with(&"a".repeat(11_999)));
        assert!(!out.contains('\u{FFFD}'));
    }
}
