//! Retry policy for the initial HTTP request.
//!
//! Retries only happen before the first body byte: a status code or a transport
//! error. Once streaming starts, a failure is reported to the caller.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

use crate::LlmError;

const MAX_RETRIES: u32 = 3;
const BASE_DELAY: Duration = Duration::from_millis(500);
const MAX_JITTER_MS: u64 = 250;
/// Upper bound on a delay the server asks for. A server replying with
/// `Retry-After: 3600` must not stall the turn for an hour (#24).
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Send a request, retrying 429/5xx and connect failures with exponential
/// backoff. A server-provided `Retry-After` wins over the computed backoff, up
/// to [`MAX_RETRY_AFTER`].
pub(crate) async fn send_with_retry(
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, LlmError> {
    let request = request.build()?;

    for attempt in 0..=MAX_RETRIES {
        let last_attempt = attempt == MAX_RETRIES;
        // `Request` has no `Clone`; `try_clone` fails only for non-replayable bodies.
        let Some(cloned) = request.try_clone() else {
            return Ok(client.execute(request).await?);
        };
        match client.execute(cloned).await {
            Ok(response) if is_retryable(response.status()) && !last_attempt => {
                let delay = retry_delay(&response, attempt);
                tokio::time::sleep(delay).await;
            }
            Ok(response) => return Ok(response),
            // Only a failed connection is known to have sent nothing. Any other
            // transport error may have reached the server, and replaying a POST
            // then risks running the request twice (#24).
            Err(e) if last_attempt || !e.is_connect() => return Err(e.into()),
            Err(_) => tokio::time::sleep(backoff(attempt)).await,
        }
    }

    unreachable!("loop returns on the last attempt")
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

/// The delay before the next attempt: `Retry-After` when the server sent a
/// usable one, clamped to [`MAX_RETRY_AFTER`], else the exponential backoff.
fn retry_delay(response: &reqwest::Response, attempt: u32) -> Duration {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after)
        .map_or_else(|| backoff(attempt), |delay| delay.min(MAX_RETRY_AFTER))
}

/// `Retry-After` is either a number of seconds or an HTTP-date (RFC 7231).
/// A date in the past means "retry now".
fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = OffsetDateTime::parse(value, &Rfc2822).ok()?;
    let remaining = at - OffsetDateTime::now_utc();
    if remaining.is_negative() {
        return Some(Duration::ZERO);
    }
    remaining.try_into().ok()
}

fn backoff(attempt: u32) -> Duration {
    BASE_DELAY * 2u32.pow(attempt) + Duration::from_millis(jitter_ms())
}

/// Cheap jitter without an RNG dependency: low bits of the wall clock.
fn jitter_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()) % MAX_JITTER_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_in_seconds_is_used() {
        assert_eq!(parse_retry_after("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after(" 2 "), Some(Duration::from_secs(2)));
    }

    #[test]
    fn a_huge_retry_after_is_capped() {
        let delay = parse_retry_after("3600")
            .map(|delay| delay.min(MAX_RETRY_AFTER))
            .expect("parsed");
        assert_eq!(delay, MAX_RETRY_AFTER, "an hour must not stall the turn");
    }

    #[test]
    fn retry_after_accepts_an_http_date() {
        // The HTTP-date form: an instant in the past means retry immediately.
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(Duration::ZERO)
        );

        let soon = OffsetDateTime::now_utc() + time::Duration::seconds(30);
        let stamp = soon.format(&Rfc2822).expect("formats");
        let delay = parse_retry_after(&stamp).expect("a parsed date");
        assert!(
            delay > Duration::from_secs(20) && delay <= Duration::from_secs(30),
            "expected roughly the remaining 30s, got {delay:?}"
        );
    }

    #[test]
    fn an_unparsable_retry_after_falls_back_to_backoff() {
        assert_eq!(parse_retry_after("soon"), None);
        assert_eq!(parse_retry_after(""), None);
    }
}
