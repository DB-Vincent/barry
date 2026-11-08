//! Retry policy for the initial HTTP request.
//!
//! Retries only happen before the first body byte: a status code or a
//! transport error. Once streaming starts, a failure is reported to the caller.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::LlmError;

const MAX_RETRIES: u32 = 3;
const BASE_DELAY: Duration = Duration::from_millis(500);
const MAX_JITTER_MS: u64 = 250;

/// Send a request, retrying 429/5xx and transport errors with exponential backoff.
/// `Retry-After` (in seconds) wins over the computed backoff.
pub(crate) async fn send_with_retry(
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, LlmError> {
    let request = request.build().map_err(|e| LlmError::Transport {
        message: e.to_string(),
    })?;

    for attempt in 0..=MAX_RETRIES {
        let last_attempt = attempt == MAX_RETRIES;
        // `Request` has no `Clone`; `try_clone` fails only for non-replayable bodies.
        let Some(cloned) = request.try_clone() else {
            return client
                .execute(request)
                .await
                .map_err(|e| LlmError::Transport {
                    message: e.to_string(),
                });
        };
        match client.execute(cloned).await {
            Ok(response) if is_retryable(response.status()) && !last_attempt => {
                let delay = retry_after(&response).unwrap_or_else(|| backoff(attempt));
                tokio::time::sleep(delay).await;
            }
            Ok(response) => return Ok(response),
            Err(e) if last_attempt => {
                return Err(LlmError::Transport {
                    message: e.to_string(),
                })
            }
            Err(_) => tokio::time::sleep(backoff(attempt)).await,
        }
    }

    unreachable!("loop returns on the last attempt")
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn backoff(attempt: u32) -> Duration {
    BASE_DELAY * 2u32.pow(attempt) + Duration::from_millis(jitter_ms())
}

/// Cheap jitter without an RNG dependency: low bits of the wall clock.
fn jitter_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % MAX_JITTER_MS)
        .unwrap_or(0)
}
