//! Fake LLM server backed by wiremock for wire-level tests.
//! Renders scripted replies as real OpenAI-compatible SSE.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use wiremock::matchers;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A reply that FakeLlm renders as OpenAI SSE.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Return streamed text content.
    Text { content: String },
    /// Return a tool call.
    Tool { name: String, arguments: Value },
    /// Return an HTTP status code (e.g. 429 for retry testing).
    HttpStatus { status: u16 },
    /// Return raw SSE text as-is.
    RawSse { sse: String },
}

/// Fake LLM server backed by wiremock.
pub struct FakeLlm {
    server: MockServer,
    _replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    auth_headers: Arc<Mutex<Vec<Option<String>>>>,
}

impl FakeLlm {
    pub async fn start(script: Vec<Reply>) -> Self {
        let server = MockServer::start().await;
        let replies = Arc::new(Mutex::new(VecDeque::from(script)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let auth_headers = Arc::new(Mutex::new(Vec::new()));

        let replies_clone = replies.clone();
        let requests_clone = requests.clone();
        let auth_headers_clone = auth_headers.clone();

        Mock::given(matchers::method("POST"))
            .respond_with(move |req: &wiremock::Request| {
                // Record request body
                let mut requests = requests_clone.lock().unwrap();
                let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
                requests.push(body);

                // Record Authorization header
                let mut auths = auth_headers_clone.lock().unwrap();
                let auth = req
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                auths.push(auth);
                drop(requests);
                drop(auths);

                let mut replies = replies_clone.lock().unwrap();
                let reply = replies.pop_front().expect("FakeLlm: ran out of replies");

                match reply {
                    Reply::HttpStatus { status } => ResponseTemplate::new(status),
                    Reply::RawSse { sse } => ResponseTemplate::new(200)
                        .insert_header("content-type", "text/event-stream")
                        .set_body_raw(sse.into_bytes(), "text/event-stream"),
                    _ => {
                        let sse = render_sse(&reply);
                        ResponseTemplate::new(200)
                            .insert_header("content-type", "text/event-stream")
                            .set_body_raw(sse.into_bytes(), "text/event-stream")
                    }
                }
            })
            .mount(&server)
            .await;

        Self {
            server,
            _replies: replies,
            requests,
            auth_headers,
        }
    }

    /// The base URL of the fake server (e.g. `http://127.0.0.1:12345`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Returns the parsed JSON bodies of all requests received so far.
    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }

    /// Returns the Authorization header of the last request, if any.
    pub fn last_auth_header(&self) -> Option<String> {
        self.auth_headers.lock().unwrap().last().cloned().flatten()
    }
}

fn render_sse(reply: &Reply) -> String {
    let mut sse = String::new();

    match reply {
        Reply::Text { content } => {
            // Role chunk
            sse.push_str("data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n");
            // Split content into at least 2 chunks
            let mid = content.len() / 2;
            let (first, second) = content.split_at(mid);
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
                escape_json(first)
            ));
            if !second.is_empty() {
                sse.push_str(&format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
                    escape_json(second)
                ));
            }
            // Finish reason
            sse.push_str("data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n");
            // Usage
            sse.push_str(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
            );
        }
        Reply::Tool { name, arguments } => {
            let args_str = serde_json::to_string(arguments).unwrap();
            // Role chunk with tool_calls placeholder
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call_1\",\"function\":{{\"name\":\"{}\",\"arguments\":\"\"}}}}]}}}}]}}\n\n",
                escape_json(name)
            ));
            // Arguments chunk
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{}\"}}}}]}}}}]}}\n\n",
                escape_json(&args_str)
            ));
            // Finish reason
            sse.push_str("data: {\"choices\":[{\"finish_reason\":\"tool_calls\"}]}\n\n");
            // Usage
            sse.push_str(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
            );
        }
        _ => {}
    }

    sse.push_str("data: [DONE]\n\n");
    sse
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
