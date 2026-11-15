/// BC-1.8 Cancelling mid-stream yields Aborted within 200 ms, with the
/// partial text kept.
use barry_llm::{Compat, LlmEvent, LlmRequest, OpenAiProvider, Provider};
use barry_protocol::{Message, StopReason};
use futures::stream::StreamExt;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Minimal HTTP server: reads the request headers, sends chunk 1 immediately,
/// waits `delay_ms`, then sends `[DONE]`. Returns the server URL.
async fn slow_sse_server(delay_ms: u64) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            if socket.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  \r\n\
                  data: {\"choices\":[{\"delta\":{\"content\":\"partial te\"}}]}\n\n",
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        let _ = socket.write_all(b"data: [DONE]\n\n").await;
    });
    format!("http://{}", addr)
}

#[tokio::test]
async fn bc_1_8_cancel_mid_stream_is_aborted_with_partial_text() {
    let base_url = slow_sse_server(5000).await;

    let provider = OpenAiProvider::new(
        "test-model".to_string(),
        base_url.parse::<reqwest::Url>().unwrap(),
        None,
        1024,
        Compat::default(),
    );

    let req = LlmRequest {
        messages: vec![Message::User {
            content: "cancel me".to_string(),
        }],
        tools: vec![],
    };

    let cancel = CancellationToken::new();
    let mut stream = provider.stream(req, cancel.clone());

    // Phase 1: read until the first TextDelta, then cancel.
    let mut seen_text = false;
    while let Some(event) = stream.next().await {
        match event {
            Ok(LlmEvent::TextDelta(_)) => {
                seen_text = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        seen_text,
        "expected at least one TextDelta before cancelling"
    );

    let started = Instant::now();
    cancel.cancel();

    // Phase 2: keep polling the same stream until Done arrives.
    let mut aborted = None;
    while let Some(event) = stream.next().await {
        if let Ok(LlmEvent::Done { stop, .. }) = event {
            aborted = Some((stop, started.elapsed()));
            break;
        }
    }

    let (stop, elapsed) = aborted.expect("expected an Aborted Done event");
    assert_eq!(stop, StopReason::Aborted);
    assert!(
        elapsed.as_millis() < 200,
        "abort took {:?}, expected < 200 ms",
        elapsed
    );
}
