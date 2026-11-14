/// BC-4.6 With `network = true`, bash can reach a local HTTP server. With
/// `network = false` it cannot.
use barry_core::config::Config;
use barry_core::Agent;
use barry_llm::LlmRequest;
use barry_policy::{Policy, PolicyConfig};
use barry_protocol::{ApprovalChoice, Message, StopReason};
use barry_testkit::scripted::Reply;
use barry_testkit::{ScriptedApprover, ScriptedProvider, Workspace};
use futures::channel::mpsc;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use tokio_util::sync::CancellationToken;

fn config(network: bool) -> Config {
    Config {
        default_model: "test".to_string(),
        max_turns: 10,
        sandbox_network: network,
        fs_read_deny: vec![],
        fs_protected: vec![],
    }
}

fn policy(ws: &Workspace, network: bool) -> Policy {
    Policy::new(PolicyConfig {
        cwd: ws.cwd().to_path_buf(),
        home: ws.home().to_path_buf(),
        extra_writable: vec![],
        read_deny: vec![],
        protected: vec![],
        rules: vec![],
        network,
    })
    .expect("policy constructs")
}

/// Start a one-line HTTP server on loopback and return its port.
fn start_http_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = "ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

/// The last tool result the model received: `(ok, content)`.
fn last_tool_result(requests: &[LlmRequest]) -> (bool, String) {
    let req = requests.last().expect("at least one request");
    let msg = req
        .messages
        .iter()
        .rev()
        .find(|m| matches!(m, Message::Tool { .. }))
        .expect("a tool message");
    match msg {
        Message::Tool { content, ok, .. } => (*ok, content.clone()),
        _ => unreachable!(),
    }
}

async fn run(ws: &Workspace, network: bool, port: u16) -> (bool, String) {
    let approver = Arc::new(ScriptedApprover::new(vec![ApprovalChoice::Once]));
    let provider = Arc::new(ScriptedProvider::new(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({
                "command": format!("curl -s -m 5 http://127.0.0.1:{port}/")
            }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ]));
    let mut agent = Agent::new(
        config(network),
        provider.clone(),
        approver,
        Some(policy(ws, network)),
    )
    .expect("agent constructs");
    let (tx, _rx) = mpsc::channel(32);
    let stop = agent
        .run_turn("fetch the local server", tx, CancellationToken::new())
        .await
        .expect("turn completes");
    assert_eq!(stop, StopReason::Stop);
    last_tool_result(&provider.seen_requests())
}

#[tokio::test]
async fn bc_4_6_network_true_reaches_local_server() {
    let ws = Workspace::new();
    let port = start_http_server();

    let (ok, content) = run(&ws, true, port).await;
    assert!(ok, "network = true should reach the server: {content}");
    assert!(
        content.contains("ok"),
        "the server response should reach the model: {content}"
    );
}

#[tokio::test]
async fn bc_4_6_network_false_cannot_reach_local_server() {
    let ws = Workspace::new();
    let port = start_http_server();

    let (ok, content) = run(&ws, false, port).await;
    assert!(!ok, "network = false must block the server: {content}");
}
