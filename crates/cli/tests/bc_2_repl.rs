/// BC-2.12 `barry` with no `-p` starts a line REPL in cwd: a prompt streams
/// the answer to stdout, and `/exit` exits 0.
///
/// BC-2.13 A write outside cwd prompts over stdin: `o` runs it once, `a` runs
/// it and grants the directory for the session, and `d` denies it without
/// creating the file.
///
/// BC-2.14 `/grants` lists the directories granted this session. `/model
/// <name>` sends the next request with that model id.
///
/// BC-2.15 Ctrl-C during a turn cancels it cleanly, and the REPL accepts the
/// next input.
///
/// These drive the real binary with real HTTP (`testkit::FakeLlm`) and an
/// in-memory stdin pipe, so they cover input handling, approvals, rendering
/// and exit codes at once.
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use barry_testkit::{FakeLlm, Reply, Workspace};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

fn barry(llm: &FakeLlm, cwd: &Path, state: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    // Never let the developer's real config leak into an acceptance test.
    cmd.env_remove("BARRY_CONFIG");
    // Keep session logs out of the developer's real state directory.
    cmd.env("XDG_STATE_HOME", state);
    cmd.env("BARRY_BASE_URL", llm.uri());
    cmd.current_dir(cwd);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run the REPL with `input` on stdin and wait for it to exit.
async fn run_repl(llm: &FakeLlm, cwd: &Path, input: &str) -> Output {
    let state = tempfile::tempdir().expect("state dir");
    let mut child = barry(llm, cwd, state.path()).spawn().expect("barry starts");

    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(input.as_bytes())
        .await
        .expect("write stdin");
    drop(stdin);

    tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("barry exits")
        .expect("barry output")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn bc_2_12_repl_streams_the_answer_and_exits_on_exit() {
    let llm = FakeLlm::start(vec![Reply::Text {
        content: "hello from repl".to_string(),
    }])
    .await;
    let ws = Workspace::new();

    let out = run_repl(&llm, ws.cwd(), "hi\n/exit\n").await;

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("hello from repl"),
        "the streamed answer goes to stdout: {:?}",
        stdout(&out)
    );
}

/// BC-2.13 `o` approves once, and the file is written.
#[tokio::test(flavor = "multi_thread")]
async fn bc_2_13_approval_once_writes_the_file() {
    let ws = Workspace::new();
    let target = ws.outside().join("approved.txt");
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({
                "path": target.display().to_string(),
                "content": "approved",
            }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ])
    .await;

    let out = run_repl(&llm, ws.cwd(), "write it\no\n/exit\n").await;

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        stderr(&out)
    );
    assert!(
        target.exists(),
        "approving once writes the file; stdout: {:?}",
        stdout(&out)
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("approved file"),
        "approved"
    );
    assert!(
        stdout(&out).contains("Allow write"),
        "the approval prompt is shown over stdin: {:?}",
        stdout(&out)
    );
}

/// BC-2.13 `d` denies, and nothing is created.
#[tokio::test(flavor = "multi_thread")]
async fn bc_2_13_denial_leaves_the_file_absent() {
    let ws = Workspace::new();
    let target = ws.outside().join("denied.txt");
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({
                "path": target.display().to_string(),
                "content": "denied",
            }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ])
    .await;

    let out = run_repl(&llm, ws.cwd(), "write it\nd\n/exit\n").await;

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        stderr(&out)
    );
    assert!(
        !target.exists(),
        "a denied write creates nothing; stdout: {:?}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("denied by user"),
        "the user sees the denial: {:?}",
        stdout(&out)
    );
}

/// BC-2.14 `a` grants the directory for the session, and `/grants` lists it.
#[tokio::test(flavor = "multi_thread")]
async fn bc_2_14_grants_lists_the_granted_directory() {
    let ws = Workspace::new();
    let target = ws.outside().join("granted.txt");
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "write".to_string(),
            arguments: json!({
                "path": target.display().to_string(),
                "content": "granted",
            }),
        },
        Reply::Text {
            content: "done".to_string(),
        },
    ])
    .await;

    let out = run_repl(&llm, ws.cwd(), "write it\na\n/grants\n/exit\n").await;

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        stderr(&out)
    );
    assert!(target.exists(), "always-this-session writes the file");

    // The grant is stored canonicalised (macOS /var → /private/var).
    let outside = std::fs::canonicalize(ws.outside()).expect("canonical outside");
    assert!(
        stdout(&out).contains(&outside.display().to_string()),
        "`/grants` lists {}; stdout: {:?}",
        outside.display(),
        stdout(&out)
    );
}

/// BC-2.14 `/model` changes the model id on the next request.
#[tokio::test(flavor = "multi_thread")]
async fn bc_2_14_model_changes_the_next_request() {
    let ws = Workspace::new();
    let llm = FakeLlm::start(vec![
        Reply::Text {
            content: "one".to_string(),
        },
        Reply::Text {
            content: "two".to_string(),
        },
    ])
    .await;

    let out = run_repl(&llm, ws.cwd(), "hi\n/model other-model\nhi\n/exit\n").await;

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, stderr: {}",
        stderr(&out)
    );
    let requests = llm.requests();
    assert_eq!(requests.len(), 2, "two turns were sent");
    assert_eq!(requests[0]["model"], "local", "the default model is used");
    assert_eq!(
        requests[1]["model"], "other-model",
        "`/model` applies to the next request"
    );
    assert!(
        stdout(&out).contains("model: other-model"),
        "the switch is confirmed: {:?}",
        stdout(&out)
    );
}

/// BC-2.15 Ctrl-C while the turn waits for approval cancels it; the REPL
/// then accepts the next input.
#[tokio::test(flavor = "multi_thread")]
async fn bc_2_15_ctrl_c_cancels_the_turn_and_the_repl_continues() {
    let ws = Workspace::new();
    // `sleep 30` needs approval, so the process is parked at the prompt when
    // the signal arrives and never runs.
    let llm = FakeLlm::start(vec![
        Reply::Tool {
            name: "bash".to_string(),
            arguments: json!({ "command": "sleep 30" }),
        },
        Reply::Text {
            content: "recovered".to_string(),
        },
    ])
    .await;
    let state = tempfile::tempdir().expect("state dir");

    let mut child = barry(&llm, ws.cwd(), state.path())
        .spawn()
        .expect("barry starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(b"run\n").await.expect("write prompt");

    let mut lines = tokio::io::BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut seen = String::new();
    let got_prompt = loop {
        match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                seen.push_str(&line);
                seen.push('\n');
                if line.contains("Allow bash") {
                    break true;
                }
            }
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break false,
        }
    };
    assert!(got_prompt, "expected an approval prompt, saw: {seen:?}");

    let pid = child.id().expect("child pid");
    let signalled = std::process::Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signalled.success(), "SIGINT was delivered");

    // The cancelled turn must not swallow the next prompt.
    stdin
        .write_all(b"hi\n/exit\n")
        .await
        .expect("write next input");
    drop(stdin);

    let rest = tokio::time::timeout(Duration::from_secs(20), async {
        let mut rest = String::new();
        while let Ok(Some(line)) = lines.next_line().await {
            rest.push_str(&line);
            rest.push('\n');
        }
        rest
    })
    .await
    .expect("the REPL continues after Ctrl-C");

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("barry exits")
        .expect("wait for barry");

    assert_eq!(
        status.code(),
        Some(0),
        "expected exit 0\nprompt: {seen:?}\nrest: {rest:?}"
    );
    assert!(
        rest.contains("recovered"),
        "the REPL accepted the next input after Ctrl-C; rest: {rest:?}"
    );
}
