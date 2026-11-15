#![allow(clippy::unwrap_used, clippy::expect_used)]

/// A headless run with `--approval-file` approves only what the file lists.
/// Everything else stays denied, and the audit log names the rule.
use barry_testkit::{FakeLlm, Reply};

struct Run {
    out: std::process::Output,
    dir: tempfile::TempDir,
}

impl Run {
    fn exists(&self, name: &str) -> bool {
        self.dir.path().join(name).exists()
    }

    fn session_log(&self) -> String {
        let sessions = self.dir.path().join("state/barry/sessions");
        std::fs::read_dir(sessions)
            .expect("session dir")
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect()
    }
}

fn bash(command: &str) -> Reply {
    Reply::Tool {
        name: "bash".to_string(),
        arguments: serde_json::json!({ "command": command }),
    }
}

fn write(path: &str) -> Reply {
    Reply::Tool {
        name: "write".to_string(),
        arguments: serde_json::json!({ "path": path, "content": "x" }),
    }
}

async fn run(approvals: Option<&str>, script: Vec<Reply>) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut replies = script;
    replies.push(Reply::Text {
        content: "done".to_string(),
    });
    let llm = FakeLlm::start(replies).await;

    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"));
    cmd.env_remove("BARRY_CONFIG")
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("BARRY_BASE_URL", llm.uri())
        .current_dir(dir.path())
        .args(["-p", "go"]);
    if let Some(text) = approvals {
        let file = dir.path().join("approvals.toml");
        std::fs::write(&file, text).unwrap();
        cmd.arg("--approval-file").arg(&file);
    }
    let out = cmd.output().await.expect("barry runs");
    Run { out, dir }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listed_command_runs_and_is_logged_as_a_rule_decision() {
    let r = run(
        Some("[[allow]]\nid = 'mk'\ntool = 'bash'\ncommand = 'touch listed.txt'\n"),
        vec![bash("touch listed.txt")],
    )
    .await;

    assert_eq!(r.out.status.code(), Some(0), "{:?}", r.out);
    assert!(r.exists("listed.txt"));
    assert!(
        r.session_log().contains("rule:approval-file:mk"),
        "{}",
        r.session_log()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_command_is_denied() {
    let r = run(
        Some("[[allow]]\ntool = 'bash'\ncommand = 'touch listed.txt'\n"),
        vec![bash("touch other.txt")],
    )
    .await;

    assert!(!r.exists("other.txt"));
    assert!(!r.exists("listed.txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_approval_file_nothing_is_approved() {
    let r = run(None, vec![bash("touch listed.txt")]).await;

    assert!(!r.exists("listed.txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_does_not_become_a_prefix_grant() {
    // `touch a.txt` is listed. If approving it granted the prefix `touch`,
    // the second command would run.
    let r = run(
        Some("[[allow]]\ntool = 'bash'\ncommand = 'touch a.txt'\n"),
        vec![bash("touch a.txt"), bash("touch b.txt")],
    )
    .await;

    assert!(r.exists("a.txt"));
    assert!(!r.exists("b.txt"), "approval must cover one command only");
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_syntax_cannot_ride_on_a_listed_command() {
    let r = run(
        Some("[[allow]]\ntool = 'bash'\ncommand = 'touch a.txt'\n"),
        vec![bash("touch a.txt; touch b.txt")],
    )
    .await;

    assert!(!r.exists("a.txt"));
    assert!(!r.exists("b.txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_outside_the_cwd_need_a_matching_rule() {
    let outside = tempfile::tempdir().expect("outside dir");
    let listed = outside.path().join("ok");
    std::fs::create_dir(&listed).unwrap();
    let allowed = listed.join("a.txt");
    let refused = outside.path().join("b.txt");

    let rules = format!(
        "[[allow]]\ntool = 'write'\npath_under = '{}'\n",
        listed.display()
    );
    let r = run(
        Some(&rules),
        vec![
            write(allowed.to_str().unwrap()),
            write(refused.to_str().unwrap()),
        ],
    )
    .await;

    // One write was refused, so the run exits 5 (#37) instead of 0.
    assert_eq!(r.out.status.code(), Some(5), "{:?}", r.out);
    assert!(allowed.exists());
    assert!(!refused.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_approval_file_exits_2() {
    let r = run(Some("[[allow]]\ntool = 'bash'\n"), vec![]).await;

    assert_eq!(r.out.status.code(), Some(2), "{:?}", r.out);
    assert!(String::from_utf8_lossy(&r.out.stderr).contains("approval file"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_approval_file_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .env_remove("BARRY_CONFIG")
        .args(["-p", "go", "--approval-file"])
        .arg(dir.path().join("nope.toml"))
        .output()
        .await
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_flag_needs_a_prompt() {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_barry"))
        .env_remove("BARRY_CONFIG")
        .args(["--approval-file", "x.toml"])
        .output()
        .await
        .unwrap();

    assert!(!out.status.success());
}
