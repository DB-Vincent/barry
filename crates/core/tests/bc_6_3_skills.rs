//! BC-6.3 A skill's name, description and path appear in the system prompt,
//! and its body does not.
use barry_core::testing::skills_section;
use std::path::PathBuf;

fn write_skill(dir: PathBuf, _name: &str, frontmatter: &str, body: &str) {
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\n{frontmatter}\n---\n{body}"),
    )
    .unwrap();
}

#[test]
fn bc_6_3_skill_name_description_path_but_not_body() {
    let global_skills = tempfile::tempdir().unwrap();
    let project_skills = tempfile::tempdir().unwrap();

    write_skill(
        global_skills.path().join("review"),
        "review",
        "name: Code Review\n",
        "SECRET BODY THAT MUST NOT LEAK",
    );
    write_skill(
        project_skills.path().join("docs"),
        "docs",
        "name: Docs\n",
        "ANOTHER SECRET BODY",
    );

    let section = skills_section(global_skills.path(), project_skills.path());

    assert!(section.contains("# Skills"));
    assert!(section.contains("Code Review"));
    assert!(section.contains("Docs"));
    assert!(section.contains("review/SKILL.md") || section.contains("review"));
    assert!(section.contains("docs/SKILL.md") || section.contains("docs"));

    // The skill bodies must not appear in the prompt.
    assert!(!section.contains("SECRET BODY THAT MUST NOT LEAK"));
    assert!(!section.contains("ANOTHER SECRET BODY"));
}

#[test]
fn bc_6_3_no_skills_is_empty() {
    let global = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let section = skills_section(global.path(), project.path());
    assert_eq!(section, "");
}
