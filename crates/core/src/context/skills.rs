//! Skill discovery for the system prompt (PLAN 6.3).
//!
//! Discovers `~/.config/barry/skills/*/SKILL.md` and
//! `<git root>/.barry/skills/*/SKILL.md`, parses the `name` and `description`
//! fields from the YAML frontmatter with a minimal `key: value` parser (no YAML
//! dependency), and renders them under `# Skills`. Skill bodies are never
//! included in the prompt.

use std::path::{Path, PathBuf};

use super::instructions::wrap_untrusted;

/// Build the skills section for the system prompt.
///
/// `global_skills` is `~/.config/barry/skills` and `project_skills` is
/// `<git root>/.barry/skills`. Directories that do not exist are skipped.
pub fn skills_section(global_skills: &Path, project_skills: &Path) -> String {
    let mut global: Vec<(String, String, PathBuf)> = Vec::new(); // (name, description, path)
    let mut project: Vec<(String, String, PathBuf)> = Vec::new();

    collect_skills(global_skills, &mut global);
    collect_skills(project_skills, &mut project);

    if global.is_empty() && project.is_empty() {
        return String::new();
    }

    let mut out = String::from("# Skills\nRead a skill's file with the read tool when relevant:\n");
    out.push_str(&render_list(&global));
    if !project.is_empty() {
        // Repository skills are attacker-controlled on an untrusted checkout.
        out.push_str(&wrap_untrusted(&render_list(&project)));
    }
    out
}

fn render_list(skills: &[(String, String, PathBuf)]) -> String {
    let mut out = String::new();
    for (name, description, path) in skills {
        out.push_str(&format!("- {name}: {description} ({})\n", path.display()));
    }
    out
}

/// Collect skills from one `skills/` directory: each immediate subdirectory
/// containing a `SKILL.md` is one skill.
fn collect_skills(dir: &Path, skills: &mut Vec<(String, String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let skill_md = path.join("SKILL.md");
        let Ok(content) = std::fs::read_to_string(&skill_md) else {
            continue;
        };
        let (name, description) = parse_frontmatter(&content);
        if name.is_empty() {
            continue;
        }
        skills.push((name, description, skill_md));
    }
}

/// Parse `name` and `description` from YAML frontmatter using a minimal
/// `key: value` parser.
fn parse_frontmatter(content: &str) -> (String, String) {
    let mut name = String::new();
    let mut description = String::new();

    let mut in_frontmatter = false;
    for line in content.lines() {
        let line = line.trim();
        if line == "---" {
            if in_frontmatter {
                break;
            }
            in_frontmatter = true;
            continue;
        }
        if !in_frontmatter {
            continue;
        }
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        match key.as_str() {
            "name" => name = value,
            "description" => description = value,
            _ => {}
        }
    }

    (name, description)
}

/// Split a `key: value` line. Returns None when there is no `:`.
fn split_key_value(line: &str) -> Option<(String, String)> {
    let mut iter = line.splitn(2, ':');
    let key = iter.next()?.trim();
    let value = iter.next()?.trim();
    // Strip surrounding quotes.
    let value = strip_quotes(value);
    Some((key.to_string(), value.to_string()))
}

fn strip_quotes(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frontmatter() {
        let (name, desc) = parse_frontmatter(
            "---\nname: Code Review\ndescription: \"Review the code\"\n---\nbody\n",
        );
        assert_eq!(name, "Code Review");
        assert_eq!(desc, "Review the code");
    }

    #[test]
    fn empty_when_no_skills() {
        let global = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        assert_eq!(skills_section(global.path(), project.path()), "");
    }

    #[test]
    fn project_skills_are_wrapped_and_global_are_not() {
        let global = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        for (root, name) in [(&global, "g-skill"), (&project, "p-skill")] {
            let dir = root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("SKILL.md"), format!("---\nname: {name}\n---\n")).unwrap();
        }
        let section = skills_section(global.path(), project.path());
        let open = section
            .find("<untrusted_project_content>")
            .expect("open tag");
        let close = section
            .find("</untrusted_project_content>")
            .expect("close tag");
        assert!(section.find("g-skill").unwrap() < open);
        let p = section.find("p-skill").unwrap();
        assert!(open < p && p < close, "{section}");
    }
}
