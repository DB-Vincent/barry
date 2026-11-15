//! Integration tests for barry-core, built as one test binary so linking happens once.

use std::sync::Mutex;

/// Serializes `HOME` env var access across the tests in this binary.
pub(crate) static HOME_LOCK: Mutex<()> = Mutex::new(());

mod bc_2_11_prompt_snapshot;
mod bc_2_1_read_tool;
mod bc_2_2_edit_tool;
mod bc_2_3_bash;
mod bc_2_4_bash_timeout;
mod bc_2_5_truncation;
mod bc_2_6_max_turns;
mod bc_2_7_three_results;
mod bc_2_8_unknown_tool;
mod bc_2_9_cancel_bash;
mod bc_2_agent_tool_stub;
mod bc_2_bash_flag;
mod bc_2_tool_result_shape;
mod bc_3_2_write_outside_cwd_denied;
mod bc_3_3_grant_persists;
mod bc_3_4_grant_no_carry;
mod bc_3_6_protected_path;
mod bc_3_7_read_deny;
mod bc_3_9_bash_always_session;
mod bc_4_1_sandbox_blocks_outside_write;
mod bc_4_2_sandbox_grant_retry;
mod bc_4_5_git_config_protected;
mod bc_4_6_network;
mod bc_5_1_tool_decision_log;
mod bc_5_3_redaction;
mod bc_5_4_log_permissions;
mod bc_5_5_resume;
mod bc_6_1_agents_md;
mod bc_6_2_instructions_truncated;
mod bc_6_3_skills;
mod bc_6_4_compaction_clear;
mod bc_6_6_compaction_log_entry;
mod bc_6_7_compact_command;
mod bc_hook_pre_tool_use;
