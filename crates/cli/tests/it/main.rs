//! Integration tests for barry-cli, built as one test binary so linking happens once.

mod bc_0_1_version;
mod bc_0_2_rules_check;
mod bc_0_3_malformed_config;
mod bc_2_10_headless;
mod bc_2_repl;
mod bc_3_12_config_rules;
mod bc_3_12_config_strict;
mod bc_3_13_config_show;
mod bc_4_3_sandbox_blocks_secret_read;
mod bc_4_4_sandbox_env_no_secrets;
mod bc_4_7_missing_bwrap;
mod bc_4_8_sandbox_cwd_writes_visible;
mod bc_5_2_log_verify;
mod bc_5_5_resume_cli;
mod bc_approval_file;
mod bc_budgets_cli;
mod bc_exit_codes;
