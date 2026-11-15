//! Integration tests for barry-policy, built as one test binary so linking happens once.

mod bash_rule_bypasses;
mod bc_3_11_rule_validation;
mod bc_3_5_path_canonicalisation;
mod bc_3_8_rule_table;
mod dangling_symlink;
mod grant_dir_paths;
mod granted_prefixes;
mod protected_paths;
mod session_grants;
