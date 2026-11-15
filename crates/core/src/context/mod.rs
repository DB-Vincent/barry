//! Context assembly for the system prompt (M6).
//!
//! Combines AGENTS.md instructions and discovered skills into the prompt
//! sections used by [`crate::prompt::system_prompt`].

pub mod instructions;
pub mod skills;
pub mod truncate;

pub use instructions::instructions_section;
pub use skills::skills_section;
