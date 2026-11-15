//! Integration tests for barry-llm, built as one test binary so linking happens once.

mod bc_1_1_streamed_text;
mod bc_1_2_split_tool_call;
mod bc_1_3_two_tool_calls;
mod bc_1_4_stop_reasons;
mod bc_1_5_invalid_json_args;
mod bc_1_6_retry_and_auth;
mod bc_1_7_bearer_header;
mod bc_1_8_cancel;
mod bc_1_9_reasoning_field;
