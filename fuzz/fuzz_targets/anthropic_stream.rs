//! Arbitrary bytes, in arbitrary read sizes, through the SSE parser and the
//! Anthropic stream state. Must not panic or allocate without bound.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|reads: Vec<Vec<u8>>| {
    let _ = barry_llm::fuzzing::anthropic_stream_reads(&reads);
});
