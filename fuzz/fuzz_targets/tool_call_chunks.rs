//! Arbitrary JSON chunks through the tool-call assembly. Must not panic or
//! allocate without bound (a huge `index` once did).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(chunks) = serde_json::from_slice::<Vec<serde_json::Value>>(data) else {
        return;
    };
    let _ = barry_llm::fuzzing::assemble_chunks(&chunks, Some("reasoning"));
});
