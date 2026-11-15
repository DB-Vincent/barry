//! Arbitrary path strings through `canonicalise`. A successful result must
//! never contain a `..` component.
#![no_main]

use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|path: &str| {
    let cwd = std::env::temp_dir();
    if let Ok(result) = barry_policy::canonicalise(&cwd, Path::new(path)) {
        assert!(
            !result.components().any(|c| matches!(c, Component::ParentDir)),
            "{path:?} canonicalised to {result:?}"
        );
    }
});
