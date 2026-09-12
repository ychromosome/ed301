use std::env;
use std::fs;
use std::path::PathBuf;

pub(crate) fn required_exact_environment(name: &str, expected: &str) {
    let actual = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert_eq!(actual, expected, "unsafe {name} selection");
}

pub(crate) fn canonical_directory(name: &str) -> PathBuf {
    let raw = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert!(
        !raw.chars().any(char::is_control),
        "{name} contains a control character"
    );
    let path = fs::canonicalize(&raw)
        .unwrap_or_else(|error| panic!("cannot canonicalize {name}: {error}"));
    assert!(path.is_dir(), "{name} is not a directory");
    let printable = path
        .to_str()
        .unwrap_or_else(|| panic!("{name} is not valid UTF-8"));
    assert!(
        !printable.chars().any(char::is_control),
        "canonical {name} contains a control character"
    );
    path
}

pub(crate) fn reject_native_injection_environment() {
    const EXACT: &[&str] = &[
        "ARFLAGS",
        "CFLAGS",
        "CCC_OVERRIDE_OPTIONS",
        "CCC_PRINT_BINDINGS",
        "CCC_PRINT_OPTIONS",
        "COMPILER_PATH",
        "CPPFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "CRATE_CC_NO_DEFAULTS",
        "CC_ENABLE_DEBUG_OUTPUT",
        "GCC_EXEC_PREFIX",
        "HOST_ARFLAGS",
        "HOST_CFLAGS",
        "TARGET_ARFLAGS",
        "TARGET_CFLAGS",
    ];
    for (name, _) in env::vars_os() {
        let Some(name) = name.to_str() else {
            panic!("non-UTF-8 environment variable name");
        };
        let prefixed = [
            "CC_",
            "CXX_",
            "AR_",
            "RANLIB_",
            "CFLAGS_",
            "CPPFLAGS_",
            "CXXFLAGS_",
            "LDFLAGS_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
        assert!(
            !prefixed && !EXACT.contains(&name),
            "native build override is forbidden: {name}"
        );
    }
}
