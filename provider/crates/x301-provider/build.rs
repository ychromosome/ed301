use std::env;
use std::fs;
use std::path::PathBuf;

fn required_exact_environment(name: &str, expected: &str) {
    let actual = env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    assert_eq!(actual, expected, "unsafe {name} selection");
}

fn canonical_directory(name: &str) -> PathBuf {
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

fn reject_native_injection_environment() {
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

fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/hybrid_kem.c");
    println!("cargo:rerun-if-changed=c/param_helpers.h");
    println!("cargo:rerun-if-changed=c/provider_internal.h");
    println!("cargo:rerun-if-changed=../../common/generated_x301_profile.h");
    println!("cargo:rerun-if-changed=../../common/provider_codec.h");
    println!("cargo:rerun-if-changed=../../common/provider_rand.h");
    for name in [
        "X301_HERMETIC_PROVIDER_BUILD",
        "OPENSSL_INCLUDE_DIR",
        "OPENSSL_LIB_DIR",
        "CC",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    required_exact_environment("X301_HERMETIC_PROVIDER_BUILD", "1");
    let fuzz = env::var_os("CARGO_FEATURE_TEST_FUZZ_COVERAGE").is_some();
    let compiler = if fuzz {
        "/usr/bin/clang"
    } else {
        "/usr/bin/gcc"
    };
    required_exact_environment("CC", compiler);
    required_exact_environment("AR", "/usr/bin/ar");
    reject_native_injection_environment();
    let include_dir = canonical_directory("OPENSSL_INCLUDE_DIR");
    let lib_dir = canonical_directory("OPENSSL_LIB_DIR");
    let manifest_dir = canonical_directory("CARGO_MANIFEST_DIR");
    let source_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("provider manifest must remain below the source root");
    let source_map = format!(
        "-ffile-prefix-map={}=/usr/src/ed301-v2",
        source_root
            .to_str()
            .expect("source root must remain valid UTF-8")
    );

    let mut build = cc::Build::new();
    let hybrid = env::var_os("CARGO_FEATURE_TLS_X301_MLKEM1024").is_some();
    let sanitizer = env::var_os("CARGO_FEATURE_TEST_SANITIZER").is_some();
    assert!(
        !(sanitizer && fuzz),
        "sanitizer and fuzz coverage are separate artifacts"
    );
    for (feature, define) in [
        (
            "CARGO_FEATURE_TEST_FAILPOINT",
            "X301_TEST_FAILPOINT_ARTIFACT",
        ),
        (
            "CARGO_FEATURE_PKI_EXPERIMENT",
            "X301_PKI_EXPERIMENT_ARTIFACT",
        ),
        (
            "CARGO_FEATURE_TLS_X301_MLKEM1024",
            "X301_ENABLE_HYBRID_MLKEM1024",
        ),
        (
            "CARGO_FEATURE_SECRET_TAINT_INSTRUMENTATION",
            "X301_SECRET_TAINT_INSTRUMENTATION",
        ),
    ] {
        if env::var_os(feature).is_some() {
            build.define(define, "1");
        }
    }
    if hybrid {
        build.file("c/hybrid_kem.c");
    }
    if sanitizer {
        build
            .flag("-fsanitize=address,undefined")
            .flag("-fno-sanitize-recover=all")
            .flag("-fno-omit-frame-pointer");
        println!("cargo:rustc-link-lib=asan");
        println!("cargo:rustc-link-lib=ubsan");
    }
    if fuzz {
        build.flag("-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp");
    }
    build
        .compiler(compiler)
        .archiver("/usr/bin/ar")
        .include(&include_dir)
        .file("c/provider_shim.c")
        .std("c11")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fstack-protector-strong")
        .flag(&source_map)
        .warnings(true)
        .warnings_into_errors(true)
        .compile("x301_provider_shim");

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir
            .to_str()
            .expect("canonical OPENSSL_LIB_DIR must remain UTF-8")
    );
    println!("cargo:rustc-link-lib=crypto");

    // The dynamic export surface is restricted to the single required
    // provider entry point by rustc's cdylib symbol handling and is verified
    // independently by the module-export gate.
}
