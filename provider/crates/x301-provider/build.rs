use std::env;

#[path = "../../common/build_support.rs"]
mod build_support;
use build_support::{
    canonical_directory, reject_native_injection_environment, required_exact_environment,
};

fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/hybrid_kem.c");
    println!("cargo:rerun-if-changed=c/param_helpers.h");
    println!("cargo:rerun-if-changed=../../common/build_support.rs");
    println!("cargo:rerun-if-changed=../../common/param_helpers.h");
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
