use std::env;

#[path = "../../common/build_support.rs"]
mod build_support;
use build_support::{
    canonical_directory, reject_native_injection_environment, required_exact_environment,
};

fn main() {
    println!("cargo:rerun-if-changed=c/provider_shim.c");
    println!("cargo:rerun-if-changed=c/param_helpers.h");
    println!("cargo:rerun-if-changed=../../common/build_support.rs");
    println!("cargo:rerun-if-changed=../../common/param_helpers.h");
    println!("cargo:rerun-if-changed=c/provider_internal.h");
    println!("cargo:rerun-if-changed=../../common/generated_ed301_profile.h");
    println!("cargo:rerun-if-changed=../../common/provider_codec.h");
    println!("cargo:rerun-if-changed=../../common/provider_rand.h");
    for name in [
        "ED301_HERMETIC_PROVIDER_BUILD",
        "OPENSSL_INCLUDE_DIR",
        "OPENSSL_LIB_DIR",
        "CC",
        "AR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    required_exact_environment("ED301_HERMETIC_PROVIDER_BUILD", "1");
    required_exact_environment("CC", "/usr/bin/gcc");
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
    let failpoint = env::var_os("CARGO_FEATURE_TEST_FAILPOINT").is_some();
    let pki_experiment = env::var_os("CARGO_FEATURE_PKI_EXPERIMENT").is_some();
    let tls_experiment = env::var_os("CARGO_FEATURE_TLS_EXPERIMENT").is_some();
    let tls_collider = env::var_os("CARGO_FEATURE_TLS_COLLIDER").is_some();
    let pki_only = pki_experiment && !tls_experiment && !tls_collider;
    assert!(
        usize::from(failpoint)
            + usize::from(pki_only)
            + usize::from(tls_experiment)
            + usize::from(tls_collider)
            <= 1,
        "provider artifact features are mutually exclusive"
    );
    if failpoint {
        build.define("ED301V2_TEST_FAILPOINT_ARTIFACT", "1");
    }
    if pki_experiment {
        build.define("ED301V2_PKI_EXPERIMENT_ARTIFACT", "1");
    }
    if tls_experiment {
        build.define("ED301V2_TLS_EXPERIMENT_ARTIFACT", "1");
    }
    if tls_collider {
        build.define("ED301V2_TLS_COLLIDER_ARTIFACT", "1");
    }
    // This feature instruments the C shim only. Rust and the sealed OpenSSL
    // binaries remain outside ASan/UBSan instrumentation; Valgrind covers
    // the complete process in a separate lane.
    if env::var_os("CARGO_FEATURE_TEST_SANITIZER").is_some() {
        build
            .flag("-fsanitize=address,undefined")
            .flag("-fno-sanitize-recover=all")
            .flag("-fno-omit-frame-pointer");
        println!("cargo:rustc-link-lib=asan");
        println!("cargo:rustc-link-lib=ubsan");
    }
    build
        .compiler("/usr/bin/gcc")
        .archiver("/usr/bin/ar")
        .include(&include_dir)
        .file("c/provider_shim.c")
        .std("c11")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fstack-protector-strong")
        .flag(&source_map)
        .warnings(true)
        .warnings_into_errors(true)
        .compile("ed301_eddsa_v2_shim");

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
