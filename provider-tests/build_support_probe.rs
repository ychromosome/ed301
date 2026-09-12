#[path = "../provider/common/build_support.rs"]
mod build_support;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("reject") => build_support::reject_native_injection_environment(),
        Some("directory") => {
            build_support::canonical_directory("PROBE_DIRECTORY");
        }
        Some("exact") => build_support::required_exact_environment("PROBE_EXACT", "1"),
        _ => panic!("unknown probe"),
    }
}
