# Rust implementation work for the approved v2 profiles

Phase C development, not a Gate-C approval or production release. The v1
source baseline is imported from the clean, revision-bound project checkout;
parameter-dependent declarations and expected outputs are regenerated from
the approved Gate-A/B artifacts. No old build or side-channel result applies.

Build output is kept outside the repository with CARGO_TARGET_DIR so the
Gate-B-bound ignore file and other archived inputs need not be changed.
Current progress, bounds and verification evidence belong under phase-c/.
