//! Test-only FFI for X301 dudect; not a provider or public product interface.
use std::hint::black_box;
use x301_core::{public_from_secret, shared_secret, x301::BASE_U_BYTES};
use zeroize::Zeroizing;

/// Opaque test-owned seed slot.
pub struct TimingSlot {
    seed: Zeroizing<[u8; 38]>,
}

/// # Safety
/// The caller supplies 38 readable initialized bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x301_timing_new(seed: *const u8) -> *mut TimingSlot {
    if seed.is_null() {
        return std::ptr::null_mut();
    }
    let mut owned = Zeroizing::new([0_u8; 38]);
    owned.copy_from_slice(unsafe { std::slice::from_raw_parts(seed, 38) });
    Box::into_raw(Box::new(TimingSlot { seed: owned }))
}

/// # Safety
/// The pointer is null or exclusively owned, live, and returned by this adapter.
/// It is not used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x301_timing_free(slot: *mut TimingSlot) {
    if !slot.is_null() {
        drop(unsafe { Box::from_raw(slot) });
    }
}

/// # Safety
/// The pointer remains live, immutable, and owned by the single-threaded caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x301_timing_public(slot: *const TimingSlot) -> u8 {
    let Some(slot) = (unsafe { slot.as_ref() }) else {
        return 0;
    };
    match public_from_secret(black_box(&*slot.seed)) {
        Ok(public) => {
            black_box(public);
            1
        }
        Err(_) => 0,
    }
}

/// # Safety
/// The pointer remains live, immutable, and owned by the single-threaded caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x301_timing_shared(slot: *const TimingSlot) -> u8 {
    let Some(slot) = (unsafe { slot.as_ref() }) else {
        return 0;
    };
    match shared_secret(black_box(&*slot.seed), black_box(&BASE_U_BYTES)) {
        Ok(shared) => {
            black_box(shared);
            1
        }
        Err(_) => 0,
    }
}
