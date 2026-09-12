//! Rust-owned X301 provider keys and exchange contexts.
//!
//! The unchanged D1 core owns canonical public coordinates, validated raw
//! secrets and shared outputs. Only WeakSecret is resampled during keygen.
//! The OpenSSL adapter retains the bound v1 allocation and FFI contracts.

use core::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crypto_bigint::CtEq;
use x301_core::parameters::{PUBLIC_BYTES, SECRET_BYTES, SHARED_BYTES};
#[cfg(test)]
use x301_core::public_from_secret;
use x301_core::{PublicKey, SecretKey, keygen};

#[path = "../../../common/allocation.rs"]
mod allocation;
use allocation::{Shared, try_box_at};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "secret-taint-instrumentation")]
fn taint_secret(value: &mut [u8]) {
    ed301_valgrind_client::mark_undefined(value);
}

#[cfg(not(feature = "secret-taint-instrumentation"))]
#[inline(always)]
fn taint_secret(_value: &mut [u8]) {}

/// Function table consumed by the C provider shim.
#[repr(C)]
pub(crate) struct X301RustApi {
    abi_version: u32,
    struct_size: usize,
    secret_bytes: usize,
    public_bytes: usize,
    shared_bytes: usize,
    key_new: extern "C" fn() -> *mut c_void,
    key_free: unsafe extern "C" fn(*mut c_void),
    key_import: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int,
    key_set_encoded_public: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    key_generate: unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int>,
        *mut c_void,
    ) -> *mut c_void,
    key_duplicate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> *mut c_void,
    key_has: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    key_validate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    key_match: unsafe extern "C" fn(*const c_void, *const c_void, c_int, c_int) -> c_int,
    key_get_private: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    key_get_public: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    exchange_new: extern "C" fn() -> *mut c_void,
    exchange_free: unsafe extern "C" fn(*mut c_void),
    exchange_duplicate: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    exchange_init: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    exchange_set_peer: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    exchange_derive: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    cleanse: unsafe extern "C" fn(*mut u8, usize),
}

pub(crate) static RUST_API: X301RustApi = X301RustApi {
    abi_version: 1,
    struct_size: core::mem::size_of::<X301RustApi>(),
    secret_bytes: SECRET_BYTES,
    public_bytes: PUBLIC_BYTES,
    shared_bytes: SHARED_BYTES,
    key_new,
    key_free,
    key_import,
    key_set_encoded_public,
    key_generate,
    key_duplicate,
    key_has,
    key_validate,
    key_match,
    key_get_private,
    key_get_public,
    exchange_new,
    exchange_free,
    exchange_duplicate,
    exchange_init,
    exchange_set_peer,
    exchange_derive,
    cleanse,
};

#[derive(Clone, Default)]
struct X301Key {
    private: Option<Shared<SecretKey>>,
    public: Option<PublicKey>,
}

#[derive(Clone, Default)]
struct X301Exchange {
    private: Option<Shared<SecretKey>>,
    peer_public: Option<PublicKey>,
}

#[cfg(feature = "test-failpoint")]
fn hit_panic_failpoint(name: &str) {
    match std::env::var("X301_V2_PROVIDER_PANIC_FAILPOINT") {
        Ok(value) if value == name => panic!("injected X301 provider panic in {name}"),
        _ => {}
    }
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_panic_failpoint(_name: &str) {}

#[cfg(feature = "test-failpoint")]
fn hit_alloc_failpoint(name: &str) -> bool {
    matches!(
        std::env::var("X301_V2_PROVIDER_ALLOC_FAILPOINT"),
        Ok(value) if value == name
    )
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_alloc_failpoint(_name: &str) -> bool {
    false
}

#[cfg(feature = "test-failpoint")]
fn public_alias_mask() -> u8 {
    std::env::var("X301_V2_PROVIDER_PUBLIC_ALIAS_MASK")
        .ok()
        .and_then(|value| u8::from_str_radix(&value, 16).ok())
        .filter(|mask| *mask != 0 && (*mask & 0x1f) == 0)
        .unwrap_or(0)
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn public_alias_mask() -> u8 {
    0
}

fn ffi_int(operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(0)
}

fn ffi_pointer(operation: impl FnOnce() -> *mut c_void) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(core::ptr::null_mut())
}

extern "C" fn key_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_new");
        try_box_at("key_new", X301Key::default())
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_free(key: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !key.is_null() {
            // SAFETY: Each pointer returned by this module is freed once.
            drop(unsafe { Box::from_raw(key.cast::<X301Key>()) });
        }
    }));
}

unsafe extern "C" fn key_import(
    key: *mut c_void,
    private: *const u8,
    private_len: usize,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_import");
        // SAFETY: C passes a live Rust-owned key and readable optional buffers.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_mut() }) else {
            return 0;
        };
        // SecretKey validates length and the excluded clamp before any peer bytes.
        let Some(raw_private) = (unsafe { read_optional_secret(private, private_len) }) else {
            return 0;
        };
        // SAFETY: The caller retains the public buffer for this invocation.
        let Some(raw_public) = (unsafe { read_optional_public(public, public_len) }) else {
            return 0;
        };
        if raw_private.is_none() && raw_public.is_none() {
            return 0;
        }
        let derived_public = match raw_private.as_ref() {
            Some(secret) => match secret.public_key() {
                Ok(value) => Some(value),
                Err(_) => return 0,
            },
            None => None,
        };
        if let (Some(public), Some(derived)) = (raw_public.as_ref(), derived_public.as_ref())
            && !bytes_equal(derived.as_bytes(), public.as_bytes())
        {
            return 0;
        }
        let private = match raw_private {
            Some(secret) => match Shared::try_new_at("key_import", secret) {
                Some(secret) => Some(secret),
                None => return 0,
            },
            None => None,
        };
        *key = X301Key {
            private,
            public: derived_public.or(raw_public),
        };
        1
    })
}

unsafe extern "C" fn key_set_encoded_public(
    key: *mut c_void,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_set_encoded_public");
        // SAFETY: C passes a live Rust-owned key and readable public buffer.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_mut() }) else {
            return 0;
        };
        let Some(Some(public)) = (unsafe { read_optional_public(public, public_len) }) else {
            return 0;
        };
        if let Some(existing) = key.public.as_ref() {
            if !bytes_equal(existing.as_bytes(), public.as_bytes()) {
                return 0;
            }
        } else if let Some(private) = key.private.as_ref() {
            let Ok(derived) = private.public_key() else {
                return 0;
            };
            if !bytes_equal(derived.as_bytes(), public.as_bytes()) {
                return 0;
            }
        }
        key.public = Some(public);
        1
    })
}

unsafe extern "C" fn key_generate(
    fill_random: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int>,
    callback_context: *mut c_void,
) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_generate");
        let Some(fill_random) = fill_random else {
            return core::ptr::null_mut();
        };
        let generated = keygen(|bytes| {
            // SAFETY: D1 supplies its live zeroizing 38-byte buffer. The C
            // callback is valid for this invocation and must fill it completely.
            if unsafe { fill_random(callback_context, bytes.as_mut_ptr(), bytes.len()) } != 1 {
                return Err(());
            }
            taint_secret(bytes);
            Ok(())
        });
        let Ok((secret, public)) = generated else {
            return core::ptr::null_mut();
        };
        // Allocation/internal errors are final; they never cause another draw.
        let Some(private) = Shared::try_new_at("key_generate_shared", secret) else {
            return core::ptr::null_mut();
        };
        let key = X301Key {
            private: Some(private),
            public: Some(public),
        };
        try_box_at("key_generate", key)
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_duplicate(
    source: *const c_void,
    include_private: c_int,
    include_public: c_int,
) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_duplicate");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(source) = (unsafe { source.cast::<X301Key>().as_ref() }) else {
            return core::ptr::null_mut();
        };
        let private = (include_private != 0)
            .then(|| source.private.clone())
            .flatten();
        let public = (include_public != 0)
            .then(|| source.public.clone())
            .flatten();
        try_box_at("key_duplicate", X301Key { private, public })
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_has(
    key: *const c_void,
    require_private: c_int,
    require_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        i32::from(
            (require_private == 0 || key.private.is_some())
                && (require_public == 0 || key.public.is_some()),
        )
    })
}

unsafe extern "C" fn key_validate(
    key: *const c_void,
    validate_private: c_int,
    validate_public: c_int,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_validate");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let derived = if validate_private != 0 {
            let Some(private) = key.private.as_ref() else {
                return 0;
            };
            match private.public_key() {
                Ok(value) => Some(value),
                Err(_) => return 0,
            }
        } else {
            None
        };
        if validate_public != 0 {
            let Some(public) = key.public.as_ref() else {
                return 0;
            };
            if let Some(derived) = derived.as_ref()
                && !bytes_equal(derived.as_bytes(), public.as_bytes())
            {
                return 0;
            }
        }
        1
    })
}

unsafe extern "C" fn key_match(
    first: *const c_void,
    second: *const c_void,
    match_private: c_int,
    match_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes two live Rust-owned key objects.
        let (Some(first), Some(second)) = (unsafe { first.cast::<X301Key>().as_ref() }, unsafe {
            second.cast::<X301Key>().as_ref()
        }) else {
            return 0;
        };
        if match_private != 0 {
            let (Some(first), Some(second)) = (first.private.as_ref(), second.private.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(first.as_bytes(), second.as_bytes()) {
                return 0;
            }
        }
        if match_public != 0 {
            let (Some(first), Some(second)) = (first.public.as_ref(), second.public.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(first.as_bytes(), second.as_bytes()) {
                return 0;
            }
        }
        1
    })
}

unsafe extern "C" fn key_get_private(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let Some(private) = key.private.as_ref() else {
            return 0;
        };
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, private.as_bytes()) })
    })
}

unsafe extern "C" fn key_get_public(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let Some(public) = key.public.as_ref() else {
            return 0;
        };
        let mut encoded = public.to_bytes();
        encoded[PUBLIC_BYTES - 1] |= public_alias_mask();
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, &encoded) })
    })
}

extern "C" fn exchange_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("exchange_new");
        try_box_at("exchange_new", X301Exchange::default())
            .map_or(core::ptr::null_mut(), |value| Box::into_raw(value).cast())
    })
}

unsafe extern "C" fn exchange_free(exchange: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !exchange.is_null() {
            // SAFETY: Each pointer returned by this module is freed once.
            drop(unsafe { Box::from_raw(exchange.cast::<X301Exchange>()) });
        }
    }));
}

unsafe extern "C" fn exchange_duplicate(source: *const c_void) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("exchange_duplicate");
        // SAFETY: C passes a live Rust-owned exchange object.
        let Some(source) = (unsafe { source.cast::<X301Exchange>().as_ref() }) else {
            return core::ptr::null_mut();
        };
        try_box_at("exchange_duplicate", source.clone())
            .map_or(core::ptr::null_mut(), |value| Box::into_raw(value).cast())
    })
}

unsafe extern "C" fn exchange_init(exchange: *mut c_void, key: *const c_void) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_init");
        // SAFETY: C passes live Rust-owned exchange and key objects.
        let (Some(exchange), Some(key)) = (
            unsafe { exchange.cast::<X301Exchange>().as_mut() },
            unsafe { key.cast::<X301Key>().as_ref() },
        ) else {
            return 0;
        };
        let Some(private) = key.private.clone() else {
            return 0;
        };
        *exchange = X301Exchange {
            private: Some(private),
            peer_public: None,
        };
        1
    })
}

unsafe extern "C" fn exchange_set_peer(exchange: *mut c_void, peer: *const c_void) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_set_peer");
        // SAFETY: C passes live Rust-owned exchange and key objects.
        let (Some(exchange), Some(peer)) = (
            unsafe { exchange.cast::<X301Exchange>().as_mut() },
            unsafe { peer.cast::<X301Key>().as_ref() },
        ) else {
            return 0;
        };
        if exchange.private.is_none() {
            return 0;
        }
        let Some(public) = peer.public.as_ref() else {
            return 0;
        };
        exchange.peer_public = Some(public.clone());
        1
    })
}

unsafe extern "C" fn exchange_derive(
    exchange: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_derive");
        // SAFETY: C passes a live Rust-owned exchange object.
        let Some(exchange) = (unsafe { exchange.cast::<X301Exchange>().as_ref() }) else {
            return 0;
        };
        let (Some(private), Some(peer_public)) =
            (exchange.private.as_ref(), exchange.peer_public.as_ref())
        else {
            return 0;
        };
        let Ok(shared) = private.shared_secret(peer_public) else {
            return 0;
        };
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, shared.as_bytes()) })
    })
}

unsafe extern "C" fn cleanse(buffer: *mut u8, length: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if length != 0 && length <= isize::MAX as usize && !buffer.is_null() {
            // SAFETY: C owns this writable temporary buffer.
            unsafe { core::slice::from_raw_parts_mut(buffer, length) }.zeroize();
        }
    }));
}

fn bytes_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let equal = left.ct_eq(right).to_bool();
    #[cfg(feature = "secret-taint-instrumentation")]
    {
        let mut public_equal = equal;
        ed301_valgrind_client::make_defined(&mut public_equal);
        public_equal
    }
    #[cfg(not(feature = "secret-taint-instrumentation"))]
    {
        equal
    }
}

unsafe fn read_optional_public(input: *const u8, input_len: usize) -> Option<Option<PublicKey>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != PUBLIC_BYTES {
        return None;
    }
    #[cfg(test)]
    PUBLIC_READS.with(|count| count.set(count.get() + 1));
    // SAFETY: C guarantees exactly PUBLIC_BYTES readable bytes.
    let encoded = unsafe { core::slice::from_raw_parts(input, PUBLIC_BYTES) };
    PublicKey::from_bytes(encoded).ok().map(Some)
}

unsafe fn read_optional_secret(input: *const u8, input_len: usize) -> Option<Option<SecretKey>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != SECRET_BYTES {
        return None;
    }
    let mut output = Zeroizing::new([0_u8; SECRET_BYTES]);
    // SAFETY: C guarantees exactly SECRET_BYTES readable bytes. The first
    // owned copy is zeroizing, including error and unwind paths.
    unsafe { core::ptr::copy_nonoverlapping(input, output.as_mut_ptr(), SECRET_BYTES) };
    // Imported bytes retain their incoming shadow state. Only fresh RNG output
    // needs explicit marking in instrumented builds.
    SecretKey::from_bytes(output.as_ref()).ok().map(Some)
}

#[cfg(test)]
std::thread_local! {
    static PUBLIC_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

unsafe fn write_exact<const N: usize>(output: *mut u8, output_len: usize, value: &[u8; N]) -> bool {
    if output.is_null() || output_len < N {
        return false;
    }
    // SAFETY: The caller guarantees `output_len` writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), output, N) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../vectors/x301-v2.json")).unwrap()
    }

    fn octets(value: &serde_json::Value) -> Vec<u8> {
        let encoded = value.as_str().unwrap();
        (0..encoded.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
            .collect()
    }

    struct OwnedKey(*mut c_void);

    impl Drop for OwnedKey {
        fn drop(&mut self) {
            // SAFETY: The test owns the one live pointer returned by this
            // module and releases it exactly once.
            unsafe { key_free(self.0) };
        }
    }

    #[test]
    fn phase_b_keys_keep_original_secrets_and_exact_publics() {
        for row in vectors()["keys"].as_array().unwrap() {
            let secret = octets(&row["secret_hex"]);
            let public = octets(&row["public_hex"]);
            let key = OwnedKey(key_new());
            assert!(!key.0.is_null());
            assert_eq!(
                unsafe {
                    key_import(
                        key.0,
                        secret.as_ptr(),
                        secret.len(),
                        public.as_ptr(),
                        public.len(),
                    )
                },
                1
            );
            let mut exported = [0_u8; SECRET_BYTES];
            assert_eq!(
                unsafe { key_get_private(key.0, exported.as_mut_ptr(), exported.len()) },
                1
            );
            assert_eq!(exported.as_slice(), secret);
            assert_eq!(
                unsafe { key_get_public(key.0, exported.as_mut_ptr(), exported.len()) },
                1
            );
            assert_eq!(exported.as_slice(), public);
            assert_eq!(unsafe { key_validate(key.0, 1, 1) }, 1);
            exported.zeroize();
        }
    }

    #[test]
    fn all_weak_aliases_fail_before_reading_valid_or_invalid_peer_bytes() {
        let data = vectors();
        let public = octets(&data["keys"][0]["public_hex"]);
        let noncanonical = octets(&data["errors"][0]["u_hex"]);
        let good_secret = octets(&data["keys"][0]["secret_hex"]);
        let key = OwnedKey(key_new());
        assert_eq!(
            unsafe {
                key_import(
                    key.0,
                    good_secret.as_ptr(),
                    good_secret.len(),
                    core::ptr::null(),
                    0,
                )
            },
            1
        );
        for row in data["weak_secrets"].as_array().unwrap() {
            let weak = octets(&row["secret_hex"]);
            for peer in [&public, &noncanonical] {
                PUBLIC_READS.with(|count| count.set(0));
                assert_eq!(
                    unsafe {
                        key_import(key.0, weak.as_ptr(), weak.len(), peer.as_ptr(), peer.len())
                    },
                    0
                );
                PUBLIC_READS.with(|count| assert_eq!(count.get(), 0));
                let mut unchanged = [0_u8; SECRET_BYTES];
                assert_eq!(
                    unsafe { key_get_private(key.0, unchanged.as_mut_ptr(), unchanged.len()) },
                    1
                );
                assert_eq!(unchanged.as_slice(), good_secret);
                unchanged.zeroize();
            }
        }
    }

    struct Draws {
        inputs: Vec<Vec<u8>>,
        calls: usize,
        fail_at: Option<usize>,
    }

    unsafe extern "C" fn fill_draw(context: *mut c_void, output: *mut u8, length: usize) -> c_int {
        // SAFETY: Every invocation below supplies this live Draws object.
        let draws = unsafe { &mut *context.cast::<Draws>() };
        let index = draws.calls;
        draws.calls += 1;
        if draws.fail_at == Some(index) || length != SECRET_BYTES || index >= draws.inputs.len() {
            return 0;
        }
        // SAFETY: D1's keygen supplied the exact writable callback buffer.
        unsafe { core::ptr::copy_nonoverlapping(draws.inputs[index].as_ptr(), output, length) };
        1
    }

    #[test]
    fn keygen_resamples_all_weak_aliases_but_random_failure_is_final() {
        let data = vectors();
        let mut inputs: Vec<Vec<u8>> = data["weak_secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| octets(&row["secret_hex"]))
            .collect();
        inputs.push(octets(&data["keys"][0]["secret_hex"]));
        let mut draws = Draws {
            inputs,
            calls: 0,
            fail_at: None,
        };
        let key =
            OwnedKey(unsafe { key_generate(Some(fill_draw), (&mut draws as *mut Draws).cast()) });
        assert!(!key.0.is_null());
        assert_eq!(draws.calls, 65);
        let mut public = [0_u8; PUBLIC_BYTES];
        assert_eq!(
            unsafe { key_get_public(key.0, public.as_mut_ptr(), public.len()) },
            1
        );
        assert_eq!(public.as_slice(), octets(&data["keys"][0]["public_hex"]));
        draws.calls = 0;
        draws.fail_at = Some(0);
        let failed =
            OwnedKey(unsafe { key_generate(Some(fill_draw), (&mut draws as *mut Draws).cast()) });
        assert!(failed.0.is_null());
        assert_eq!(draws.calls, 1);
    }

    #[test]
    fn exchange_holds_validated_owners_after_keys_are_freed() {
        let data = vectors();
        let a = octets(&data["keys"][0]["secret_hex"]);
        let b = octets(&data["keys"][1]["public_hex"]);
        let key = OwnedKey(key_new());
        let peer = OwnedKey(key_new());
        assert_eq!(
            unsafe { key_import(key.0, a.as_ptr(), a.len(), core::ptr::null(), 0) },
            1
        );
        assert_eq!(
            unsafe { key_import(peer.0, core::ptr::null(), 0, b.as_ptr(), b.len()) },
            1
        );
        let exchange = exchange_new();
        assert!(!exchange.is_null());
        assert_eq!(unsafe { exchange_init(exchange, key.0) }, 1);
        assert_eq!(unsafe { exchange_set_peer(exchange, peer.0) }, 1);
        // SAFETY: key and exchange are live Rust-owned objects in this test.
        let raw_key = unsafe { &*key.0.cast::<X301Key>() };
        assert_eq!(raw_key.private.as_ref().unwrap().reference_count(), 2);
        let duplicate = unsafe { exchange_duplicate(exchange) };
        assert!(!duplicate.is_null());
        assert_eq!(raw_key.private.as_ref().unwrap().reference_count(), 3);
        drop(key);
        drop(peer);
        let mut shared = [0_u8; SHARED_BYTES];
        assert_eq!(
            unsafe { exchange_derive(exchange, shared.as_mut_ptr(), shared.len()) },
            1
        );
        assert_eq!(shared.as_slice(), octets(&data["dh"][0]["shared_hex"]));
        unsafe { exchange_free(exchange) };
        shared.zeroize();
        assert_eq!(
            unsafe { exchange_derive(duplicate, shared.as_mut_ptr(), shared.len()) },
            1
        );
        assert_eq!(shared.as_slice(), octets(&data["dh"][0]["shared_hex"]));
        unsafe { exchange_free(duplicate) };
        shared.zeroize();
    }

    #[test]
    fn low_order_peer_imports_but_derive_returns_no_partial_output() {
        let secret = [0x31; SECRET_BYTES];
        let public = [0; PUBLIC_BYTES];
        let key = OwnedKey(key_new());
        let peer = OwnedKey(key_new());
        let exchange = exchange_new();
        assert_eq!(
            unsafe { key_import(key.0, secret.as_ptr(), secret.len(), core::ptr::null(), 0) },
            1
        );
        assert_eq!(
            unsafe { key_import(peer.0, core::ptr::null(), 0, public.as_ptr(), public.len()) },
            1
        );
        assert_eq!(unsafe { exchange_init(exchange, key.0) }, 1);
        assert_eq!(unsafe { exchange_set_peer(exchange, peer.0) }, 1);
        let mut output = [0xa5; SHARED_BYTES];
        assert_eq!(
            unsafe { exchange_derive(exchange, output.as_mut_ptr(), output.len()) },
            0
        );
        assert_eq!(output, [0xa5; SHARED_BYTES]);
        unsafe { exchange_free(exchange) };
    }

    #[test]
    fn cleanse_rejects_oversized_lengths_without_forming_a_slice() {
        let mut byte = 0x5a;
        unsafe { cleanse(&mut byte, isize::MAX as usize + 1) };
        assert_eq!(byte, 0x5a);
        unsafe { cleanse(&mut byte, 1) };
        assert_eq!(byte, 0);
    }

    #[test]
    fn private_only_duplicate_rejects_foreign_public_atomically() {
        let private_a = [0x31_u8; SECRET_BYTES];
        let private_b = [0xa7_u8; SECRET_BYTES];
        let public_a = public_from_secret(&private_a).expect("A public key");
        let public_b = public_from_secret(&private_b).expect("B public key");
        assert_ne!(public_a, public_b);

        let source = OwnedKey(key_new());
        assert!(!source.0.is_null());
        // SAFETY: All buffers and the module-owned key remain live for each
        // complete call.
        assert_eq!(
            unsafe {
                key_import(
                    source.0,
                    private_a.as_ptr(),
                    private_a.len(),
                    core::ptr::null(),
                    0,
                )
            },
            1
        );
        // SAFETY: `source` remains live and the returned object is owned by
        // this test.
        let duplicate = OwnedKey(unsafe { key_duplicate(source.0, 1, 0) });
        assert!(!duplicate.0.is_null());
        // SAFETY: `duplicate` remains live for all queries below.
        assert_eq!(unsafe { key_has(duplicate.0, 1, 0) }, 1);
        assert_eq!(unsafe { key_has(duplicate.0, 0, 1) }, 0);

        let mut private_after = [0_u8; SECRET_BYTES];
        // SAFETY: The output is exactly the documented private-key size.
        assert_eq!(
            unsafe {
                key_get_private(duplicate.0, private_after.as_mut_ptr(), private_after.len())
            },
            1
        );
        assert_eq!(private_after, private_a);

        // SAFETY: The public buffers are exact and remain readable.
        assert_eq!(
            unsafe { key_set_encoded_public(duplicate.0, public_b.as_ptr(), public_b.len()) },
            0
        );
        assert_eq!(unsafe { key_has(duplicate.0, 0, 1) }, 0);
        private_after.fill(0);
        assert_eq!(
            unsafe {
                key_get_private(duplicate.0, private_after.as_mut_ptr(), private_after.len())
            },
            1
        );
        assert_eq!(private_after, private_a);

        assert_eq!(
            unsafe { key_set_encoded_public(duplicate.0, public_a.as_ptr(), public_a.len()) },
            1
        );
        assert_eq!(unsafe { key_validate(duplicate.0, 1, 1) }, 1);
        private_after.zeroize();
    }
}
