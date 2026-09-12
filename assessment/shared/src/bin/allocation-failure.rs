//! Controlled allocator failure; no intentional invalid memory access.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static FAIL_NEXT: AtomicBool = AtomicBool::new(false);
static DROPS: AtomicUsize = AtomicUsize::new(0);
struct Allocator;
// SAFETY: Successful allocations/deallocations are forwarded with the same
// layout to System; returning null reports an allocation failure.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_NEXT.swap(false, Ordering::SeqCst) {
            std::ptr::null_mut()
        } else {
            // SAFETY: caller supplied a valid allocation layout.
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: allocation ownership and matching layout come from caller.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
fn hit_alloc_failpoint(_: &str) -> bool {
    false
}
#[path = "../../../../provider/common/allocation.rs"]
mod allocation;
struct Payload([u8; 38]);
impl Drop for Payload {
    fn drop(&mut self) {
        self.0.fill(0);
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
fn main() {
    FAIL_NEXT.store(true, Ordering::SeqCst);
    let boxed = allocation::try_box(Payload([0xa5; 38]));
    assert!(boxed.is_none());
    assert!(!FAIL_NEXT.load(Ordering::SeqCst));
    assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    FAIL_NEXT.store(true, Ordering::SeqCst);
    let shared = allocation::Shared::try_new_at("allocator", Payload([0xa5; 38]));
    assert!(shared.is_none());
    assert!(!FAIL_NEXT.load(Ordering::SeqCst));
    assert_eq!(DROPS.load(Ordering::SeqCst), 2);
    let retry = allocation::Shared::try_new_at("allocator", Payload([0xa5; 38])).unwrap();
    drop(retry);
    assert_eq!(DROPS.load(Ordering::SeqCst), 3);
    println!("ALLOCATION_FAILURE=PASS");
}
