//! Isolated tests of the unchanged provider ownership implementation.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use std::cell::Cell;

thread_local! {
    static FAIL_SITE: Cell<Option<&'static str>> = const { Cell::new(None) };
}

fn hit_alloc_failpoint(site: &str) -> bool {
    FAIL_SITE.with(|value| {
        if value.get() == Some(site) {
            value.set(None);
            true
        } else {
            false
        }
    })
}

#[path = "../../../provider/common/allocation.rs"]
mod allocation;

#[cfg(test)]
mod tests {
    use super::{
        FAIL_SITE,
        allocation::{Shared, try_box},
    };
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };

    struct Probe {
        bytes: [u8; 38],
        drops: Arc<AtomicUsize>,
    }
    impl Probe {
        fn new(drops: &Arc<AtomicUsize>) -> Self {
            Self {
                bytes: [0xa5; 38],
                drops: drops.clone(),
            }
        }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            // Tests destructor execution/order, not optimized memory erasure.
            self.bytes.fill(0);
            assert_eq!(self.bytes, [0; 38]);
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn boxed_value_and_alignment() {
        #[repr(align(256))]
        struct Aligned([u8; 38]);
        let boxed = try_box(Aligned([7; 38])).unwrap();
        assert_eq!((&*boxed as *const Aligned).addr() % 256, 0);
        assert_eq!(boxed.0, [7; 38]);
    }

    #[test]
    fn zero_sized_value_drops_once() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Zst;
        impl Drop for Zst {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        let before = DROPS.load(Ordering::SeqCst);
        drop(try_box(Zst).unwrap());
        assert_eq!(DROPS.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn aligned_zero_sized_value() {
        #[repr(align(512))]
        struct AlignedZst;
        let boxed = try_box(AlignedZst).unwrap();
        assert_eq!((&*boxed as *const AlignedZst).addr() % 512, 0);
        drop(boxed);
    }

    #[test]
    fn clones_keep_value_alive_until_last_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let first = Shared::try_new_at("test", Probe::new(&drops)).unwrap();
        let second = first.clone();
        assert_eq!(first.reference_count(), 2);
        assert!(std::ptr::eq(&*first, &*second));
        drop(first);
        assert_eq!(second.bytes, [0xa5; 38]);
        assert_eq!(second.reference_count(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(second);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn many_clones_and_non_fifo_drop_order() {
        let drops = Arc::new(AtomicUsize::new(0));
        let first = Shared::try_new_at("test", Probe::new(&drops)).unwrap();
        let count = if cfg!(miri) { 16 } else { 4096 };
        let mut copies: Vec<_> = (0..count).map(|_| first.clone()).collect();
        assert_eq!(first.reference_count(), count + 1);
        drop(first);
        while copies.len() > 1 {
            drop(copies.swap_remove(copies.len() / 2));
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(copies[0].bytes, [0xa5; 38]);
        drop(copies);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn named_allocation_failure_drops_payload_and_allows_retry() {
        let drops = Arc::new(AtomicUsize::new(0));
        FAIL_SITE.with(|site| site.set(Some("fail")));
        assert!(Shared::try_new_at("fail", Probe::new(&drops)).is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let value = Shared::try_new_at("fail", Probe::new(&drops)).unwrap();
        drop(value);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn unwind_releases_only_its_own_reference() {
        let drops = Arc::new(AtomicUsize::new(0));
        let first = Shared::try_new_at("test", Probe::new(&drops)).unwrap();
        let copy = first.clone();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _held = copy;
            panic!("controlled unwind");
        }));
        assert!(result.is_err());
        assert_eq!(first.reference_count(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panicking_payload_drop_still_reclaims_allocation() {
        struct Panics(Arc<AtomicUsize>);
        impl Drop for Panics {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("controlled destructor panic");
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let value = Shared::try_new_at("test", Panics(drops.clone())).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| drop(value))).is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        // Miri's leak checker verifies the allocation is reclaimed on unwind.
    }

    #[test]
    fn concurrent_clone_read_and_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let value = Shared::try_new_at("test", Probe::new(&drops)).unwrap();
        let start = Arc::new(Barrier::new(4));
        let mut threads = Vec::new();
        for _ in 0..3 {
            let value = value.clone();
            let start = start.clone();
            threads.push(thread::spawn(move || {
                start.wait();
                for _ in 0..if cfg!(miri) { 4 } else { 10_000 } {
                    let another = value.clone();
                    assert_eq!(another.bytes, [0xa5; 38]);
                    thread::yield_now();
                    drop(another);
                }
            }));
        }
        drop(value);
        start.wait();
        for worker in threads {
            worker.join().unwrap();
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_drop_observes_writes_before_other_releases() {
        struct Published {
            written: [AtomicBool; 3],
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Published {
            fn drop(&mut self) {
                for flag in &self.written {
                    assert!(flag.load(Ordering::Relaxed));
                }
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let value = Shared::try_new_at(
            "test",
            Published {
                written: std::array::from_fn(|_| AtomicBool::new(false)),
                drops: drops.clone(),
            },
        )
        .unwrap();
        let mut threads = Vec::new();
        for i in 0..3 {
            let copy = value.clone();
            threads.push(thread::spawn(move || {
                copy.written[i].store(true, Ordering::Relaxed);
                drop(copy);
            }));
        }
        // No join before the final-reference contenders release their values.
        drop(value);
        for worker in threads {
            worker.join().unwrap();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn send_sync_for_thread_safe_payloads() {
        fn require<T: Send + Sync>() {}
        require::<Shared<AtomicUsize>>();
        require::<Shared<Probe>>();
    }
}
