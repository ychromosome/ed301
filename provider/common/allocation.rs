//! Shared fallible allocation from the bound Ed301-v1 provider.
//! Each including FFI module supplies its test-only allocation failpoint.

use core::{
    marker::PhantomData,
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering, fence},
};

struct SharedInner<T> {
    references: AtomicUsize,
    value: T,
}

/// Fallibly allocated, immutable provider state shared by keys and signature
/// contexts. This is deliberately narrower than `Arc`: it supports only
/// construction, immutable dereference and cloning, so key replacement keeps
/// snapshot semantics without copying the roughly 10-KiB verification table.
pub(crate) struct Shared<T> {
    inner: NonNull<SharedInner<T>>,
    marker: PhantomData<SharedInner<T>>,
}

impl<T> Shared<T> {
    pub(crate) fn try_new_at(site: &str, value: T) -> Option<Self> {
        let inner = try_box_at(
            site,
            SharedInner {
                references: AtomicUsize::new(1),
                value,
            },
        )?;
        let inner = NonNull::from(Box::leak(inner));
        Some(Self {
            inner,
            marker: PhantomData,
        })
    }

    #[cfg(test)]
    pub(crate) fn reference_count(&self) -> usize {
        // SAFETY: Every live Shared owns one reference to the allocation.
        unsafe { self.inner.as_ref() }
            .references
            .load(Ordering::Relaxed)
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        // SAFETY: `self` holds a live reference, so the allocation and counter
        // remain valid throughout this increment.
        let inner = unsafe { self.inner.as_ref() };
        let previous = inner.references.fetch_add(1, Ordering::Relaxed);
        if previous > isize::MAX as usize {
            std::process::abort();
        }
        Self {
            inner: self.inner,
            marker: PhantomData,
        }
    }
}

impl<T> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: A live Shared reference keeps the immutable value allocated.
        &unsafe { self.inner.as_ref() }.value
    }
}

impl<T> Drop for Shared<T> {
    fn drop(&mut self) {
        // SAFETY: `self` owns exactly one live reference to this allocation.
        let inner = unsafe { self.inner.as_ref() };
        if inner.references.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        // SAFETY: The final reference uniquely reclaims the original Box.
        drop(unsafe { Box::from_raw(self.inner.as_ptr()) });
    }
}

// SAFETY: Shared exposes immutable access only. Sending or sharing it is sound
// exactly when the stored value is both Send and Sync.
unsafe impl<T: Send + Sync> Send for Shared<T> {}
// SAFETY: Same invariant as the Send implementation above.
unsafe impl<T: Send + Sync> Sync for Shared<T> {}

/// Fallibly move `value` onto the heap.
///
/// Returns `None` instead of aborting the process when the global allocator
/// cannot satisfy the request; the moved value is dropped in that case, so
/// secret material still runs its zeroizing destructor.  Zero-sized types
/// never allocate and use a dangling, aligned pointer exactly as `Box::new`
/// does, so the returned box drops normally.
pub(crate) fn try_box<T>(value: T) -> Option<Box<T>> {
    let layout = std::alloc::Layout::new::<T>();
    if layout.size() == 0 {
        let pointer = core::ptr::NonNull::<T>::dangling().as_ptr();
        // SAFETY: For a zero-sized type any aligned dangling pointer is a
        // valid place to write the value.
        unsafe { core::ptr::write(pointer, value) };
        // SAFETY: `Box::from_raw` accepts a dangling aligned pointer for a
        // zero-sized type and takes ownership of the written value.
        return Some(unsafe { Box::from_raw(pointer) });
    }
    // SAFETY: `layout` has non-zero size.
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        drop(value);
        return None;
    }
    // SAFETY: `pointer` is non-null and was allocated with the layout of
    // `T`, so it is properly aligned, writable and uniquely owned here.
    unsafe { core::ptr::write(pointer, value) };
    // SAFETY: `pointer` now owns an initialized `T` obtained from the
    // global allocator, matching the `Box::from_raw` contract.
    Some(unsafe { Box::from_raw(pointer) })
}

/// Fallible heap allocation for one named externally reachable call site.
pub(crate) fn try_box_at<T>(site: &str, value: T) -> Option<Box<T>> {
    if super::hit_alloc_failpoint(site) {
        drop(value);
        return None;
    }
    try_box(value)
}
