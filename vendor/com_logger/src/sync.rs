use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct Mutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }

        MutexGuard { mutex: self }
    }
}

// SAFETY: The atomic lock guarantees exclusive mutable access to `value`, and
// requiring T: Send prevents sharing values that cannot cross thread contexts.
unsafe impl<T: Send> Sync for Mutex<T> {}

pub(crate) struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: A guard exists only after this mutex was exclusively locked.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The lock permits only one live guard, so mutable access is
        // exclusive until this guard is dropped.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::Mutex;

    #[test]
    fn guard_updates_value_and_unlocks_on_drop() {
        let mutex = Mutex::new(1);
        {
            let mut guard = mutex.lock();
            *guard = 2;
        }
        assert_eq!(*mutex.lock(), 2);
    }
}
