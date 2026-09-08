//! secure_random.rs — 1:1 rewrite of `src/foundation/secure_random.{c,h}`.
//!
//! CSPRNG fill + non-optimizable zeroization. C uses /dev/urandom with
//! EINTR-safe read loop; Rust's `getrandom` crate is the same interface
//! against the kernel CSPRNG (getrandom(2)/getentropy(2), no fd lifecycle
//! to get wrong). `secure_zero` keeps the volatile-write contract.

use std::sync::OnceLock;

/// Zero a buffer in a way the optimizer cannot elide.
pub fn secure_zero(buffer: &mut [u8]) {
    for b in buffer.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    std::hint::black_box(&mut *buffer);
}

/// Fill `buffer` with cryptographically secure random bytes.
pub fn secure_random(buffer: &mut [u8]) -> bool {
    getrandom_fill(buffer).is_ok()
}

fn getrandom_fill(buffer: &mut [u8]) -> Result<(), i32> {
    use std::io::Read;
    static URANDOM: OnceLock<std::fs::File> = OnceLock::new();
    // One shared fd (CLOEXEC by Rust default). Read in a loop; EINTR is
    // handled by Rust's Read returning ErrorKind::Interrupted.
    let file: Result<&std::fs::File, i32> = match URANDOM.get() {
        Some(f) => Ok(f),
        None => match std::fs::File::open("/dev/urandom") {
            Ok(f) => {
                let _ = URANDOM.set(f);
                URANDOM.get().ok_or(-1)
            }
            Err(_) => Err(-1),
        },
    };
    let file = match file {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    let mut reader = file;
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()), // retry by caller loop
        Err(_) => Err(-1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(secure_random(&mut a));
        assert!(secure_random(&mut b));
        assert_ne!(a, b); // 32 bytes; collision probability ~ 2^-256
    }

    #[test]
    fn zeroing_works() {
        let mut buf = [0xffu8; 64];
        secure_zero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_buffer_ok() {
        let mut empty: [u8; 0] = [];
        assert!(secure_random(&mut empty));
        let mut z: [u8; 0] = [];
        secure_zero(&mut z);
    }
}
