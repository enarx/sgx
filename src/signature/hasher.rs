// SPDX-License-Identifier: Apache-2.0

use crate::{crypto::Digest, page::SecInfo};

use core::num::NonZeroU32;
use core::slice::from_raw_parts;

/// Input length is not a multiple of the page size
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct InvalidSize;

/// Hashes an enclave producing a measurement
///
/// This structure simulates the enclave creation process and produces an
/// `MRENCLAVE` value (the enclave measurement) just like the firmware will do
/// during enclave creation. This permits the creation and validation of
/// measurements even when not on a system supporting SGX.
///
/// In order to create a measurement, you should create an instance using
/// `Hasher::new()`. Then you should call `Hasher::load()` for all enclave
/// segments. Finally, you should call `Hasher::finish()` to produce the
/// `MRENCLAVE` value.
pub struct Hasher<T: Digest>(T);

impl<T: Digest> Hasher<T> {
    /// Create a hasher instance
    pub fn new(size: usize, ssa_frame_pages: NonZeroU32) -> Self {
        let size = size as u64;

        // This value documented in 41.3.
        const ECREATE: u64 = 0x0045544145524345;

        let mut digest = T::new();
        digest.update(&ECREATE.to_le_bytes());
        digest.update(&ssa_frame_pages.get().to_le_bytes());
        digest.update(&size.to_le_bytes());
        digest.update(&[0u8; 44]); // Reserved
        Self(digest)
    }

    /// Simulate segment loading
    ///
    /// Call this function once per segment. Note that segment sizes **MUST**
    /// be a multiple of the page size.
    pub fn load(
        &mut self,
        pages: &[u8],
        mut offset: usize,
        secinfo: SecInfo,
        measure: bool,
    ) -> Result<(), InvalidSize> {
        // These values documented in 41.3.
        const EEXTEND: u64 = 0x00444E4554584545;
        const EADD: u64 = 0x0000000044444145;
        const PAGE: usize = 4096;

        if pages.len() % PAGE != 0 {
            return Err(InvalidSize);
        }

        // For each page in the input...
        for page in pages.chunks(PAGE) {
            // Hash for the EADD instruction.
            let si = &secinfo as *const _ as *const u8;
            self.0.update(&EADD.to_le_bytes());
            self.0.update(&(offset as u64).to_le_bytes());
            self.0.update(unsafe { from_raw_parts(si, 48) });

            // Hash for the EEXTEND instruction.
            if measure {
                let mut off = offset;
                for segment in page.chunks(256) {
                    self.0.update(&EEXTEND.to_le_bytes());
                    self.0.update(&(off as u64).to_le_bytes());
                    self.0.update(&[0u8; 48]);
                    self.0.update(segment);
                    off += segment.len();
                }
            }

            offset += page.len();
        }

        Ok(())
    }

    /// Produce the `MRENCLAVE` value
    pub fn finish(self) -> T::Output {
        self.0.finish()
    }
}

#[cfg(test)]
mod test {
    use core::num::NonZeroU32;

    use super::{Hasher, InvalidSize};
    use crate::crypto::Digest;
    use crate::page::SecInfo;

    struct Dummy;

    impl Digest for Dummy {
        type Output = [u8; 32];

        fn new() -> Self {
            Self
        }

        fn update(&mut self, _: &[u8]) {}

        fn finish(self) -> Self::Output {
            Default::default()
        }
    }

    #[test]
    fn badsize() {
        let pages = NonZeroU32::new(1).unwrap();
        let mut hasher = Hasher::<Dummy>::new(1 << 20, pages);

        let buf = [0; 4096];
        for i in 1..4096 {
            assert_eq!(
                hasher.load(&buf[i..], 0, SecInfo::tcs(), true),
                Err(InvalidSize)
            );
        }

        assert_eq!(hasher.load(&buf, 0, SecInfo::tcs(), true), Ok(()));
    }
}
