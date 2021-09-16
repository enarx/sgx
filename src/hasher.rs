// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

use crate::{Measurement, Parameters, SecInfo};

use openssl::sha;

use core::num::NonZeroU32;
use core::slice::from_raw_parts;

const PAGE: usize = 4096;

/// Input length is not a multiple of the page size
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct InvalidSize;

/// This struct creates and updates the MRENCLAVE value associated
/// with an enclave's Signature (or SIGSTRUCT). This value is updated with
/// each ECREATE, EADD, or EEXTEND operation as documented in 41.3 and as
/// summarized at https://github.com/enarx/enarx/wiki/SGX-Measurement. The leaf
/// functions are mimicked to obtain these values, but are not actually called here;
/// to use them, refer to the [iocuddle-sgx](../../iocuddle-sgx) library.
pub struct Hasher(sha::Sha256, Parameters);

impl Hasher {
    /// Mimics call to SGX_IOC_ENCLAVE_CREATE (ECREATE).
    pub fn new(size: usize, ssa_frame_pages: NonZeroU32, parameters: Parameters) -> Self {
        let size = size as u64;

        // This value documented in 41.3.
        const ECREATE: u64 = 0x0045544145524345;

        let mut sha256 = sha::Sha256::new();
        sha256.update(&ECREATE.to_le_bytes());
        sha256.update(&ssa_frame_pages.get().to_le_bytes());
        sha256.update(&size.to_le_bytes());
        sha256.update(&[0u8; 44]); // Reserved

        Self(sha256, parameters)
    }

    /// Hashes pages as if they were loaded via EADD/EEXTEND
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

    /// Produces MRENCLAVE value by hashing with SHA256.
    pub fn finish(self) -> Measurement {
        self.1.measurement(self.0.finish())
    }
}
