// SPDX-License-Identifier: Apache-2.0

use crate::parameters::{Attributes, MiscSelect, Parameters};
use core::num::NonZeroU32;

impl Parameters {
    /// Creates a new `Secs` instance
    ///
    /// This creates a new instances of an SGX Enclave Control Structure (SECS)
    /// page using the specified `Parameters` along with the `base` address and
    /// `size` as well as the number of pages in an SSA frame.
    ///
    /// Note that the `Masked` types in `Parameters` are interpreted as follows:
    ///   * `data`: contains the features the enclave author desires
    ///   * `mask`: contains the features supported by this platform
    ///
    /// The intersection of these two sets forms the set of features enabled.
    pub fn secs(&self, base: *const (), size: usize, ssa_frame_pages: NonZeroU32) -> Secs {
        Secs {
            size: size as u64,
            baseaddr: base as u64,
            ssaframesize: ssa_frame_pages,
            miscselect: self.misc.data & self.misc.mask,
            reserved0: [0; 24],
            attributes: self.attr.data & self.attr.mask,
            mrenclave: [0; 32],
            reserved1: [0; 32],
            mrsigner: [0; 32],
            reserved2: [0; 12],
            pid: self.pid,
            svn: self.svn,
            reserved3: [0; 7],
            reserved4: [[0; 28]; 17],
        }
    }
}

/// SGX Enclave Control Structure (SECS) page
///
/// The contents of `Secs` are entirely opaque as this type is passed directly
/// to the hardware during enclave creation and never user readable.
#[derive(Copy, Clone)]
#[repr(C, align(4096))]
pub struct Secs {
    size: u64,
    baseaddr: u64,
    ssaframesize: NonZeroU32,
    miscselect: MiscSelect,
    reserved0: [u8; 24],
    attributes: Attributes,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    mrsigner: [u8; 32],
    reserved2: [u64; 12],
    pid: u16,
    svn: u16,
    reserved3: [u32; 7],
    reserved4: [[u64; 28]; 17],
}

impl core::fmt::Debug for Secs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secs")
            .field("size", &self.size)
            .field("baseaddr", &self.baseaddr)
            .field("ssaframesize", &self.ssaframesize)
            .field("miscselect", &self.miscselect)
            .field("attributes", &self.attributes)
            .field("pid", &self.pid)
            .field("svn", &self.svn)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::Secs;
    use testaso::testaso;

    testaso! {
        struct Secs: 4096, 4096 => {
            size: 0,
            baseaddr: 8,
            ssaframesize: 16,
            miscselect: 20,
            reserved0: 24,
            attributes: 48,
            mrenclave: 64,
            reserved1: 96,
            mrsigner: 128,
            reserved2: 160,
            pid: 256,
            svn: 258,
            reserved3: 260,
            reserved4: 288
        }
    }
}
