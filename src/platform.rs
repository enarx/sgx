// SPDX-License-Identifier: Apache-2.0

use crate::parameters::{Attributes, Features, MiscSelect, Xfrm};

bitflags::bitflags! {
    /// Features of SGX supported by the platform
    pub struct Facets: u64 {
        /// SGX Version 1 instructions are available
        const V1 = 1 << 0;

        /// SGX Version 2 instructions are available
        const V2 = 1 << 1;

        /// Flexible Launch Control is available
        const FLC = 1 << 63;
    }
}

/// The platform's SGX support details
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    pub facets: Facets,
    pub bits32: u8,
    pub bits64: u8,
    reserved0: [u8; 2],
    pub misc: MiscSelect,
    pub attr: Attributes,
    pub epcs: u64,
    reserved1: [u64; 11],
}

impl Platform {
    /// Returns information about this Platform's support for SGX
    ///
    /// # Safety
    ///
    /// This function is unsafe because it calls the `CPUID` instruction.
    pub unsafe fn scan() -> Option<Self> {
        use core::arch::x86_64::__cpuid_count as cpuid;

        // Sanity check
        let res = cpuid(0x00000000, 0x00000000);
        let max = res.eax;
        let name: [u8; 12] = core::mem::transmute([res.ebx, res.edx, res.ecx]);
        if &name != b"GenuineIntel" || max < 0x00000012 {
            return None;
        }

        // Determine if SGX and/or FLC are supported.
        let res = cpuid(0x00000007, 0x00000000);
        let sgx = res.ebx & (1 << 2) != 0;
        let flc = (res.ecx as u64 & (1 << 30)) << 33;
        if !sgx {
            return None;
        }

        // Get SGX version, max enclave sizes and MISC
        let res = cpuid(0x00000012, 0x00000000);
        let vers = res.eax as u64 & 0b11;
        let bt32 = res.edx as u8;
        let bt64 = (res.edx >> 8 & 0xff) as u8;
        let misc = MiscSelect::from_bits_truncate(res.ebx);

        // Get the SGX attributes
        let res = cpuid(0x00000012, 0x00000001);
        let feat = Features::from_bits_truncate((res.ebx as u64) << 32 | res.eax as u64);
        let xfrm = Xfrm::from_bits_truncate((res.edx as u64) << 32 | res.ecx as u64);

        // Calculate the size of the EPC
        let mut epcs = 0;
        for i in 2.. {
            let result = cpuid(0x00000012, i);
            if result.eax & 0xf != 1 {
                break;
            }

            let low = result.ecx as u64 & 0xfffff000;
            let high = result.edx as u64 & 0x000fffff;
            epcs += high << 12 | low;
        }

        Some(Self {
            facets: Facets::from_bits_truncate(vers | flc),
            bits32: bt32,
            bits64: bt64,
            reserved0: [0; 2],
            misc,
            attr: Attributes::new(feat, xfrm),
            epcs,
            reserved1: [0; 11],
        })
    }
}

#[cfg(test)]
testaso! {
    struct Platform: 8, 128 => {
        facets: 0,
        bits32: 8,
        bits64: 9,
        reserved0: 10,
        misc: 12,
        attr: 16,
        epcs: 32,
        reserved1: 40
    }
}
