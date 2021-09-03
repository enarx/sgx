// SPDX-License-Identifier: Apache-2.0

//! Thread Control Structure (Section 38.8)
//! Each executing thread in the enclave is associated with a Thread Control Structure.

bitflags::bitflags! {
    /// Section 38.8.1
    #[derive(Default)]
    #[repr(transparent)]
    pub struct Flags: u64 {
        /// Allows debugging features while executing in the enclave on this TCS. Hardware clears this bit on EADD.
        const DBGOPTIN = 1 << 0;
    }
}

/// Thread Control Structure (TCS) is an enclave page visible in its address
/// space that defines an entry point inside the enclave. A thread enters inside
/// an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
/// by only one thread at a time.
///
/// Section 38.8
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct Tcs {
    state: u64,    // Used to mark an entered TCS
    flags: Flags,  // Execution flags (cleared by EADD)
    ossa: u64,     // SSA stack offset relative to the enclave base
    cssa: u32,     // The current SSA frame index (cleared by EADD)
    nssa: u32,     // The number of frames in the SSA stack
    oentry: u64,   // Entry point offset relative to the enclave base
    aep: u64,      // Address outside enclave to exit on an exception or interrupt
    ofsbasgx: u64, // Offset relative to enclave base to become FS segment inside the enclave
    ogsbasgx: u64, // Offset relative to enclave base to become GS segment inside the enclave
    fslimit: u32,  // Size to become a new FS-limit (only 32-bit enclaves)
    gslimit: u32,  // Size to become a new GS-limit (only 32-bit enclaves)
    padding: [u64; 503],
}

impl Tcs {
    /// Creates a new TCS page
    ///
    /// This method takes three parameters.
    ///
    /// 1. `entry` - The offset in the enclave to jump to on enclave entry.
    /// 2. `ossa` - The offset in the enclave for the SSA frames.
    /// 3. `nssa` - The number of frames at the `ssa` offset.
    ///
    /// Note that while the size of each frame is determined during enclave
    /// creation, each thread (i.e. TCS page) can have a different number of
    /// SSA frames.
    pub const fn new(entry: usize, ossa: usize, nssa: u32) -> Self {
        Self {
            state: 0,
            flags: Flags::empty(),
            ossa: ossa as _,
            cssa: 0,
            nssa,
            oentry: entry as _,
            aep: 0,
            ofsbasgx: 0,
            ogsbasgx: 0,
            fslimit: !0,
            gslimit: !0,
            padding: [0; 503],
        }
    }
}

#[cfg(test)]
testaso! {
    struct Tcs: 4096, 4096 => {
        state: 0,
        flags: 8,
        ossa: 16,
        cssa: 24,
        nssa: 28,
        oentry: 32,
        aep: 40,
        ofsbasgx: 48,
        ogsbasgx: 56,
        fslimit: 64,
        gslimit: 68,
        padding: 72
    }
}
