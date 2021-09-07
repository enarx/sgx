// SPDX-License-Identifier: Apache-2.0

//! # Overview of an Enclave
//!
//! Enclaves are constructed from:
//!
//!   1. One or more pages of code and data. This is the enclave contents.
//!
//!   2. One or more State Save Area (SSA) frames per thread. Each SSA frame
//!      enables one layer of exception handling. During an exception, the
//!      CPU performs an asynchronous enclave exit (AEX) where it store the
//!      CPU state in the current SSA frame (CSSA) and then exits.
//!
//!   3. One Thread Control Structure (TCS) page per thread. Inside the
//!      enclave, this page is accessed exclusively by the hardware. Each
//!      TCS page contains the location and number of the thread's SSA
//!      frames as well as the address of the enclave to jump to when
//!      entering (i.e. the entry point).
//!
//! # Building an Enclave
//!
//! This `Builder` object will help you construct an enclave. First, you will
//! instantiate the `Builder` using `Builder::new()` or `Builder::new_at()`.
//! Next, you will add all the relevant pages using the `Loader::load()`
//! trait method. Finally, you will call `Builder::build()` to verify the
//! enclave signature and finalize the enclave construction.
//!
//! # Executing an Enclave
//!
//! Once you have built an `Enclave` you will want to execute it. This is done
//! by creating a new `Thread` object using `Enclave::spawn()`. Once you have
//! a `Thread` object, you can use `Thread::enter()` to enter the enclave,
//! passing the specified registers. When the enclave returns, you can read
//! the register state from the same structure.
//!
//! # Additional Information
//!
//! The Intel SGX documentation is available [here]. Section references in
//! further documentation refer to this document.
//!
//! [here]: https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![cfg(feature = "crypto")]
#![cfg(feature = "std")]
#![cfg(feature = "asm")]

mod builder;
mod execute;
mod ioctls;

pub use builder::Builder;
pub use execute::{Entry, ExceptionInfo, InterruptVector, Registers};

use std::sync::{Arc, RwLock};

use mmarinus::{perms, Map};
use vdso::Symbol;

/// A full initialized enclave
///
/// To begin execution in this enclave, create a new `Thread` object using
/// `Enclave::spawn()`.
pub struct Enclave {
    _mem: Map<perms::Unknown>,
    tcs: RwLock<Vec<usize>>,
}

impl Enclave {
    /// Create a new thread of execuation for an enclave.
    ///
    /// Note that this method does not create a system thread. If you want to
    /// execute multiple enclave threads in parallel, you'll need to spawn
    /// operating system threads in addition to this thread object.
    pub fn spawn(self: Arc<Enclave>) -> Option<Thread> {
        let fnc = vdso::Vdso::locate()
            .expect("vDSO not found")
            .lookup("__vdso_sgx_enter_enclave")
            .expect("__vdso_sgx_enter_enclave not found");

        let tcs = self.tcs.write().unwrap().pop()?;
        Some(Thread {
            enc: self,
            tcs,
            fnc,
        })
    }
}

/// A single thread of execution inside an enclave
///
/// You can begin enclave execution using `Thread::enter()`.
pub struct Thread {
    enc: Arc<Enclave>,
    tcs: usize,
    fnc: &'static Symbol,
}

impl Drop for Thread {
    fn drop(&mut self) {
        self.enc.tcs.write().unwrap().push(self.tcs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::Hasher;
    use crate::loader::{Flags, Loader};
    use crate::types::page;
    use crate::types::sig::{Author, Parameters};

    use std::num::NonZeroU32;

    use openssl::{bn, rsa};
    use primordial::Page;

    #[derive(Copy, Clone, Debug)]
    #[repr(C, align(4096))]
    pub struct Tcs {
        state: u64,    // Used to mark an entered TCS
        flags: u64,    // Execution flags (cleared by EADD)
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
        pub const fn new(entry: usize, ossa: usize, nssa: u32) -> Self {
            Self {
                state: 0,
                flags: 0,
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

    // Our test enclave will have one code page, followed by one TCS page
    // followed by one SSA page.
    const CODE_OFFSET: usize = 0;
    const TCS_OFFSET: usize = 1;
    const SSA_OFFSET: usize = 2;
    const SSA_COUNT: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };
    const ENCLAVE_SIZE: usize = 1 * 1024 * 1024;

    /// This function contains the contents of the enclave. It is page-sized.
    /// Ideally, it would be page aligned as well. However, Rust does not
    /// currently support function alignement.
    ///
    /// The intent of this function is to increment the 5 registers that our
    /// API allows to be passed in/out of enclaves.
    ///
    /// Don't call this function directly. It has a non-standard ABI.
    #[naked]
    unsafe extern "C" fn code() -> ! {
        asm!(
            "2:",
            "inc rdi", // Increment all the registers.
            "inc rsi",
            "inc rdx",
            "inc r8",
            "inc r9",
            "xchg rbx, rcx", // Get the exit address in RBX.
            "mov rax, 0x04", // Set RAX = EEXIT.
            "enclu",         // Do the exit.
            "3:",
            ".fill((4096 - (3b - 2b)))", // Ensure the code function is page-sized.
            options(noreturn)
        )
    }

    #[test]
    #[cfg_attr(not(has_sgx), ignore)]
    fn test() {
        // Create the signature parameters, the builder and the hasher.
        let parameters = Parameters::default();
        let mut builder = Builder::new(ENCLAVE_SIZE, SSA_COUNT, parameters).unwrap();
        let mut hasher = Hasher::new(ENCLAVE_SIZE, SSA_COUNT, parameters);

        // Add the code page.
        // # Safety
        // Yes, it depends on undefined behavior. Yes, the pointer is
        // unaligned. Yes, this is horrible. Sorry! However, this is
        // the simplest way to copy the code function into a `Page`.
        // TODO: make this not awful...
        let pages = unsafe { [*(code as *const Page)] };
        let secinfo = page::SecInfo::reg(page::Flags::R | page::Flags::X);
        builder
            .load(pages, CODE_OFFSET, secinfo, Flags::Measure)
            .unwrap();
        hasher
            .load(pages, CODE_OFFSET, secinfo, Flags::Measure)
            .unwrap();

        // Add the TCS page.
        let tcs = Tcs::new(
            CODE_OFFSET * Page::SIZE,
            SSA_OFFSET * Page::SIZE,
            SSA_COUNT.get(),
        );
        let pages = [unsafe { std::mem::transmute(tcs) }; 1];
        let secinfo = page::SecInfo::tcs();
        builder
            .load(pages, TCS_OFFSET, secinfo, Flags::Measure)
            .unwrap();
        hasher
            .load(pages, TCS_OFFSET, secinfo, Flags::Measure)
            .unwrap();

        // Add the SSA page.
        let pages = [Page::zeroed()];
        let secinfo = page::SecInfo::reg(page::Flags::R | page::Flags::W);
        builder
            .load(pages, SSA_OFFSET, secinfo, Flags::Measure)
            .unwrap();
        hasher
            .load(pages, SSA_OFFSET, secinfo, Flags::Measure)
            .unwrap();

        // Generate a signing key.
        let exp = bn::BigNum::from_u32(3u32).unwrap();
        let key = rsa::Rsa::generate_with_e(3072, &exp).unwrap();

        // Create the enclave signature
        let vendor = Author::new(0, 0);
        let signature = hasher.finish().sign(vendor, key).unwrap();

        // Build the enclave.
        let enclave = builder.build(&signature).unwrap();
        let mut thread = enclave.spawn().unwrap();

        // Set up the register to pass to the enclave.
        let mut registers = Registers {
            rdi: 1.into(),
            rsi: 2.into(),
            rdx: 3.into(),
            r8: 4.into(),
            r9: 5.into(),
        };

        // Enter the enclave.
        thread.enter(Entry::Enter, &mut registers).unwrap();

        // Validate that all registers are incremented.
        assert_eq!(
            registers,
            Registers {
                rdi: 2.into(),
                rsi: 3.into(),
                rdx: 4.into(),
                r8: 5.into(),
                r9: 6.into(),
            }
        );
    }
}
