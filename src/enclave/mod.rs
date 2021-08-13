// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![allow(clippy::module_inception)]
#![cfg(feature = "crypto")]
#![cfg(feature = "std")]
#![cfg(feature = "asm")]

mod builder;
mod enclave;
mod ioctls;

pub use builder::*;
pub use enclave::*;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::page;
    use crate::types::tcs::Tcs;

    use std::num::NonZeroU32;

    use lset::Span;
    use primordial::Page;

    /// # Overview of an Enclave
    ///
    /// Enclaves are constructed from:
    ///
    ///   1. One or more pages of code and data. This is enclave contents.
    ///
    ///   2. One or more State Save Area (SSA) pages per thread. Each SSA page
    ///      enables one layer of exception handling. During an exception, the
    ///      CPU performs an asynchronous enclave exit (AEX) where it store the
    ///      CPU state in the current SSA page (CSSA) and then exits.
    ///
    ///   3. One Thread Control Structure (TCS) page per thread. Inside the
    ///      enclave, this page is accessed exclusively by the hardware. Each
    ///      TCS page contains the location and number of the thread's SSA
    ///      pages as well as address of the enclave to jump to when entering
    ///      (i.e. the entry point).

    // Our test enclave will have one code page, followed by one TCS page
    // followed by one SSA page.
    const CODE_OFFSET: usize = 0;
    const TCS_OFFSET: usize = 1;
    const SSA_OFFSET: usize = 2;
    const SSA_COUNT: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

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
        // Define the location and size of the enclave.
        let span = Span {
            start: 1 * 1024 * 1024 * 1024,
            count: 1 * 1024 * 1024,
        };

        // Instantiate the enclave builder.
        let mut builder = Builder::new(span).unwrap();

        // Copy the code, TCS and SSA pages into the enclave.
        let segs: [Segment; 3] = [
            Segment {
                /// # Safety
                /// Yes, it depends on undefined behavior. Yes, the pointer is
                /// unaligned. Yes, this is horrible. Sorry! However, this is
                /// the simplest way to copy the code function into a `Page`.
                /// TODO: make this not awful...
                src: vec![unsafe { *(code as *const Page) }],
                dst: span.start + CODE_OFFSET * Page::size(),
                si: page::SecInfo::reg(page::Flags::R | page::Flags::X),
            },
            Segment {
                src: vec![Page::copy(Tcs::new(
                    CODE_OFFSET * Page::size(),
                    SSA_OFFSET * Page::size(),
                    SSA_COUNT.get(),
                ))],
                dst: span.start + TCS_OFFSET * Page::size(),
                si: page::SecInfo::tcs(),
            },
            Segment {
                src: vec![Page::zeroed()],
                dst: span.start + SSA_OFFSET * Page::size(),
                si: page::SecInfo::reg(page::Flags::R | page::Flags::W),
            },
        ];
        builder.load(&segs).unwrap();

        // Build the enclave.
        let enclave = builder.build().unwrap();
        let mut thread = Thread::new(enclave).unwrap();

        // Set up the register to pass to the enclave.
        let mut registers = enclave::Registers {
            rdi: 1.into(),
            rsi: 2.into(),
            rdx: 3.into(),
            r8: 4.into(),
            r9: 5.into(),
        };

        // Enter the enclave.
        thread.enter(enclave::Entry::Enter, &mut registers).unwrap();

        // Validate that all registers are incremented.
        assert_eq!(
            registers,
            enclave::Registers {
                rdi: 2.into(),
                rsi: 3.into(),
                rdx: 4.into(),
                r8: 5.into(),
                r9: 6.into(),
            }
        );
    }
}
