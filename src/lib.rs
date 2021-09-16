// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![cfg_attr(feature = "asm", feature(asm))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::all)]

/// This macro enables writing tests for alignment, size, and offset of fields in structs.
/// Example usage:
/// testaso! {
///     struct mystruct: 8, 4096 => {
///         f1: 0,
///         f2: 8
///     }
/// }
#[cfg(test)]
macro_rules! testaso {
    (@off $name:path=>$field:ident) => {
        memoffset::offset_of!($name, $field)
    };

    ($(struct $name:path: $align:expr, $size:expr => { $($field:ident: $offset:expr),* })+) => {
        #[cfg(test)]
        #[test]
        fn align() {
            use core::mem::align_of;

            $(
                assert_eq!(
                    align_of::<$name>(),
                    $align,
                    "align: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn size() {
            use core::mem::size_of;

            $(
                assert_eq!(
                    size_of::<$name>(),
                    $size,
                    "size: {}",
                    stringify!($name)
                );
            )+
        }

        #[cfg(test)]
        #[test]
        fn offsets() {
            $(
                $(
                    assert_eq!(
                        testaso!(@off $name=>$field),
                        $offset,
                        "offset: {}::{}",
                        stringify!($name),
                        stringify!($field)
                    );
                )*
        )+
        }
    };
}

//pub mod attestation_types;

mod attr;
mod author;
mod crypto;
mod measure;
mod misc;
mod page;
mod secs;
mod ssa;

pub use attr::{Attributes, Features, Xfrm};
pub use author::Author;
pub use crypto::*;
pub use measure::{Masked, Measure, Parameters};
pub use misc::MiscSelect;
pub use page::{Class, Permissions, SecInfo};
pub use secs::Secs;
pub use ssa::{ExInfo, ExitType, GenPurposeRegs, Misc, StateSaveArea, Vector, XSave};

/// SGX ENCLU Leaf Instructions
pub mod enclu {
    pub const EREPORT: usize = 0x00;
    pub const EGETKEY: usize = 0x01;
    pub const EENTER: usize = 0x02;
    pub const ERESUME: usize = 0x03;
    pub const EEXIT: usize = 0x04;
    pub const EACCEPT: usize = 0x05;
    pub const EMODPE: usize = 0x06;
    pub const EACCEPTCOPY: usize = 0x07;
}

#[derive(Clone)]
struct RsaNumber([u8; Self::SIZE]);

impl RsaNumber {
    const SIZE: usize = 384;
}

impl core::fmt::Debug for RsaNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02x}", *b)?;
        }

        Ok(())
    }
}

impl Eq for RsaNumber {}
impl PartialEq for RsaNumber {
    fn eq(&self, rhs: &Self) -> bool {
        self.0[..] == rhs.0[..]
    }
}

/// The `Signature` on the enclave
///
/// This structure encompasses the `SIGSTRUCT` structure from the SGX
/// documentation, renamed for ergonomics. The two portions of the
/// data that are included in the signature are further divided into
/// subordinate structures (`Author` and `Contents`) for ease during
/// signature generation and validation.
///
/// Section 38.13
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    author: Author,
    modulus: RsaNumber,
    exponent: u32,
    signature: RsaNumber,
    measure: Measure,
    reserved: [u8; 12],
    q1: RsaNumber,
    q2: RsaNumber,
}

impl Signature {
    /// Get the enclave author
    pub fn author(&self) -> Author {
        self.author
    }

    /// Get the enclave measure
    pub fn measure(&self) -> Measure {
        self.measure
    }

    /// Read a `Signature` from a file
    #[cfg(any(test, feature = "std"))]
    pub fn read_from(mut reader: impl std::io::Read) -> std::io::Result<Self> {
        // # Safety
        //
        // This code is safe because we never read from the slice before it is
        // fully written to.

        let mut sig = std::mem::MaybeUninit::<Signature>::uninit();
        let ptr = sig.as_mut_ptr() as *mut u8;
        let len = std::mem::size_of_val(&sig);
        let buf = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        reader.read_exact(buf).unwrap();
        unsafe { Ok(sig.assume_init()) }
    }
}

#[cfg(test)]
testaso! {
    struct Signature: 8, 1808 => {
        author: 0,
        modulus: 128,
        exponent: 512,
        signature: 516,
        measure: 900,
        reserved: 1028,
        q1: 1040,
        q2: 1424
    }
}
