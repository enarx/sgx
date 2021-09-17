// SPDX-License-Identifier: Apache-2.0

//! This crate contains types for building an Intel SGX implementation.
//!
//! Fully understanding the contents of this crate will likely require access
//! to the [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html).
//!
//! How to use this crate partly depends on what you are trying to accomplish:
//!
//!   1. If you are an enclave developer, you probably want the `parameters`
//!      and `ssa` modules.
//!   2. If you are signing an enclave, you probably want the `signature` and
//!      `crypto` modules.
//!   3. If you are developing an enclave loader, you probably want the
//!      `parameters` and `page` modules. However, you may also want the
//!      `signature` module to load a signature.

#![cfg_attr(not(test), no_std)]
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

pub mod crypto;
pub mod page;
pub mod parameters;
pub mod signature;
pub mod ssa;

#[cfg(target_arch = "x86_64")]
pub mod platform;

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
