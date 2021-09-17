// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

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
pub mod platform;
pub mod signature;
pub mod ssa;

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
