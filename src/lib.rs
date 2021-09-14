// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#![cfg_attr(feature = "asm", feature(asm, naked_functions))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::all)]
#![deny(missing_docs)]

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
mod isv;
mod misc;
mod page;
mod secs;
mod sig;

#[cfg(feature = "crypto")]
mod hasher;

pub use attr::{Attributes, Features, Xfrm};
pub use isv::{ProductId, SecurityVersion};
pub use misc::MiscSelect;
pub use page::{Class, Permissions, SecInfo};
pub use secs::Secs;
pub use sig::{Author, Masked, Measurement, Parameters, Signature};

#[cfg(feature = "crypto")]
pub use hasher::{Hasher, InvalidSize};

/// SGX ENCLU Leaf Instructions
#[allow(missing_docs)]
pub mod leaf {
    pub const EREPORT: usize = 0x00;
    pub const EGETKEY: usize = 0x01;
    pub const EENTER: usize = 0x02;
    pub const ERESUME: usize = 0x03;
    pub const EEXIT: usize = 0x04;
    pub const EACCEPT: usize = 0x05;
    pub const EMODPE: usize = 0x06;
    pub const EACCEPTCOPY: usize = 0x07;
}

#[cfg(all(test, feature = "crypto"))]
mod crypto {
    use super::*;

    use std::fs::File;
    use std::io::Read;
    use std::num::NonZeroU32;

    use openssl::{pkey, rsa};

    // A NOTE ABOUT THIS TESTING METHODOLOGY
    //
    // The ANSWER values in this test are not guaranteed to be correct.
    // They were produced by getting the hasher to output the same hash
    // for the binary from the Linux kernel SGX selftest and then running
    // the algorithm again to produce these ANSWERs. At least some of the
    // ANSWERs are correct. The remaining ones alert us to algorithmic
    // changes. We expect that over time our ANSWERs will be correct.
    //
    // The canonical source of correctness for this algorithm is, of
    // course, the Intel SGX CPU/microcode/ME. If you can demonstrate a
    // a case where we don't match this, we will happily change our ANSWERs.

    const DATA: [u8; PAGE] = [123u8; PAGE];
    const PAGE: usize = 4096;

    fn load(path: &str) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();

        let mut data = vec![0u8; size as usize];
        file.read_exact(&mut data).unwrap();

        data
    }

    fn loadkey(path: &str) -> rsa::Rsa<pkey::Private> {
        let pem = load(path);
        rsa::Rsa::private_key_from_pem(&pem).unwrap()
    }

    fn hash(input: &[(&[u8], SecInfo)]) -> Result<[u8; 32], InvalidSize> {
        // Add the lengths of all the enclave segments to produce enclave size.
        let size = input.iter().fold(0, |c, x| c + x.0.len());

        // Inputs:
        //   enclave size: the next power of two beyond our segments
        //      ssa pages: 1
        let ssa_pages = NonZeroU32::new(1).unwrap();
        let mut hasher = Hasher::new(size.next_power_of_two(), ssa_pages, Parameters::default());

        let mut off = 0;
        for i in input {
            hasher.load(i.0, off, i.1, true)?;
            off += i.0.len();
        }

        // Use default signature parameters
        Ok(hasher.finish().mrenclave())
    }

    #[test]
    fn badsize() {
        let question = hash(&[(&[1u8, 2, 3, 4], SecInfo::tcs())]);
        assert_eq!(question, Err(InvalidSize));
    }

    #[test]
    fn empty() {
        const ANSWER: [u8; 32] = [
            252, 149, 215, 52, 58, 111, 14, 95, 207, 19, 57, 38, 97, 120, 23, 26, 207, 44, 152, 5,
            72, 202, 97, 25, 204, 94, 10, 197, 188, 89, 246, 246,
        ];
        let question = hash(&[]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn tcs() {
        const ANSWER: [u8; 32] = [
            230, 83, 134, 171, 179, 130, 94, 239, 114, 13, 202, 111, 173, 126, 101, 185, 44, 96,
            129, 56, 92, 7, 246, 99, 17, 85, 245, 207, 201, 9, 51, 65,
        ];
        let question = hash(&[(&DATA, SecInfo::tcs())]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn r() {
        const ANSWER: [u8; 32] = [
            0, 117, 112, 212, 9, 215, 100, 12, 99, 30, 102, 236, 187, 103, 39, 144, 251, 33, 191,
            112, 25, 95, 140, 251, 201, 209, 113, 187, 15, 71, 15, 242,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Permissions::READ))]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn rw() {
        const ANSWER: [u8; 32] = [
            129, 184, 53, 91, 133, 145, 39, 205, 176, 182, 220, 37, 36, 198, 139, 91, 148, 181, 98,
            116, 22, 122, 174, 173, 173, 59, 39, 209, 165, 47, 8, 219,
        ];
        let question = hash(&[(&DATA, SecInfo::reg(Permissions::READ | Permissions::WRITE))]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn rwx() {
        const ANSWER: [u8; 32] = [
            175, 209, 233, 45, 48, 189, 118, 146, 139, 110, 63, 192, 56, 119, 66, 69, 246, 116,
            142, 206, 58, 97, 186, 173, 59, 110, 122, 19, 171, 237, 80, 6,
        ];
        let question = hash(&[(
            &DATA,
            SecInfo::reg(Permissions::READ | Permissions::WRITE | Permissions::EXECUTE),
        )]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn rx() {
        const ANSWER: [u8; 32] = [
            76, 207, 169, 240, 107, 1, 166, 236, 108, 53, 91, 107, 135, 238, 123, 132, 35, 246,
            230, 31, 254, 6, 3, 175, 35, 2, 39, 175, 114, 254, 73, 55,
        ];
        let question = hash(&[(
            &DATA,
            SecInfo::reg(Permissions::READ | Permissions::EXECUTE),
        )]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn long() {
        const LONG: [u8; PAGE * 2] = [123u8; PAGE * 2];
        const ANSWER: [u8; 32] = [
            233, 11, 17, 35, 117, 163, 196, 106, 142, 137, 169, 130, 108, 108, 51, 5, 29, 241, 152,
            190, 9, 245, 27, 16, 85, 173, 17, 90, 43, 124, 46, 84,
        ];
        let question = hash(&[
            (&DATA, SecInfo::tcs()),
            (&LONG, SecInfo::reg(Permissions::READ)),
        ]);
        assert_eq!(question, Ok(ANSWER));
    }

    #[test]
    fn selftest() {
        let bin = load("tests/encl.bin");
        let sig = Signature::read_from(File::open("tests/encl.ss").unwrap()).unwrap();
        let key = loadkey("tests/encl.pem");

        let mut tcs = [0u8; PAGE];
        let mut src = vec![0u8; (bin.len() - 1) / PAGE * PAGE];

        let dst = unsafe { tcs.align_to_mut::<u8>().1 };
        dst.copy_from_slice(&bin[..PAGE]);

        let dst = unsafe { src.align_to_mut::<u8>().1 };
        dst.copy_from_slice(&bin[PAGE..]);

        // Validate the hash.
        let rwx = Permissions::READ | Permissions::WRITE | Permissions::EXECUTE;
        assert_eq!(
            sig.measurement().mrenclave(),
            hash(&[(&tcs, SecInfo::tcs()), (&src, SecInfo::reg(rwx))]).unwrap(),
            "failed to produce correct mrenclave hash"
        );

        // Ensure that sign() can reproduce the exact same signature struct.
        assert_eq!(
            sig,
            sig.measurement().sign(sig.author(), key).unwrap(),
            "failed to produce correct signature"
        );
    }
}
