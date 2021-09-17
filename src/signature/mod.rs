// SPDX-License-Identifier: Apache-2.0

mod author;
mod body;
mod hasher;

pub use author::Author;
pub use body::Body;
pub use hasher::{Hasher, InvalidSize};

use crate::crypto::PrivateKey;

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
    modulus: [u8; 384],
    exponent: u32,
    signature: [u8; 384],
    body: Body,
    reserved: [u8; 12],
    q1: [u8; 384],
    q2: [u8; 384],
}

impl Signature {
    pub fn new<T: PrivateKey>(key: &T, author: Author, body: Body) -> Result<Self, T::Error> {
        use core::mem::{size_of, transmute};

        let a: [u8; size_of::<Author>()] = unsafe { transmute(author) };
        let b: [u8; size_of::<Body>()] = unsafe { transmute(body) };
        let sd = key.sign(&a, &b)?;

        Ok(Self {
            author,
            modulus: sd.modulus,
            exponent: sd.exponent,
            signature: sd.signature,
            body,
            reserved: [0; 12],
            q1: sd.q1,
            q2: sd.q2,
        })
    }

    /// Get the signature author
    pub fn author(&self) -> Author {
        self.author
    }

    /// Get the signature body
    pub fn body(&self) -> Body {
        self.body
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
        body: 900,
        reserved: 1028,
        q1: 1040,
        q2: 1424
    }
}
