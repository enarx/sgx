// SPDX-License-Identifier: Apache-2.0

//! Enclave signature types
//!
//! This module contains types used to generate enclave signatures.
//!
//! Most likely, you will start with the `Hasher` to measure an enclave and
//! product the `MRENCLAVE` measurement. Then you will want to use the
//! `Parameters` type to create a `Body`. Finally, you will combine an
//! `Author` with the `Body` and an `RsaPrivateKey` to create a `Signature`.

mod author;
mod body;
mod hasher;

pub use author::Author;
pub use body::Body;
pub use hasher::{Hasher, InvalidSize};

use crate::crypto::PrivateKey;

/// A signature on an enclave
///
/// This structure encompasses the `SIGSTRUCT` structure from the SGX
/// documentation, renamed for ergonomics. The two portions of the
/// data that are included in the signature are further divided into
/// subordinate structures (`Author` and `Body`) for ease during
/// signature generation and validation.
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
    /// Signs the supplied `author` and `body` with the specified `key`.
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

    pub fn author(&self) -> Author {
        self.author
    }

    pub fn body(&self) -> Body {
        self.body
    }
}

#[cfg(test)]
testaso! {
    struct Signature: 4, 1808 => {
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
