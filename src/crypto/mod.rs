// SPDX-License-Identifier: Apache-2.0

//! Cryptography backends
//!
//! This module contains traits for implementing cryptography. It also contains
//! some cryptography backends (see the `openssl` and `rcrypto` crate features).

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(feature = "rcrypto")]
pub mod rcrypto;

/// A fixed-size hash
pub trait Digest: Sized {
    type Output: AsRef<[u8]>;

    fn new() -> Self;
    fn update(&mut self, bytes: &[u8]);
    fn finish(self) -> Self::Output;

    #[inline]
    fn chain(mut self, bytes: &[u8]) -> Self {
        self.update(bytes);
        self
    }
}

/// A private key used for signing an enclave
pub trait PrivateKey: Sized {
    type Error: core::fmt::Debug;

    fn generate(exponent: u8) -> Result<Self, Self::Error>;
    fn from_pem(pem: &str) -> Result<Self, Self::Error>;
    fn from_der(der: &[u8]) -> Result<Self, Self::Error>;
    fn sign(&self, author: &[u8], body: &[u8]) -> Result<SigData, Self::Error>;
}

/// A detached enclave signature
pub struct SigData {
    pub signature: [u8; 384],
    pub modulus: [u8; 384],
    pub exponent: u32,
    pub q1: [u8; 384],
    pub q2: [u8; 384],
}

#[cfg(test)]
#[allow(dead_code)]
fn selftest<K: PrivateKey, D: Digest<Output = [u8; 32]>>() {
    const SIG: &[u8; size_of::<Signature>()] = include_bytes!("../../tests/encl.ss");
    const BIN: &[u8] = include_bytes!("../../tests/encl.bin");
    const PEM: &str = include_str!("../../tests/encl.pem");
    const PAGE: usize = 4096;

    use core::mem::{size_of, transmute};
    use core::num::NonZeroU32;

    use crate::page::{Class, Flags, SecInfo};
    use crate::parameters::{Attributes, Features, Masked, Parameters, Xfrm};
    use crate::signature::{Author, Hasher, Signature};

    let len = BIN.len().next_power_of_two();
    let sig: Signature = unsafe { transmute(*SIG) };
    let rwx = Flags::READ | Flags::WRITE | Flags::EXECUTE;

    // Validate hash generation
    let mut h = Hasher::<D>::new(len, NonZeroU32::new(1).unwrap());
    h.load(&BIN[..PAGE], 0, SecInfo::from(Class::Tcs), true)
        .unwrap();
    h.load(&BIN[PAGE..], PAGE, Class::Regular.info(rwx), true)
        .unwrap();
    let mrenclave = h.finish();
    assert_eq!(sig.body().mrenclave(), mrenclave);

    // Validate object construction
    let parameters = Parameters {
        attr: Masked {
            data: Attributes::new(Features::MODE64BIT, Xfrm::X87 | Xfrm::SSE),
            mask: Attributes::new(Features::empty(), Xfrm::empty()),
        },
        ..Default::default()
    };
    let body = parameters.body(mrenclave);
    assert_eq!(Author::new(0, 0), sig.author());
    assert_eq!(parameters, sig.body().parameters());
    assert_eq!(parameters.body(mrenclave), sig.body());

    // Validate signature generation
    let key = K::from_pem(PEM).unwrap();
    assert_eq!(sig, Signature::new(&key, sig.author(), sig.body()).unwrap());
    assert_eq!(sig, Signature::new(&key, Author::new(0, 0), body).unwrap());
}
