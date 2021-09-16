// SPDX-License-Identifier: Apache-2.0

//! SigStruct (Section 38.13)
//! SigStruct is a structure created and signed by the enclave developer that
//! contains information about the enclave. SIGSTRUCT is processed by the EINIT
//! leaf function to verify that the enclave was properly built.

use crate::{Attributes, MiscSelect};

use core::fmt::Debug;
use core::ops::{BitAnd, BitOr, Not};

/// Succinctly describes a masked type, e.g. masked Attributes or masked MiscSelect.
/// A mask is applied to Attributes and MiscSelect structs in a Signature (SIGSTRUCT)
/// to specify values of Attributes and MiscSelect to enforce. This struct combines
/// the struct and its mask for simplicity.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: BitAnd<Output = T>> {
    /// The data being masked, e.g. Attribute flags.
    pub data: T,

    /// The mask.
    pub mask: T,
}

impl<T> Default for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Default,
    T: Copy,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> From<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Copy,
{
    fn from(value: T) -> Self {
        Self {
            data: value,
            mask: value | !value,
        }
    }
}

impl<T> PartialEq<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: PartialEq,
    T: Copy,
{
    fn eq(&self, other: &T) -> bool {
        self.mask & self.data == self.mask & *other
    }
}

/// Enclave parameters
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Parameters {
    /// Fault information to display in the MISC section of the SSA
    pub misc: Masked<MiscSelect>,

    /// Enclave attributes
    pub attr: Masked<Attributes>,

    /// ISV-defined product identifier
    pub isv_prod_id: u16,

    /// ISV-defined security version number
    pub isv_svn: u16,
}

impl Parameters {
    /// Combines the parameters and a hash of the enclave to produce a `Measure`
    pub const fn measure(&self, mrenclave: [u8; 32]) -> Measure {
        Measure {
            misc: self.misc,
            reserved0: [0; 20],
            attr: self.attr,
            mrenclave,
            reserved1: [0; 32],
            isv_prod_id: self.isv_prod_id,
            isv_svn: self.isv_svn,
        }
    }
}

/// The enclave Measure
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Measure {
    misc: Masked<MiscSelect>,
    reserved0: [u8; 20],
    attr: Masked<Attributes>,
    mrenclave: [u8; 32],
    reserved1: [u8; 32],
    isv_prod_id: u16,
    isv_svn: u16,
}

impl Measure {
    /// Get the enclave measure hash
    pub fn mrenclave(&self) -> [u8; 32] {
        self.mrenclave
    }

    /// Get the enclave parameters
    pub fn parameters(&self) -> Parameters {
        Parameters {
            isv_prod_id: self.isv_prod_id,
            isv_svn: self.isv_svn,
            misc: self.misc,
            attr: self.attr,
        }
    }

    /// Signs a measure using the specified key on behalf of an author
    #[cfg(feature = "openssl")]
    pub fn sign(
        self,
        author: super::Author,
        key: openssl::rsa::Rsa<openssl::pkey::Private>,
    ) -> Result<super::Signature, openssl::error::ErrorStack> {
        use crate::RsaNumber;
        use core::convert::TryInto;
        use openssl::{bn::*, hash::*, pkey::*, sign::*};
        const EXPONENT: u32 = 3;
        assert!(key.n().num_bytes() as usize <= RsaNumber::SIZE);
        assert_eq!(key.e(), &*BigNum::from_u32(EXPONENT)?);

        let a = unsafe {
            core::slice::from_raw_parts(
                &author as *const _ as *const u8,
                core::mem::size_of_val(&author),
            )
        };

        let c = unsafe {
            core::slice::from_raw_parts(
                &self as *const _ as *const u8,
                core::mem::size_of_val(&self),
            )
        };

        // Generates signature on Signature author and contents
        let rsa_key = PKey::from_rsa(key.clone())?;
        let md = MessageDigest::sha256();
        let mut signer = Signer::new(md, &rsa_key)?;
        signer.update(a)?;
        signer.update(c)?;
        let signature = signer.sign_to_vec()?;

        // Generates q1, q2 values for RSA signature verification
        let s = BigNum::from_slice(&signature)?;
        let m = key.n();

        let mut ctx = BigNumContext::new()?;
        let mut q1 = BigNum::new()?;
        let mut qr = BigNum::new()?;

        q1.div_rem(&mut qr, &(&s * &s), m, &mut ctx)?;
        let q2 = &(&s * &qr) / m;

        Ok(super::Signature {
            author,
            modulus: m.try_into()?,
            exponent: EXPONENT,
            signature: s.try_into()?,
            measure: self,
            reserved: [0; 12],
            q1: q1.try_into()?,
            q2: q2.try_into()?,
        })
    }
}

#[cfg(test)]
testaso! {
    struct Measure: 4, 128 => {
        misc: 0,
        reserved0: 8,
        attr: 28,
        mrenclave: 60,
        reserved1: 92,
        isv_prod_id: 124,
        isv_svn: 126
    }
}
