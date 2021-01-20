// SPDX-License-Identifier: Apache-2.0

use openssl::{bn::BigNum, ecdsa::EcdsaSig, error::ErrorStack};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
/// Error type for the Sig module
pub struct SigError;

/// This struct creates a Signature from raw r and s values, which can
/// be converted to DER form with the method below.
#[derive(Copy, Clone)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Signature {{ r: {:?}, s: {:?} }}",
            self.r.iter(),
            self.s.iter()
        )
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.r[..] == other.r[..] && self.s[..] == other.s[..]
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 32],
            s: [0u8; 32],
        }
    }
}

// turns &[u8] into Signature
impl TryFrom<&[u8]> for Signature {
    type Error = ErrorStack;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut r: [u8; 32] = Default::default();
        let mut s: [u8; 32] = Default::default();
        r.copy_from_slice(&value[0..32]);
        s.copy_from_slice(&value[32..64]);

        Ok(Signature { r, s })
    }
}

// turns Signature into ecdsa
impl TryFrom<&Signature> for EcdsaSig {
    type Error = ErrorStack;
    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let r = BigNum::from_slice(&value.r)?;
        let s = BigNum::from_slice(&value.s)?;
        Ok(EcdsaSig::from_private_components(r, s)?)
    }
}

// turns a Signature in to an ECDSA DER Vector
impl TryFrom<&Signature> for Vec<u8> {
    type Error = ErrorStack;
    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        Ok(EcdsaSig::try_from(value)?.to_der()?)
    }
}

impl Signature {
    /// Creates DER form EcdsaSig from raw r and s values, to be
    /// used in verification of the Signature.
    pub fn to_der_vec(self) -> Result<Vec<u8>, ErrorStack> {
        let sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&self.r)?,
            BigNum::from_slice(&self.s)?,
        )?
        .to_der()?;
        Ok(sig)
    }
}
