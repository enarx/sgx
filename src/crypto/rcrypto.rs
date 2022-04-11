// SPDX-License-Identifier: Apache-2.0

use num_integer::Integer;
use num_traits::ToPrimitive;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPrivateKey, BigUint, PaddingScheme, PublicKeyParts, RsaPrivateKey};
use sha2::{Digest, Sha256};

fn arr_from_big(value: &BigUint) -> [u8; 384] {
    let mut arr = [0u8; 384];
    let buf = value.to_bytes_le();
    arr.copy_from_slice(&buf);
    arr
}

/// SHA2-256
pub struct S256Digest(Sha256);

impl super::Digest for S256Digest {
    type Output = [u8; 32];

    #[inline]
    fn new() -> Self {
        Self(Sha256::new())
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    #[inline]
    fn finish(self) -> Self::Output {
        *self.0.finalize().as_ref()
    }
}

/// RSA w/ SHA2-256
pub struct RS256PrivateKey(RsaPrivateKey);

impl RS256PrivateKey {
    pub fn new(key: RsaPrivateKey) -> Self {
        assert!(key.n().bits() <= 384 * 8);
        Self(key)
    }
}

impl super::PrivateKey for RS256PrivateKey {
    type Error = rsa::errors::Error;

    fn generate(exponent: u8) -> Result<Self, Self::Error> {
        let mut rng = thread_rng();
        let exp = BigUint::from(exponent);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 384 * 8, &exp)?;
        Ok(Self::new(key))
    }

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        Ok(Self::new(key))
    }

    fn from_der(der: &[u8]) -> Result<Self, Self::Error> {
        let key = RsaPrivateKey::from_pkcs1_der(der)?;
        Ok(Self::new(key))
    }

    fn sign(&self, author: &[u8], body: &[u8]) -> Result<super::SigData, Self::Error> {
        use sha2::digest::Update;

        let hash = Sha256::new().chain(author).chain(body).finalize();

        let mut signature = [0u8; 384];
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::hash::Hash::SHA2_256));
        let sig = self.0.sign(padding, &hash)?;
        signature.copy_from_slice(&sig);

        // Calculate q1 and q2.
        let s = BigUint::from_bytes_be(&signature);
        let m = self.0.n();
        let (q1, qr) = (&s * &s).div_rem(m);
        let q2 = (&s * qr) / m;

        Ok(super::SigData {
            signature: arr_from_big(&s),
            modulus: arr_from_big(m),
            exponent: self.0.e().to_u32().unwrap(),
            q1: arr_from_big(&q1),
            q2: arr_from_big(&q2),
        })
    }
}

#[test]
#[cfg(test)]
fn selftest() {
    super::selftest::<RS256PrivateKey, S256Digest>();
}
