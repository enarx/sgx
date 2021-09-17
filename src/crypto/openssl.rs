// SPDX-License-Identifier: Apache-2.0

use openssl::{bn, error::ErrorStack, pkey, rsa, sha, sign};

fn arr_from_bn(value: &bn::BigNumRef) -> [u8; 384] {
    let mut le = [0u8; 384];
    let be = value.to_vec();

    assert!(be.len() <= le.len());
    for i in 0..be.len() {
        le[be.len() - i - 1] = be[i];
    }

    le
}

pub struct S256Digest(sha::Sha256);

impl super::Digest for S256Digest {
    type Output = [u8; 32];

    #[inline]
    fn new() -> Self {
        Self(sha::Sha256::new())
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    #[inline]
    fn finish(self) -> Self::Output {
        self.0.finish()
    }
}

pub struct RS256PrivateKey(rsa::Rsa<pkey::Private>);

impl RS256PrivateKey {
    pub fn new(key: rsa::Rsa<pkey::Private>) -> Self {
        assert!(key.n().num_bytes() <= 384);
        Self(key)
    }
}

impl super::PrivateKey for RS256PrivateKey {
    type Error = ErrorStack;

    fn generate(exponent: u8) -> Result<Self, Self::Error> {
        let exponent = bn::BigNum::from_u32(exponent.into()).unwrap();
        let key = rsa::Rsa::generate_with_e(384 * 8, &*exponent)?;
        Ok(Self::new(key))
    }

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        let key = rsa::Rsa::private_key_from_pem(pem.as_bytes())?;
        Ok(Self::new(key))
    }

    fn from_der(der: &[u8]) -> Result<Self, Self::Error> {
        let key = rsa::Rsa::private_key_from_der(der)?;
        Ok(Self::new(key))
    }

    fn sign(&self, author: &[u8], body: &[u8]) -> Result<super::SigData, Self::Error> {
        // Sign the input.
        let mut signature = [0u8; 384];
        let rsa_key = pkey::PKey::from_rsa(self.0.clone())?;
        let md = openssl::hash::MessageDigest::sha256();
        let mut signer = sign::Signer::new(md, &rsa_key)?;
        signer.update(author)?;
        signer.update(body)?;
        signer.sign(&mut signature)?;

        // Calculate q1 and q2.
        let s = bn::BigNum::from_slice(&signature)?;
        let m = self.0.n();
        let mut ctx = bn::BigNumContext::new()?;
        let mut q1 = bn::BigNum::new()?;
        let mut qr = bn::BigNum::new()?;
        q1.div_rem(&mut qr, &(&s * &s), m, &mut ctx)?;
        let q2 = &(&s * &qr) / m;

        // Get the exponent.
        let mut exponent: u32 = 0;
        for byte in self.0.e().to_vec() {
            exponent <<= 8;
            exponent |= byte as u32;
        }

        Ok(super::SigData {
            signature: arr_from_bn(&s),
            modulus: arr_from_bn(&*m),
            exponent,
            q1: arr_from_bn(&*q1),
            q2: arr_from_bn(&*q2),
        })
    }
}

#[test]
#[cfg(test)]
fn selftest() {
    super::selftest::<RS256PrivateKey, S256Digest>();
}
