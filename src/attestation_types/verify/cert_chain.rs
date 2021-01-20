// SPDX-License-Identifier: Apache-2.0

use super::error::VerifyError;
use openssl::{stack::Stack, x509::*};

/// This constructs a complete certificate chain by uniting the tenant's chain (from Intel)
/// with the leaf cert embedded in the platform's Quote.
#[derive(Clone)]
pub struct CertChain {
    chain: Vec<X509>,
    leaf: X509,
    max_len: usize,
}

#[allow(dead_code)]
impl CertChain {
    /// The CertChain is constructed from a vector of X509 certificates and
    /// a leaf certificate. The maximum chain length defaults to 10.
    pub fn new_from_chain(c: Vec<X509>, leaf: &X509) -> Self {
        CertChain {
            chain: c,
            leaf: leaf.clone(),
            max_len: 10,
        }
    }

    /// The maximum chain length can be set manually.
    pub fn set_max_len(&mut self, len: usize) {
        self.max_len = len;
    }

    /// Returns length of chain, including leaf cert
    pub fn len(&self) -> usize {
        self.chain.len() + 1
    }

    /// This checks that the CertChain's length is under the maximum allowed.
    pub fn len_ok(&self) -> Result<(), VerifyError> {
        if self.chain.len() > self.max_len {
            return Err(VerifyError(
                "Certificate chain length exceeds max allowable.".to_string(),
            ));
        }
        Ok(())
    }

    /// For all certificates in the CertChain, this verifies that the cert's issuer
    /// matches the parent cert's subject field.
    pub fn verify_issuers(&self) -> Result<(), VerifyError> {
        let chain: Vec<X509> = [self.leaf.clone()]
            .iter()
            .cloned()
            .chain(self.chain.iter().cloned())
            .collect();
        let mut iter = chain.iter().peekable();
        while let Some(next_cert) = iter.next() {
            let parent = iter.peek();
            if parent.is_none() {
                continue;
            };
            if parent.unwrap().issued(&next_cert) != X509VerifyResult::OK {
                return Err(VerifyError(
                    "invalid issuer relationship in certificate chain".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// This verifies that the signatures on the certificate chain are correct by
    /// checking the context of the leaf certificate.
    pub fn verify_sigs(mut self) -> Result<(), VerifyError> {
        // Parse out root cert, which will be at end of chain.
        // The rest of the chain holds intermediate certs.
        let root_cert = match self.chain.pop() {
            Some(cert) => cert,
            None => {
                return Err(VerifyError("no certs found in chain".to_string()));
            }
        };

        // Only the root certificate is added to the trusted store.
        let mut store_bldr = store::X509StoreBuilder::new()?;
        store_bldr.add_cert(root_cert)?;
        let store = store_bldr.build();

        // Creates the chain of untrusted certificates.
        let mut chain = Stack::new()?;
        for c in self.chain.iter() {
            let _ = chain.push(c.clone());
        }

        // This context will be initialized with the trusted store and
        // the chain of untrusted certificates to verify the leaf.
        let mut context = X509StoreContext::new()?;

        // This operation verifies the leaf (PCK_cert) in the context of the
        // chain. If the chain cannot be verified, the leaf will not be
        // verified.
        match context.init(&store, &self.leaf, &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerifyError(format!(
                "invalid signature in certificate chain: {}",
                context.error()
            ))),
            Err(e) => Err(VerifyError(format!(
                "could not determine validity of cert chain signatures; {}",
                e
            ))),
        }
    }
}
