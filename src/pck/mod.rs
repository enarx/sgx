// SPDX-License-Identifier: Apache-2.0

//! SGX PCK Certificate parsing
//!
//! see 1.3.5 Intel® SGX PCK Certificate of https://download.01.org/intel-sgx/sgx-dcap/1.10.3/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

mod raw;

use raw::SgxExtensionRaw;

use const_oid::AssociatedOid;
use der::Decode;
use x509::ext::Extensions;

pub struct SgxExtension<'a> {
    pub fmspc: &'a [u8],
    pub pcesvn: u8,
    pub pceid: &'a [u8],
    pub tcb_components: [u8; 16],
    pub is_multi: bool,
}

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SgxExtensionError {
    MissingSgxExtension,
    DerDecodingError(der::Error),
}

impl core::fmt::Display for SgxExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SgxExtensionError::MissingSgxExtension => write!(f, "SGX: Missing extension"),
            SgxExtensionError::DerDecodingError(e) => write!(f, "SGX: Der decoding error: {e}"),
        }
    }
}

impl<'a> SgxExtension<'a> {
    pub fn from_x509_extensions(extensions: &'a Extensions) -> Result<Self, SgxExtensionError> {
        let extension = extensions
            .iter()
            .find(|e| e.extn_id == SgxExtensionRaw::OID)
            .ok_or(SgxExtensionError::MissingSgxExtension)?;

        let sgx_extension: SgxExtensionRaw =
            Decode::from_der(extension.extn_value).map_err(SgxExtensionError::DerDecodingError)?;

        Ok(Self {
            fmspc: sgx_extension.fmspc.bytes,
            pcesvn: sgx_extension.tcb.inner.pcesvn.value,
            pceid: sgx_extension.pceid.bytes,
            is_multi: sgx_extension.platform_config.is_some(),
            tcb_components: [
                sgx_extension.tcb.inner.tcb1.value,
                sgx_extension.tcb.inner.tcb2.value,
                sgx_extension.tcb.inner.tcb3.value,
                sgx_extension.tcb.inner.tcb4.value,
                sgx_extension.tcb.inner.tcb5.value,
                sgx_extension.tcb.inner.tcb6.value,
                sgx_extension.tcb.inner.tcb7.value,
                sgx_extension.tcb.inner.tcb8.value,
                sgx_extension.tcb.inner.tcb9.value,
                sgx_extension.tcb.inner.tcb10.value,
                sgx_extension.tcb.inner.tcb11.value,
                sgx_extension.tcb.inner.tcb12.value,
                sgx_extension.tcb.inner.tcb13.value,
                sgx_extension.tcb.inner.tcb14.value,
                sgx_extension.tcb.inner.tcb15.value,
                sgx_extension.tcb.inner.tcb16.value,
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509::Certificate;

    #[test]
    fn sgx_extension_single() {
        const PCK: &[u8] = include_bytes!("../../tests/single_pck.crt");
        let pck: Certificate = Decode::from_der(PCK).unwrap();
        let extensions = pck.tbs_certificate.extensions.unwrap();

        let extension = SgxExtension::from_x509_extensions(&extensions)
            .map_err(|e| eprintln!("{e}"))
            .unwrap();
        assert_eq!(extension.fmspc, [00, 0x70, 0x6E, 0x47, 00, 00]);
        assert_eq!(extension.pcesvn, 10);
        assert_eq!(extension.pceid, [0, 0]);
        assert_eq!(
            extension.tcb_components,
            [6, 6, 2, 2, 2, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(!extension.is_multi);
    }

    #[test]
    fn sgx_extension_xeon() {
        const PCK: &[u8] = include_bytes!("../../tests/multi_pck.crt");
        let pck: Certificate = Decode::from_der(PCK).unwrap();
        let extensions = pck.tbs_certificate.extensions.unwrap();

        let extension = SgxExtension::from_x509_extensions(&extensions)
            .map_err(|e| eprintln!("{e}"))
            .unwrap();
        assert_eq!(extension.fmspc, [00, 0x60, 0x6A, 00, 00, 00]);
        assert_eq!(extension.pcesvn, 11);
        assert_eq!(extension.pceid, [0, 0]);
        assert_eq!(
            extension.tcb_components,
            [4, 4, 3, 3, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(extension.is_multi);
    }
}
