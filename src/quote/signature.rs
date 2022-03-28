// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto::{EcdsaP256Sig, EcdsaPubKey},
    quote::{cast::slice_cast, report::IsvEnclaveReport, sizes::*},
};

use core::{convert::TryFrom, fmt};

use super::error::QuoteError;

/// Section A.4, Table 9
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
#[non_exhaustive]
pub enum CertDataType {
    /// Byte array that contains concatenation of PPID, CPUSVN,
    /// PCESVN (LE), PCEID (LE)
    PpidPlaintext = 1,
    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-2048-OAEP, CPUSVN,  PCESVN (LE), PCEID (LE)
    PpidRSA2048OAEP = 2,
    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE)
    PpidRSA3072OAEP = 3,
    /// PCK Leaf Certificate
    PCKLeafCert = 4,
    /// Concatenated PCK Cert Chain  (PEM formatted).
    /// PCK Leaf Cert||Intermediate CA Cert||Root CA Cert
    PCKCertChain = 5,
    /// Intel SGX Quote (not supported).
    Quote = 6,
    /// Platform Manifest (not supported).
    Manifest = 7,
}

impl TryFrom<u16> for CertDataType {
    type Error = QuoteError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CertDataType::PpidPlaintext),
            2 => Ok(CertDataType::PpidRSA2048OAEP),
            3 => Ok(CertDataType::PpidRSA3072OAEP),
            4 => Ok(CertDataType::PCKLeafCert),
            5 => Ok(CertDataType::PCKCertChain),
            6 => Ok(CertDataType::Quote),
            7 => Ok(CertDataType::Manifest),
            _ => Err(QuoteError::UnknownCertDataType),
        }
    }
}

impl fmt::Display for CertDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CertDataType::PpidPlaintext => write!(f, "PpidPlaintext"),
            CertDataType::PpidRSA2048OAEP => write!(f, "PpidRSA2048OAEP"),
            CertDataType::PpidRSA3072OAEP => write!(f, "PpidRSA3072)AEP"),
            CertDataType::PCKLeafCert => write!(f, "PCKLeafCert"),
            CertDataType::PCKCertChain => write!(f, "PCKCertChain"),
            CertDataType::Quote => write!(f, "Quote"),
            CertDataType::Manifest => write!(f, "Manifest"),
        }
    }
}

/// A.4, Table 4
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigData<'a> {
    isv_enclave_report_sig: &'a EcdsaP256Sig,
    ecdsa_attestation_key: &'a EcdsaPubKey,
    qe_report: &'a IsvEnclaveReport,
    qe_report_sig: &'a EcdsaP256Sig,
    qe_auth: &'a [u8],
    qe_cert_data_type: u16,
    qe_cert_data_len: u32,
    qe_cert_data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SigData<'a> {
    type Error = QuoteError;

    fn try_from(bytes: &'a [u8]) -> Result<SigData<'a>, Self::Error> {
        let mut offset = 0;
        let mut offset = |size: usize| {
            offset += size;
            offset
        };

        let isv_enclave_report_sig = slice_cast::<SIG_SIZE>(
            "isv enclave report sig",
            &bytes[offset(0)..offset(SIG_SIZE)],
        )?
        .into();
        let ecdsa_attestation_key = slice_cast::<PUB_KEY_SIZE>(
            "ecdsa attestation key",
            &bytes[offset(0)..offset(PUB_KEY_SIZE)],
        )?
        .into();
        let qe_report =
            slice_cast::<REPORT_SIZE>("qe report", &bytes[offset(0)..offset(REPORT_SIZE)])?.into();
        let qe_report_sig =
            slice_cast::<SIG_SIZE>("qe report sig", &bytes[offset(0)..offset(SIG_SIZE)])?.into();
        let qe_auth_len = u16::from_le_bytes(*slice_cast::<U16_SIZE>(
            "qe auth len",
            &bytes[offset(0)..offset(U16_SIZE)],
        )?);
        let qe_auth = &bytes[offset(0)..offset(qe_auth_len as usize)];
        let qe_cert_data_type = u16::from_le_bytes(*slice_cast::<U16_SIZE>(
            "qe auth len",
            &bytes[offset(0)..offset(U16_SIZE)],
        )?);
        let qe_cert_data_len = u32::from_le_bytes(*slice_cast::<U32_SIZE>(
            "qe cert data len",
            &bytes[offset(0)..offset(U32_SIZE)],
        )?);
        let qe_cert_data = &bytes[offset(0)..offset(qe_cert_data_len as usize)];

        Ok(SigData {
            isv_enclave_report_sig,
            ecdsa_attestation_key,
            qe_report,
            qe_report_sig,
            qe_auth,
            qe_cert_data_type,
            qe_cert_data_len,
            qe_cert_data,
        })
    }
}

impl<'a> SigData<'a> {
    pub fn isv_enclave_report_sig(&self) -> &'a EcdsaP256Sig {
        self.isv_enclave_report_sig
    }

    pub fn ecdsa_attestation_key(&self) -> &'a EcdsaPubKey {
        self.ecdsa_attestation_key
    }

    pub fn qe_report(&self) -> &'a IsvEnclaveReport {
        self.qe_report
    }

    pub fn qe_report_sig(&self) -> &'a EcdsaP256Sig {
        self.qe_report_sig
    }

    pub fn qe_auth(&self) -> &'a [u8] {
        self.qe_auth
    }

    pub fn qe_cert_data_type(&self) -> Result<CertDataType, QuoteError> {
        CertDataType::try_from(self.qe_cert_data_type)
    }

    pub fn qe_cert_data_len(&self) -> u32 {
        self.qe_cert_data_len
    }

    pub fn qe_cert_data(&self) -> &'a [u8] {
        self.qe_cert_data
    }
}
