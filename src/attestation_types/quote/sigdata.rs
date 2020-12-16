// SPDX-License-Identifier: Apache-2.0

//! The SigData structure is part of the Quote structure. For more, see the Quote module.

use super::QuoteError;
use crate::attestation_types::report::Body;
use std::{convert::TryFrom, vec::Vec};

/// ECDSA  signature, the r component followed by the
/// s component, 2 x 32 bytes.
/// A.4, Table 6
#[derive(Default)]
#[repr(C)]
pub struct ECDSAP256Sig {
    /// r component
    pub r: [u8; 32],

    /// s component
    pub s: [u8; 32],
}

/// EC KT-I Public Key, the x-coordinate followed by
/// the y-coordinate (on the RFC 6090P-256 curve),
/// 2 x 32 bytes.
/// A.4, Table 7
#[derive(Default)]
#[repr(C)]
pub struct ECDSAPubKey {
    /// x coordinate
    pub x: [u8; 32],

    /// y coordinate
    pub y: [u8; 32],
}

/// Section A.4, Table 9
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
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

impl Default for CertDataType {
    fn default() -> Self {
        Self::PCKCertChain
    }
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
            _ => Err(QuoteError(format!("Unknown Cert Data type: {}", value))),
        }
    }
}

/// A.4, Table 4
#[derive(Default)]
#[repr(C)]
pub struct SigData {
    isv_enclave_report_sig: ECDSAP256Sig,
    ecdsa_attestation_key: ECDSAPubKey,
    qe_report: Body,
    qe_report_sig: ECDSAP256Sig,
    qe_auth: Vec<u8>,
    qe_cert_data_type: CertDataType,
    qe_cert_data: Vec<u8>,
}
