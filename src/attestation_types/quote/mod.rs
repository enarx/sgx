// SPDX-License-Identifier: Apache-2.0

//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

pub mod quoteheader;
pub mod sigdata;

use super::report::{Body, ReportError};
use core::fmt;
use quoteheader::QuoteHeader;
use sigdata::SigData;

/// The length of an ECDSA signature is 64 bytes. This value must be 4 bytes.
pub const ECDSASIGLEN: u32 = 64;

#[derive(Clone, Debug)]
/// Error type for Quote module
pub struct QuoteError(pub String);

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl std::error::Error for QuoteError {}

impl From<ReportError> for QuoteError {
    fn from(_: ReportError) -> Self {
        QuoteError("Report error".to_string())
    }
}

/// Wrapper struct for the u32 indicating the signature data length
/// (described in A.4).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigDataLen(u32);

impl From<u32> for SigDataLen {
    fn from(val: u32) -> Self {
        SigDataLen(val)
    }
}

impl Default for SigDataLen {
    fn default() -> Self {
        SigDataLen(ECDSASIGLEN)
    }
}

impl From<&[u8; 4]> for SigDataLen {
    fn from(bytes: &[u8; 4]) -> Self {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&bytes[0..4]);
        let len = u32::from_le_bytes(tmp);
        SigDataLen::from(len)
    }
}

/// Section A.4
/// All integer fields are in little endian.
#[derive(Default)]
#[repr(C, align(4))]
pub struct Quote {
    /// Header for Quote structure; transparent to the user.
    pub header: QuoteHeader,

    /// Report of the atteste enclave.
    isv_enclave_report: Body,

    /// Size of the Signature Data field.
    sig_data_len: SigDataLen,

    /// Variable-length data containing the signature and
    /// supporting data.
    sig_data: SigData,
}
