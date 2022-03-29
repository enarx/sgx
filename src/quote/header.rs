// SPDX-License-Identifier: Apache-2.0

//! The QuoteHeader is part of the Quote structure.

/// Intel's Vendor ID, as specified in A.4, Table 3. Must be 16 bytes.
// pub const INTEL_VENDOR_ID: [u8; 16] = [
//     0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
// ];
use core::mem::transmute;

/// The type of attestation key used to sign the Report.
///
/// ECDSA: <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum KeyType {
    /// ECDSA-256-with-P-256 curve
    ES256 = 2,
    /// ECDSA-384-with-P-384 curve
    ES384 = 3,
}

/// The version of the quote.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum QuoteVersion {
    V3 = 3,
}

/// Unlike the other parts of the Quote, this structure
/// is transparent to the user.
/// Section A.4, Table 3
#[derive(Debug, Clone)]
#[repr(C)]
pub struct QuoteHeader {
    version: [u8; 2],
    key_type: [u8; 2],
    /// Reserved.
    reserved: [u8; 4],
    qe_svn: [u8; 2],
    pce_svn: [u8; 2],
    qe_vendor_id: [u8; 16],
    user_data: [u8; 20],
}

impl QuoteHeader {
    /// Version of Quote structure, 3 in the ECDSA case.
    pub fn version(&self) -> QuoteVersion {
        unsafe { transmute(u16::from_le_bytes(self.version)) }
    }

    /// Type of attestation key used. Only one type is currently supported:
    /// 2 (ECDSA-256-with-P-256-curve).
    pub fn key_type(&self) -> KeyType {
        unsafe { transmute(u16::from_le_bytes(self.key_type)) }
    }

    /// Security version of the QE.
    pub fn qe_svn(&self) -> u16 {
        u16::from_le_bytes(self.qe_svn)
    }

    /// Security version of the Provisioning Certification Enclave.
    pub fn pce_svn(&self) -> u16 {
        u16::from_le_bytes(self.pce_svn)
    }

    /// ID of the QE vendor.
    pub fn qe_vendor_id(&self) -> [u8; 16] {
        self.qe_vendor_id
    }

    /// Custom user-defined data. For the Intel DCAP library, the first 16 bytes
    /// contain a QE identifier used to link a PCK Cert to an Enc(PPID). This
    /// identifier is consistent for every quote generated with this QE on the
    /// platform it was created.
    pub fn user_data(&self) -> [u8; 20] {
        self.user_data
    }
}

#[cfg(test)]
mod test {
    use super::QuoteHeader;
    use testaso::testaso;

    testaso! {
        struct QuoteHeader: 1, 48 => {
            version: 0,
            key_type: 2,
            reserved: 4,
            qe_svn: 8,
            pce_svn: 10,
            qe_vendor_id: 12,
            user_data: 28
        }
    }
}
