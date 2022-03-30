// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Enclave report structures.

use crate::parameters::{Attributes, Features, MiscSelect, Xfrm};

/// The enclave report body.
///
/// For more information see the following documents:
///
/// [Intel® Software Guard Extensions (Intel® SGX) Data Center Attestation Primitives: ECDSA Quote Library API](https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf)
///
/// Table 5, A.4. Quote Format
///
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3 (3A, 3B, 3C & 3D): System Programming Guide](https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.html)
///
/// Table 38-21. Layout of REPORT
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ReportBody {
    cpusvn: [u8; 16],
    miscselect: [u8; 4],
    reserved1: [u8; 28],
    // The attributes field is composed of the features and xfrm fields.
    features: [u8; 8],
    xfrm: [u8; 8],
    mrenclave: [u8; 32],
    reserved2: [u8; 32],
    mrsigner: [u8; 32],
    reserved3: [u8; 96],
    isv_prodid: [u8; 2],
    isv_svn: [u8; 2],
    reserved4: [u8; 60],
    reportdata: [u8; 64],
}

impl ReportBody {
    /// The SVN (security version number) of the processor.
    pub fn cpu_security_version(&self) -> [u8; 16] {
        self.cpusvn
    }

    /// Bit vector specifying which extended features are saved to the MISC region of the
    /// SSA frame when an AEX occurs.
    ///
    /// If it cannot be parsed the raw little endian bytes will be returned instead.
    pub fn misc_select(&self) -> Result<MiscSelect, [u8; 4]> {
        let misc_select = u32::from_le_bytes(self.miscselect);
        MiscSelect::from_bits(misc_select).ok_or(self.miscselect)
    }

    /// Set of flags describing attributes of the enclave.
    ///
    /// If it cannot be parsed the raw little endian bytes will be returned instead.
    ///
    /// The raw bytes returned are the 64 bit features and xfrm respectively.
    pub fn attributes(&self) -> Attributes {
        let features = Features::from_bits_truncate(u64::from_le_bytes(self.features));
        let xfrm = Xfrm::from_bits_truncate(u64::from_le_bytes(self.xfrm));
        Attributes::new(features, xfrm)
    }

    /// Value of SECS.MRENCLAVE (measurement of the enclave).
    pub fn enclave_measurement(&self) -> [u8; 32] {
        self.mrenclave
    }

    /// Value from SECS.MRSIGNER (hash of the enclave signing key).
    pub fn enclave_signing_key_hash(&self) -> [u8; 32] {
        self.mrsigner
    }

    /// ISV assigned Product ID of the enclave.
    pub fn enclave_product_id(&self) -> u16 {
        u16::from_le_bytes(self.isv_prodid)
    }

    /// ISV assigned SVN (security version number) of the enclave.
    pub fn enclave_security_version(&self) -> u16 {
        u16::from_le_bytes(self.isv_svn)
    }

    /// Data provided by the user and protected by the reports MAC.
    pub fn report_data(&self) -> [u8; 64] {
        self.reportdata
    }
}

/// The REPORT structure is the output of the EREPORT instruction, and must be 512-Byte aligned.
///
/// For more information see:
///
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3 (3A, 3B, 3C & 3D): System Programming Guide](https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.html)
///
/// Table 38-21. Layout of REPORT
#[derive(Clone, Debug)]
#[repr(C, align(512))]
pub struct Report {
    body: ReportBody,
    keyid: [u8; 32],
    mac: [u8; 16],
}

impl Report {
    /// The enclave report body.
    pub fn body(&self) -> &ReportBody {
        &self.body
    }

    /// Value for key wear-out protection.
    pub fn key_id(&self) -> [u8; 32] {
        self.keyid
    }

    /// The MAC (message authentication code) on the report using report key.
    pub fn mac(&self) -> [u8; 16] {
        self.mac
    }
}

#[cfg(test)]
mod test {
    use super::{Report, ReportBody};
    use testaso::testaso;

    testaso! {
        struct ReportBody: 1, 384 => {
            cpusvn: 0,
            miscselect: 16,
            reserved1: 20,
            features: 48,
            xfrm: 56,
            mrenclave: 64,
            reserved2: 96,
            mrsigner: 128,
            reserved3: 160,
            isv_prodid: 256,
            isv_svn: 258,
            reserved4: 260,
            reportdata: 320
        }

        struct Report: 512, 512 => {
            body: 0,
            keyid: 384,
            mac: 416
        }
    }
}
