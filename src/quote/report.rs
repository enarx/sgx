// SPDX-License-Identifier: Apache-2.0

//! Section 38.15
//! The REPORT structure is the output of the EREPORT instruction, and must be 512-Byte aligned.

use crate::{
    parameters::{Attributes, Features, MiscSelect, Xfrm},
    quote::error::QuoteError,
};

use core::mem::{size_of, transmute};

/// This struct is separated out from the Report to be usable by the Quote struct.
/// Table 38-21
#[derive(Clone, Debug)]
#[repr(C)]
pub struct IsvEnclaveReport {
    cpu_svn: [u8; 16],
    misc_select: [u8; 4],
    /// Reserved
    reserved0: [u32; 7],
    features: [u8; 8],
    xfrm: [u8; 8],
    mrenclave: [u8; 32],
    /// Reserved
    reserved1: [u32; 8],
    mrsigner: [u8; 32],
    /// Reserved
    reserved2: [u32; 24],
    isv_prodid: [u8; 2],
    isv_svn: [u8; 2],
    /// Reserved
    reserved3: [u32; 15],
    report_data: [u8; 64],
}

impl IsvEnclaveReport {
    /// Cast an instance into a byte slice.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { transmute(self) }
    }

    /// The security version number of the processor.
    pub fn cpu_svn(&self) -> [u8; 16] {
        self.cpu_svn
    }

    /// Bit vector specifying which extended features are saved to the
    /// MISC region of the SSA frame when an AEX occurs
    pub fn misc_select(&self) -> Result<MiscSelect, QuoteError> {
        let misc_select = u32::from_le_bytes(self.misc_select);
        MiscSelect::from_bits(misc_select).ok_or(QuoteError::InvalidMiscSelect(misc_select))
    }

    /// Attributes of the enclave (Section 38.7.1)
    pub fn attributes(&self) -> Result<Attributes, QuoteError> {
        let features = u64::from_le_bytes(self.features);
        let features =
            Features::from_bits(features).ok_or(QuoteError::InvalidFeatures(features))?;
        let xfrm = u64::from_le_bytes(self.xfrm);
        let xfrm = Xfrm::from_bits(xfrm).ok_or(QuoteError::InvalidXfrm(xfrm))?;
        Ok(Attributes::new(features, xfrm))
    }

    /// Value of SECS.MRENCLAVE
    pub fn mrenclave(&self) -> [u8; 32] {
        self.mrenclave
    }

    /// Value from SECS.MRSIGNER
    pub fn mrsigner(&self) -> [u8; 32] {
        self.mrsigner
    }

    /// ISV assigned Product ID of the enclave
    /// ISV_PRODID in SIGSTRUCT (Table 38-19)
    pub fn isv_prodid(&self) -> u16 {
        u16::from_le_bytes(self.isv_prodid)
    }

    /// ISVSVN in SIGSTRUCT (Table 38-19)
    /// ISV assigned SVN (security version number) of the enclave
    pub fn isv_svn(&self) -> u16 {
        u16::from_le_bytes(self.isv_svn)
    }

    /// Data provided by the user and protected by the Report's MAC (Section 38.15.1)
    pub fn report_data(&self) -> [u8; 64] {
        self.report_data
    }
}

#[cfg(test)]
mod test {
    use super::IsvEnclaveReport;
    use testaso::testaso;

    testaso! {
        struct IsvEnclaveReport: 4, 384 => {
            cpu_svn: 0,
            misc_select: 16,
            reserved0: 20,
            features: 48,
            xfrm: 56,
            mrenclave: 64,
            reserved1: 96,
            mrsigner: 128,
            reserved2: 160,
            isv_prodid: 256,
            isv_svn: 258,
            reserved3: 260,
            report_data: 320
        }
    }
}
