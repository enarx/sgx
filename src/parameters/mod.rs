// SPDX-License-Identifier: Apache-2.0

//! Enclave creation parameters
//!
//! This module defines the enclave creation parameters. These parameters
//! control the CPU features available in the enclave as well as how the
//! enclave is identified.
//!
//! These types are typically used by the enclave to communicate to the enclave
//! loader what parameters it requires. It is further used by the enclave
//! loader to pass to the firmware to build an enclave with the correct
//! parameters. Finally, enclave parameters are included in the attestation.

mod attributes;
mod masked;

pub use attributes::{Attributes, Features, Xfrm};
pub use masked::Masked;

bitflags::bitflags! {
    /// MiscSelect (Section 38.7.2)
    /// The bit vector of MISCSELECT selects which extended information is to be saved in the MISC
    /// region of the SSA frame when an AEX is generated.
    /// Section 38.7.2
    #[derive(Default)]
    pub struct MiscSelect: u32 {
        /// Report info about page faults and general protection exception that occurred inside an enclave.
        const EXINFO = 1 << 0;
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Parameters {
    /// Fault information to display in the MISC section of the SSA
    pub misc: Masked<MiscSelect>,

    /// Enclave attributes
    pub attr: Masked<Attributes>,

    /// ISV-defined product identifier
    pub isv_prod_id: u16,

    /// ISV-defined security version number
    pub isv_svn: u16,
}
