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
    /// Miscelaneous SSA data selector
    ///
    /// This type controls which extra data will be provided in the SSA page
    /// after an AEX.
    #[derive(Default)]
    pub struct MiscSelect: u32 {
        /// Report #PF and #GP information
        const EXINFO = 1 << 0;
    }
}

/// Enclave creation parameters
///
/// This type is not specified in the Intel documentation and exists for
/// convenience in manipulating sets of configuration. However, the inner
/// types are specified in the Intel documentation.
///
/// Note well that this information is used in different ways in different
/// contexts. For example, when creating an `Secs` page, the mask represents
/// the platform-supported features. Likewise, when creating a `Signature`
/// the mask represents the required features for the enclave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parameters {
    /// Choose info for the `Misc` section of the `StateSaveArea`
    pub misc: Masked<MiscSelect>,

    /// CPU features for the enclave
    pub attr: Masked<Attributes>,

    /// ISV-defined product identifier
    pub isv_prod_id: u16,

    /// ISV-defined security version number
    pub isv_svn: u16,
}
