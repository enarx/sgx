// SPDX-License-Identifier: Apache-2.0

use crate::page::{Flags, SecInfo};

/// The type of an enclave page (see Intel SDM Volume 3D section 34.12.2).
/// Enclave Page Cache Map (EPCM) hols this information for each valid enclave
/// page.
#[repr(u8)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// SGX Enclave Control Structure (SECS)
    Secs = 0,
    /// Thread Control Structure (TCS)
    Tcs = 1,
    /// Regularular page
    Regular = 2,
    /// Version Array (VA) page
    VersionArray = 3,
    /// Removable from a running enclave
    Trimmed = 4,
    /// The first page of a shadow stack
    ShadowStackFirst = 5,
    /// A shadow stack page
    ShadowStackRest = 6,
}

impl Class {
    /// Convert to SecInfo with the given flags.
    pub fn info(&self, flags: impl Into<Option<Flags>>) -> SecInfo {
        SecInfo::new(*self, flags.into())
    }
}
