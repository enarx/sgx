// SPDX-License-Identifier: Apache-2.0

//! Attributes (Section 38.7.1)
//! The attributes of an enclave are specified by the struct below as described.

pub use x86_64::registers::xcontrol::XCr0Flags as Xfrm;

bitflags::bitflags! {
    /// Expresses the non-XSAVE related enclave features
    #[derive(Default)]
    pub struct Features: u64 {
        /// Enclave has been initialized by EINIT
        ///
        /// Note that this flag MUST be cleared when loading the enclave and,
        /// conversly, MUST be set when validating an attestation.
        const INIT = 1 << 0;

        /// Enables enclave debug mode
        ///
        /// This gives permission to use EDBGRD and EDBGWR to read and write
        /// enclave memory as plaintext, respectively.
        const DEBUG = 1 << 1;

        /// Enables enclave 64-bit mode
        const MODE64BIT = 1 << 2;

        /// Enables use of the provisioning key via EGETKEY
        const PROVISIONING_KEY = 1 << 4;

        /// Enables use of the EINIT token key via EGETKEY
        const EINIT_KEY = 1 << 5;

        /// Enables CET attributes
        const CET = 1 << 6;

        /// Enables key separation and sharing
        const KSS = 1 << 7;
    }
}

/// Section 38.7.1.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Attributes {
    features: Features,
    xfrm: Xfrm,
}

impl Default for Attributes {
    #[inline]
    fn default() -> Self {
        Self {
            features: Features::default(),
            xfrm: Xfrm::empty(),
        }
    }
}

impl Attributes {
    /// Creates new Attributes struct from Features and Xfrm.
    pub const fn new(features: Features, xfrm: Xfrm) -> Self {
        Self { features, xfrm }
    }

    /// Returns features value of Attributes.
    #[inline]
    pub const fn features(&self) -> Features {
        self.features
    }

    /// Returns xfrm value of Attributes.
    #[inline]
    pub const fn xfrm(&self) -> Xfrm {
        self.xfrm
    }
}

impl core::ops::Not for Attributes {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Attributes {
            features: !self.features,
            xfrm: !self.xfrm,
        }
    }
}

impl core::ops::BitAnd for Attributes {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self {
        Attributes {
            features: self.features & other.features,
            xfrm: self.xfrm & other.xfrm,
        }
    }
}

impl core::ops::BitOr for Attributes {
    type Output = Self;

    #[inline]
    fn bitor(self, other: Self) -> Self {
        Attributes {
            features: self.features | other.features,
            xfrm: self.xfrm | other.xfrm,
        }
    }
}

impl core::ops::BitXor for Attributes {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self {
        Attributes {
            features: self.features ^ other.features,
            xfrm: self.xfrm ^ other.xfrm,
        }
    }
}

#[cfg(test)]
testaso! {
    struct Attributes: 4, 16 => {}
}
