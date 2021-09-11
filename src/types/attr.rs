// SPDX-License-Identifier: Apache-2.0

//! Attributes (Section 38.7.1)
//! The attributes of an enclave are specified by the struct below as described.

pub use x86_64::registers::xcontrol::XCr0Flags as Xfrm;

bitflags::bitflags! {
    /// Section 38.7.1.
    #[derive(Default)]
    pub struct Features: u64 {
        /// Enclave has been initialized by EINIT.
        const INIT = 1 << 0;
        /// Perm for debugger to r/w enclave data with EDBGRD and EDBGWR.
        const DEBUG = 1 << 1;
        /// Enclave runs in 64-bit mode.
        const BIT64 = 1 << 2;
        /// Provisioning Key is available from EGETKEY.
        const PROV_KEY = 1 << 4;
        /// EINIT token key is available from EGETKEY.
        const EINIT_KEY = 1 << 5;
        /// Enable CET attributes.
        const CET = 1 << 6;
        /// Key Separation and Sharing enabled.
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
    pub const fn features(&self) -> Features {
        self.features
    }

    /// Returns xfrm value of Attributes.
    pub const fn xfrm(&self) -> Xfrm {
        self.xfrm
    }
}

impl core::ops::Not for Attributes {
    type Output = Self;

    fn not(self) -> Self {
        Attributes {
            features: !self.features,
            xfrm: !self.xfrm,
        }
    }
}

impl core::ops::BitAnd for Attributes {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Attributes {
            features: self.features & other.features,
            xfrm: self.xfrm & other.xfrm,
        }
    }
}

impl core::ops::BitOr for Attributes {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Attributes {
            features: self.features | other.features,
            xfrm: self.xfrm | other.xfrm,
        }
    }
}

impl core::ops::BitXor for Attributes {
    type Output = Self;

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
