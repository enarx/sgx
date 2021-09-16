// SPDX-License-Identifier: Apache-2.0

mod features;

pub use features::Features;
pub use x86_64::registers::xcontrol::XCr0Flags as Xfrm;

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
