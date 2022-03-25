// SPDX-License-Identifier: Apache-2.0

mod features;

pub use features::Features;
pub use x86_64::registers::xcontrol::XCr0Flags as Xfrm;

use core::ops::*;

/// Enclave CPU attributes
///
/// This type represents the CPU features turned on in an enclave.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Attributes {
    features: Features,
    xfrm: Xfrm,
}

impl Default for Attributes {
    /// Creates a default `Attributes` instance
    ///
    /// The default instance contains no active flags. Note that this is an
    /// invalid configuration and needs to be modified to fit your context.
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

impl Not for Attributes {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Attributes {
            features: !self.features,
            xfrm: !self.xfrm,
        }
    }
}

impl BitAnd for Attributes {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Attributes {
            features: self.features & rhs.features,
            xfrm: self.xfrm & rhs.xfrm,
        }
    }
}

impl BitAnd<Features> for Attributes {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Features) -> Self {
        Attributes {
            features: self.features & rhs,
            xfrm: self.xfrm,
        }
    }
}

impl BitAnd<Xfrm> for Attributes {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Xfrm) -> Self {
        Attributes {
            features: self.features,
            xfrm: self.xfrm & rhs,
        }
    }
}

impl BitAndAssign for Attributes {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.features = self.features & rhs.features;
        self.xfrm = self.xfrm & rhs.xfrm;
    }
}

impl BitAndAssign<Features> for Attributes {
    #[inline]
    fn bitand_assign(&mut self, rhs: Features) {
        self.features = self.features & rhs;
    }
}

impl BitAndAssign<Xfrm> for Attributes {
    #[inline]
    fn bitand_assign(&mut self, rhs: Xfrm) {
        self.xfrm = self.xfrm & rhs;
    }
}

impl BitOr for Attributes {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Attributes {
            features: self.features | rhs.features,
            xfrm: self.xfrm | rhs.xfrm,
        }
    }
}

impl BitOr<Features> for Attributes {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Features) -> Self {
        Attributes {
            features: self.features | rhs,
            xfrm: self.xfrm,
        }
    }
}

impl BitOr<Xfrm> for Attributes {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Xfrm) -> Self {
        Attributes {
            features: self.features,
            xfrm: self.xfrm | rhs,
        }
    }
}

impl BitOrAssign for Attributes {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.features = self.features | rhs.features;
        self.xfrm = self.xfrm | rhs.xfrm;
    }
}

impl BitOrAssign<Features> for Attributes {
    #[inline]
    fn bitor_assign(&mut self, rhs: Features) {
        self.features = self.features | rhs;
    }
}

impl BitOrAssign<Xfrm> for Attributes {
    #[inline]
    fn bitor_assign(&mut self, rhs: Xfrm) {
        self.xfrm = self.xfrm | rhs;
    }
}

impl BitXor for Attributes {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Attributes {
            features: self.features ^ rhs.features,
            xfrm: self.xfrm ^ rhs.xfrm,
        }
    }
}

impl BitXor<Features> for Attributes {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Features) -> Self {
        Attributes {
            features: self.features ^ rhs,
            xfrm: self.xfrm,
        }
    }
}

impl BitXor<Xfrm> for Attributes {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Xfrm) -> Self {
        Attributes {
            features: self.features,
            xfrm: self.xfrm ^ rhs,
        }
    }
}

impl BitXorAssign for Attributes {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.features = self.features ^ rhs.features;
        self.xfrm = self.xfrm ^ rhs.xfrm;
    }
}

impl BitXorAssign<Features> for Attributes {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Features) {
        self.features = self.features ^ rhs;
    }
}

impl BitXorAssign<Xfrm> for Attributes {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Xfrm) {
        self.xfrm = self.xfrm ^ rhs;
    }
}

#[cfg(test)]
mod test {
    use super::Attributes;
    use testaso::testaso;

    testaso! {
        struct Attributes: 4, 16 => {}
    }
}
