// SPDX-License-Identifier: Apache-2.0

use super::{Class, Perms};

/// The security information (`SecInfo`) about a page
///
/// Note that the `FLAGS` field from the SGX documentation is here
/// divided into two fields (`flags` and `class`) for easy manipulation.
///
/// Section 38.11
#[derive(Copy, Clone)]
#[repr(C, align(64))]
pub struct SecInfo {
    /// The permissions of the page
    pub perms: Perms,

    /// The type of the page
    pub class: Class,

    reserved: [u16; 31],
}

impl core::fmt::Debug for SecInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecInfo")
            .field("class", &self.class)
            .field("perms", &self.perms)
            .finish()
    }
}

impl SecInfo {
    /// Creates a SecInfo (page) of class type Regular.
    pub const fn reg(perms: Perms) -> Self {
        Self {
            perms,
            class: Class::Reg,
            reserved: [0; 31],
        }
    }

    /// Creates a SecInfo (page) of class type TCS.
    pub const fn tcs() -> Self {
        Self {
            perms: Perms::empty(),
            class: Class::Tcs,
            reserved: [0; 31],
        }
    }
}

#[cfg(test)]
testaso! {
    struct SecInfo: 64, 64 => {
        perms: 0,
        class: 1
    }
}
