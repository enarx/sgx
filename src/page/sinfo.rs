// SPDX-License-Identifier: Apache-2.0

use super::{Class, Flags};

/// The security information about a page
///
/// This structure encodes the security information about one or more pages.
///
/// Note that this structure divides the `FLAGS` field from the Intel docs
/// into two fields (`flags` and `class`) for easy manipulation.
#[derive(Copy, Clone)]
#[repr(C, align(64))]
pub struct SecInfo {
    flags: Flags,
    class: Class,
    reserved: [u16; 31],
}

impl core::fmt::Debug for SecInfo {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecInfo")
            .field("class", &self.class)
            .field("flags", &self.flags)
            .finish()
    }
}

impl SecInfo {
    /// Creates a `SecInfo` instance for regular pages
    pub const fn reg(flags: Flags) -> Self {
        Self {
            flags,
            class: Class::Reg,
            reserved: [0; 31],
        }
    }

    /// Creates a `SecInfo` instance for TCS pages
    pub const fn tcs() -> Self {
        Self {
            flags: Flags::empty(),
            class: Class::Tcs,
            reserved: [0; 31],
        }
    }

    /// Get the flags
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// Get the class
    pub const fn class(&self) -> Class {
        self.class
    }
}

#[cfg(test)]
testaso! {
    struct SecInfo: 64, 64 => {
        flags: 0,
        class: 1
    }
}
