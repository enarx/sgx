// SPDX-License-Identifier: Apache-2.0

use super::{Class, Flags};

use core::arch::asm;

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

impl core::fmt::Display for SecInfo {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.class {
            Class::Secs => write!(f, "S"),
            Class::Tcs => write!(f, "T"),
            Class::Reg => write!(f, "{}", self.flags),
            Class::Va => write!(f, "V"),
            Class::Trim => write!(f, "^"),
        }
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

    /// Execute EACCEPT.
    pub fn accept(&self, dest: *const u8) {
        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") crate::enclu::EACCEPT,
                in("rcx") dest,
            );
        }
    }

    /// Execute EACCEPTCOPY. Not supported on Shadow Stack (SS) pages.
    pub fn accept_copy(&self, dest: *const u8, src: *const u8) {
        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") crate::enclu::EACCEPTCOPY,
                in("rcx") dest,
                in("rdx") src,
            );
        }
    }

    /// Execute EMODPE. Not supported on Shadow Stack (SS) pages.
    ///
    /// EPCM permissions must be PROT_NONE for this to work always without
    /// failure, as EMODPE can only extend the protection bits.
    pub fn protect(&self, dest: *const u8) {
        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") crate::enclu::EMODPE,
                in("rcx") dest,
            );
        }
    }
}

#[cfg(test)]
testaso! {
    struct SecInfo: 64, 64 => {
        flags: 0,
        class: 1
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(format!("{}", SecInfo::tcs()), "T");
        assert_eq!(format!("{}", SecInfo::reg(Flags::READ)), "R");
        assert_eq!(format!("{}", SecInfo::reg(Flags::WRITE)), "W");
        assert_eq!(format!("{}", SecInfo::reg(Flags::EXECUTE)), "X");
        assert_eq!(
            format!("{}", SecInfo::reg(Flags::READ | Flags::WRITE)),
            "RW"
        );
        assert_eq!(
            format!("{}", SecInfo::reg(Flags::READ | Flags::EXECUTE)),
            "RX"
        );
        assert_eq!(
            format!("{}", SecInfo::reg(Flags::WRITE | Flags::EXECUTE)),
            "WX"
        );
        assert_eq!(
            format!(
                "{}",
                SecInfo::reg(Flags::READ | Flags::WRITE | Flags::EXECUTE)
            ),
            "RWX"
        );
    }
}
