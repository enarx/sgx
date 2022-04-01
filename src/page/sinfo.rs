// SPDX-License-Identifier: Apache-2.0

use super::{Class, Flags};
use crate::enclu::{EACCEPT, EACCEPTCOPY, EMODPE};

use core::arch::asm;

use x86_64::structures::paging::Page;

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
            Class::Regular => write!(f, "{}", self.flags),
            Class::VersionArray => write!(f, "V"),
            Class::Trimmed => write!(f, "^"),
            Class::ShadowStackFirst => write!(f, "F"),
            Class::ShadowStackRest => write!(f, "R"),
        }
    }
}

impl From<Class> for SecInfo {
    fn from(class: Class) -> Self {
        SecInfo::new(class, None)
    }
}

/// Error codes for `SecInfo::accept()`
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptError {
    /// CPU cores have not exited from the previous grace period.
    PageNotTracked,
    /// Attributes of the destination page are incorrect.
    PageAttributesMismatch,
}

impl SecInfo {
    /// Create a new instance.
    #[inline]
    pub fn new(class: Class, flags: impl Into<Option<Flags>>) -> SecInfo {
        let flags = flags.into().unwrap_or_else(|| match class {
            // A CPU constraint for SGX2 instructions
            Class::Regular => Flags::READ,
            _ => Flags::empty(),
        });

        Self {
            class,
            flags,
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

    /// Acknowledge ENCLS[EAUG], ENCLS[EMODT] and ENCLS[EMODPR] from the host.
    #[inline]
    pub fn accept(&self, dest: Page) -> Result<(), AcceptError> {
        let ret;

        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") EACCEPT,
                in("rcx") dest.start_address().as_u64(),
                lateout("rax") ret,
            );
        }

        match ret {
            0 => Ok(()),
            11 => Err(AcceptError::PageNotTracked),
            19 => Err(AcceptError::PageAttributesMismatch),
            ret => panic!("EACCEPT returned an unknown error code: {}", ret),
        }
    }

    /// Acknowledge ENCLS[EAUG] from the host.
    #[inline]
    pub fn accept_copy(&self, dest: Page, src: Page) -> Result<(), AcceptError> {
        let ret;

        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") EACCEPTCOPY,
                in("rcx") dest.start_address().as_u64(),
                in("rdx") src.start_address().as_u64(),
                lateout("rax") ret,
            );
        }

        match ret {
            0 => Ok(()),
            19 => Err(AcceptError::PageAttributesMismatch),
            ret => panic!("EACCEPTCOPY returned an unknown error code: {}", ret),
        }
    }

    /// Extend page permissions.
    #[inline]
    pub fn extend_permissions(&self, dest: Page) {
        unsafe {
            asm!(
                "xchg       {RBX}, rbx",
                "enclu",
                "mov        rbx, {RBX}",

                RBX = inout(reg) self => _,
                in("rax") EMODPE,
                in("rcx") dest.start_address().as_u64(),
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
        assert_eq!(format!("{}", SecInfo::from(Class::Tcs)), "T");
        assert_eq!(format!("{}", SecInfo::from(Class::Regular)), "R");
        assert_eq!(format!("{}", Class::Regular.info(Flags::WRITE)), "W");
        assert_eq!(format!("{}", Class::Regular.info(Flags::EXECUTE)), "X");
        assert_eq!(
            format!("{}", Class::Regular.info(Flags::READ | Flags::WRITE)),
            "RW"
        );
        assert_eq!(
            format!("{}", Class::Regular.info(Flags::READ | Flags::EXECUTE)),
            "RX"
        );
        assert_eq!(
            format!("{}", Class::Regular.info(Flags::WRITE | Flags::EXECUTE)),
            "WX"
        );
        assert_eq!(
            format!(
                "{}",
                Class::Regular.info(Flags::READ | Flags::WRITE | Flags::EXECUTE)
            ),
            "RWX"
        );
    }
}
