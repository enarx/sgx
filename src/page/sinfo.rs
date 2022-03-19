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

impl SecInfo {
    /// Create a new instance.
    #[inline]
    pub fn new(class: Class, flags: impl Into<Option<Flags>>) -> SecInfo {
        let flags = match flags.into() {
            Some(flags) => flags,
            None => {
                match class {
                    // A CPU constraint
                    Class::Regular => Flags::READ,
                    _ => Flags::empty(),
                }
            }
        };

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
