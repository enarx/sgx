// SPDX-License-Identifier: Apache-2.0

bitflags::bitflags! {
    /// The flags of a page
    ///
    /// This type identifies the flags of one or more pages. Some of these
    /// flags indicate permissions. Others, indicate state.
    pub struct Flags: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;

        const PENDING = 1 << 3;
        const MODIFIED = 1 << 4;
        const RESTRICTED = 1 << 5;
    }
}

impl core::fmt::Display for Flags {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let opts = [
            (Self::READ, 'R'),
            (Self::WRITE, 'W'),
            (Self::EXECUTE, 'X'),
            (Self::PENDING, 'P'),
            (Self::MODIFIED, 'M'),
            (Self::RESTRICTED, '!'),
        ];

        for (flag, val) in opts {
            if self.contains(flag) {
                write!(f, "{}", val)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(format!("{}", Flags::READ), "R");
        assert_eq!(format!("{}", Flags::WRITE), "W");
        assert_eq!(format!("{}", Flags::EXECUTE), "X");
        assert_eq!(format!("{}", Flags::READ | Flags::WRITE), "RW");
        assert_eq!(format!("{}", Flags::READ | Flags::EXECUTE), "RX");
        assert_eq!(format!("{}", Flags::WRITE | Flags::EXECUTE), "WX");
        assert_eq!(
            format!("{}", Flags::READ | Flags::WRITE | Flags::EXECUTE),
            "RWX"
        );
    }
}
