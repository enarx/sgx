// SPDX-License-Identifier: Apache-2.0

/// The `Author` of an enclave
///
/// This structure encompasses the first block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Author {
    header1: u128,
    vendor: u32,
    date: u32,
    header2: u128,
    swdefined: u32,
    reserved: [u32; 21],
}

impl Author {
    const HEADER1: u128 = u128::from_be(0x0600_0000_E100_0000_0000_0100_0000_0000);
    const HEADER2: u128 = u128::from_be(0x0101_0000_6000_0000_6000_0000_0100_0000);

    #[allow(clippy::unreadable_literal)]
    /// Creates a new Author from a date and software defined value.
    ///
    /// Note that the `date` input is defined in binary-coded decimal. For
    /// example, the unix epoch is: `0x1970_01_01`.
    pub const fn new(date: u32, swdefined: u32) -> Self {
        Self {
            header1: Self::HEADER1,
            vendor: 0,
            date,
            header2: Self::HEADER2,
            swdefined,
            reserved: [0; 21],
        }
    }

    #[inline]
    pub fn date(&self) -> u32 {
        self.date
    }

    #[inline]
    pub fn swdefined(&self) -> u32 {
        self.swdefined
    }
}

#[cfg(test)]
testaso! {
    struct Author: 8, 128 => {
        header1: 0,
        vendor: 16,
        date: 20,
        header2: 24,
        swdefined: 40,
        reserved: 44
    }
}

#[cfg(test)]
mod test {
    use super::Author;

    #[test]
    fn author_instantiation() {
        let author = Author::new(0x2000_03_30, 0u32);
        assert_eq!(author.header1, Author::HEADER1);
        assert_eq!(author.vendor, 0u32);
        assert_eq!(author.date, 0x2000_03_30);
        assert_eq!(author.header2, Author::HEADER2);
        assert_eq!(author.swdefined, 0u32);
        assert_eq!(author.reserved, [0; 21]);
    }
}
