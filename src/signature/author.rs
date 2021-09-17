// SPDX-License-Identifier: Apache-2.0

/// The `Author` of an enclave
///
/// This structure encompasses the first block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Author {
    /// Constant byte string.
    header1: u128,
    /// Vendor.
    pub vendor: u32,
    /// YYYYMMDD in BCD.
    pub date: u32,
    /// Constant byte string.
    header2: u128,
    /// Software-defined value.
    pub swdefined: u32,
    reserved: [u32; 21],
}

impl Author {
    #[allow(clippy::unreadable_literal)]
    /// Creates a new Author from a date and software defined value.
    pub const fn new(date: u32, swdefined: u32) -> Self {
        Self {
            header1: u128::from_be(0x06000000E10000000000010000000000),
            vendor: 0u32,
            date,
            header2: u128::from_be(0x01010000600000006000000001000000),
            swdefined,
            reserved: [0; 21],
        }
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
        let author = Author::new(20000330, 0u32);
        assert_eq!(
            author.header1,
            u128::from_be(0x06000000E10000000000010000000000)
        );
        assert_eq!(author.vendor, 0u32);
        assert_eq!(
            author.header2,
            u128::from_be(0x01010000600000006000000001000000)
        );
        assert_eq!(author.swdefined, 0u32);
        assert_eq!(author.reserved, [0; 21]);
    }
}
