// SPDX-License-Identifier: Apache-2.0

bitflags::bitflags! {
    /// The permissions of a page
    pub struct Perms: u8 {
        /// The page can be read from inside the enclave
        const READ = 1 << 0;

        /// The page can be written from inside the enclave
        const WRITE = 1 << 1;

        /// The page can be executed from inside the enclave
        const EXECUTE = 1 << 2;

        /// The page is in the PENDING state
        const PENDING = 1 << 3;

        /// The page is in the MODIFIED state
        const MODIFIED = 1 << 4;

        /// A permission restriction operation on the page is in progress
        const RESTRICTED = 1 << 5;
    }
}
