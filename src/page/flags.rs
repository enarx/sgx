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
