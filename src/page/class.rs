// SPDX-License-Identifier: Apache-2.0

/// The class of a page
///
/// This enumeration identifies the kind of one or more pages. This type is
/// named `PAGE_TYPE` in the Intel documentation.
#[repr(u8)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Class {
    Secs = 0,
    Tcs = 1,
    Reg = 2,
    Va = 3,
    Trim = 4,
}
