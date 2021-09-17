// SPDX-License-Identifier: Apache-2.0

/// The `Class` of a page
///
/// The `Class` type is the `PAGE_TYPE` data structure, merely renamed
/// due to the collision with the Rust `type` keyword.
///
/// Section 38.11.2
#[repr(u8)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Class {
    /// Page is an SECS.
    Secs = 0,
    /// Page is a TCS.
    Tcs = 1,
    /// Page is a regular page.
    Reg = 2,
    /// Page is a Version Array.
    Va = 3,
    /// Page is in trimmed state.
    Trim = 4,
}
