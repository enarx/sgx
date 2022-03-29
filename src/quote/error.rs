// SPDX-License-Identifier: Apache-2.0

use core::fmt::{self, Display};

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum QuoteError {
    InvalidMiscSelect(u32),
    InvalidFeatures(u64),
    InvalidXfrm(u64),
}

impl Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteError::InvalidMiscSelect(value) => {
                write!(f, "Invalid misc select: {}", value)
            }
            QuoteError::InvalidFeatures(value) => {
                write!(f, "Invalid misc select: {}", value)
            }
            QuoteError::InvalidXfrm(value) => {
                write!(f, "Invalid xfrm: {}", value)
            }
        }
    }
}
