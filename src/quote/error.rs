// SPDX-License-Identifier: Apache-2.0

use super::header::QuoteVersion;

use core::fmt::{self, Display};

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum QuoteError {
    UnsupportedQuoteVersion(QuoteVersion),
    UnexpectedLength(&'static str, usize, usize),
    InvalidMiscSelect,
    InvalidFeatures,
    InvalidXfrm,
    UnknownCertDataType,
    #[cfg(feature = "quote-cert-chain")]
    UnsupportedCertDataType(&'static str),
    #[cfg(feature = "quote-cert-chain")]
    CertChainParse(String),
}

impl Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteError::UnsupportedQuoteVersion(version) => {
                write!(f, "Unsupported quote version {:?}", version)
            }
            QuoteError::UnexpectedLength(ident, actual, expected) => {
                write!(
                    f,
                    "The {} slice had an unexpected length of {}, expected {}",
                    ident, actual, expected
                )
            }
            QuoteError::InvalidMiscSelect => {
                write!(f, "Invalid misc select",)
            }
            QuoteError::InvalidFeatures => {
                write!(f, "Invalid misc select",)
            }
            QuoteError::InvalidXfrm => {
                write!(f, "Invalid xfrm",)
            }
            QuoteError::UnknownCertDataType => {
                write!(f, "Unknown cert data type",)
            }
            #[cfg(feature = "quote-cert-chain")]
            QuoteError::UnsupportedCertDataType(message) => {
                write!(f, "Unsupported certificate data type: {}", message)
            }
            #[cfg(feature = "quote-cert-chain")]
            QuoteError::CertChainParse(message) => {
                write!(f, "Certificate chain parse error: {}", message)
            }
        }
    }
}
