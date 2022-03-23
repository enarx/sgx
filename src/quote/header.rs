// SPDX-License-Identifier: Apache-2.0

/// The type of attestation key used to sign the Report.
///
/// ECDSA: <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum KeyType {
    /// ECDSA-256-with-P-256 curve
    ES256 = 2,
    /// ECDSA-384-with-P-384 curve
    ES384 = 3,
}

/// The version of the quote.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum QuoteVersion {
    V3 = 3,
}
