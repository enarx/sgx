// SPDX-License-Identifier: Apache-2.0

use crate::quote::error::QuoteError;

/// Try to cast a byte slice into a statically sized type.
pub fn slice_cast<'a, const SIZE: usize>(
    identifier: &'static str,
    slice: &'a [u8],
) -> Result<&'a [u8; SIZE], QuoteError> {
    slice
        .try_into()
        .map_err(|_| QuoteError::UnexpectedLength(identifier, slice.len(), SIZE))
}
