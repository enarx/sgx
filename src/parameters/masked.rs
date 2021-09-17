// SPDX-License-Identifier: Apache-2.0

use core::ops::{BitAnd, BitOr, Not};

/// A data type mask
///
/// This type succinctly describes a masked type.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Masked<T: BitAnd<Output = T>> {
    pub data: T,
    pub mask: T,
}

impl<T> Default for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Default,
    T: Copy,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T> From<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: BitOr<Output = T>,
    T: Not<Output = T>,
    T: Copy,
{
    fn from(value: T) -> Self {
        Self {
            data: value,
            mask: value | !value,
        }
    }
}

impl<T> PartialEq<T> for Masked<T>
where
    T: BitAnd<Output = T>,
    T: PartialEq,
    T: Copy,
{
    fn eq(&self, other: &T) -> bool {
        self.mask & self.data == self.mask & *other
    }
}
