// SPDX-License-Identifier: Apache-2.0

//! A trait for loading pages into an enclave

use super::types::page::SecInfo;

use flagset::{flags, FlagSet};
use primordial::Page;

flags! {
    /// Flags which affect how pages get loaded
    pub enum Flags: usize {
        /// Measure the page contents during load
        Measure,
    }
}

/// This trait represents the ability to load pages into an enclave
pub trait Loader {
    /// The error that could occur
    type Error;

    /// Load the specified pages into the enclave at the specified page offset
    ///
    /// Note well that the `offset` parameter is in pages, not bytes!
    fn load(
        &mut self,
        pages: impl AsRef<[Page]>,
        offset: usize,
        secinfo: SecInfo,
        flags: impl Into<FlagSet<Flags>>,
    ) -> Result<(), Self::Error>;
}
