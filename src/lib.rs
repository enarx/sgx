// SPDX-License-Identifier: Apache-2.0

//! This crate contains types for building an Intel SGX implementation.
//!
//! Fully understanding the contents of this crate will likely require access
//! to the [Intel Software Developer Manual](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html).
//!
//! How to use this crate partly depends on what you are trying to accomplish:
//!
//!   1. If you are an enclave developer, you probably want the `parameters`
//!      and `ssa` modules.
//!   2. If you are signing an enclave, you probably want the `signature` and
//!      `crypto` modules.
//!   3. If you are developing an enclave loader, you probably want the
//!      `parameters` and `page` modules. However, you may also want the
//!      `signature` module to load a signature.
//!   4. If you want to parse fields from the CPU certificate, you probably
//!      want the `pck` module and `rcrypto` feature.

#![no_std]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::all)]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod crypto;
pub mod page;
pub mod parameters;
pub mod signature;

#[cfg(feature = "rcrypto")]
pub mod pck;

#[cfg(target_arch = "x86_64")]
pub mod ssa;

/// SGX ENCLU Leaf Instructions
pub mod enclu {
    pub const EREPORT: usize = 0x00;
    pub const EGETKEY: usize = 0x01;
    pub const EENTER: usize = 0x02;
    pub const ERESUME: usize = 0x03;
    pub const EEXIT: usize = 0x04;
    pub const EACCEPT: usize = 0x05;
    pub const EMODPE: usize = 0x06;
    pub const EACCEPTCOPY: usize = 0x07;
}

mod report;

pub use report::{Report, ReportBody};
