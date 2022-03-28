// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

use crate::crypto::{EcdsaP256Sig, EcdsaPubKey};

use super::{header::QuoteHeader, report::IsvEnclaveReport};

pub const SIG_SIZE: usize = size_of::<EcdsaP256Sig>();
pub const PUB_KEY_SIZE: usize = size_of::<EcdsaPubKey>();
pub const QUOTE_HEADER_SIZE: usize = size_of::<QuoteHeader>();
pub const REPORT_SIZE: usize = size_of::<IsvEnclaveReport>();
pub const U16_SIZE: usize = size_of::<u16>();
pub const U32_SIZE: usize = size_of::<u32>();

pub const QUOTE_SIG_DATA_LEN_SIZE: usize = U32_SIZE;
pub const QUOTE_SIG_START: usize = QUOTE_HEADER_SIZE + REPORT_SIZE + QUOTE_SIG_DATA_LEN_SIZE;
