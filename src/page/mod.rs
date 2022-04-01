// SPDX-License-Identifier: Apache-2.0

//! Page-related structures
//!
//! The most important structures in thie module are:
//!   1. `Secs`: controls enclave features during creation
//!   2. `SecInfo`: controls access permissions for enclave pages

mod class;
mod flags;
mod secs;
mod sinfo;

pub use class::Class;
pub use flags::Flags;
pub use secs::Secs;
pub use sinfo::AcceptError;
pub use sinfo::SecInfo;
