// SPDX-License-Identifier: Apache-2.0

use openssl::error::ErrorStack;
use std::fmt;

#[derive(Clone, Debug)]
/// Error type for Verify module
pub struct VerifyError(pub String);

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl std::error::Error for VerifyError {}

impl From<ErrorStack> for VerifyError {
    fn from(e: ErrorStack) -> Self {
        VerifyError(format!("ErrorStack: {:?}", e.errors()))
    }
}
