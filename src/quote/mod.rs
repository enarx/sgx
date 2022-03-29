// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! <https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf>
//!
//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! <https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf>

pub mod error;
pub mod header;
pub mod report;
