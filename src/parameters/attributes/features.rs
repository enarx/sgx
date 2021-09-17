// SPDX-License-Identifier: Apache-2.0

bitflags::bitflags! {
    /// Expresses the non-XSAVE related enclave features
    #[derive(Default)]
    pub struct Features: u64 {
        /// Enclave has been initialized by EINIT
        ///
        /// Note that this flag MUST be cleared when loading the enclave and,
        /// conversly, MUST be set when validating an attestation.
        const INIT = 1 << 0;

        /// Enables enclave debug mode
        ///
        /// This gives permission to use EDBGRD and EDBGWR to read and write
        /// enclave memory as plaintext, respectively. You most likely want
        /// to validate that this option is disabled during attestion.
        const DEBUG = 1 << 1;

        /// Enables enclave 64-bit mode
        const MODE64BIT = 1 << 2;

        /// Enables use of the provisioning key via EGETKEY
        const PROVISIONING_KEY = 1 << 4;

        /// Enables use of the EINIT token key via EGETKEY
        const EINIT_KEY = 1 << 5;

        /// Enables CET attributes
        const CET = 1 << 6;

        /// Enables key separation and sharing
        const KSS = 1 << 7;
    }
}
