// SPDX-License-Identifier: Apache-2.0

use crate::parameters::{Attributes, Masked, MiscSelect, Parameters};

impl Parameters {
    /// Creates a signature body
    ///
    /// This call creates a signature `Body` using the provided parameters and
    /// `mrenclave` value.
    ///
    /// Note that the `Masked` types in `Parameters` are interpreted as follows:
    ///   * `data`: contains the features the enclave author desires
    ///   * `mask`: contains the features the enclave author requires
    pub fn body(&self, mrenclave: [u8; 32]) -> Body {
        Body {
            misc: self.misc,
            cet_attr: Masked { data: 0, mask: 0 },
            reserved0: [0; 2],
            ext_fid: [0; 16],
            attr: self.attr,
            mrenclave,
            reserved1: [0; 16],
            ext_pid: self.ext_pid,
            pid: self.pid,
            svn: self.svn,
        }
    }
}

/// The enclave signature body
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Body {
    misc: Masked<MiscSelect>,
    cet_attr: Masked<u8>,
    reserved0: [u8; 2],
    ext_fid: [u8; 16],
    attr: Masked<Attributes>,
    mrenclave: [u8; 32],
    reserved1: [u8; 16],
    ext_pid: [u8; 16],
    pid: u16,
    svn: u16,
}

impl core::fmt::Debug for Body {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Body")
            .field("misc", &self.misc)
            //.field("reserved0", &self.reserved0)
            .field("attr", &self.attr)
            .field("mrenclave", &self.mrenclave)
            //.field("reserved1", &self.reserved1)
            .field("pid", &self.pid)
            .field("svn", &self.svn)
            .finish()
    }
}

impl Body {
    /// Get the enclave measure hash
    pub fn mrenclave(&self) -> [u8; 32] {
        self.mrenclave
    }

    /// Get the enclave parameters
    pub fn parameters(&self) -> Parameters {
        Parameters {
            pid: self.pid,
            svn: self.svn,
            misc: self.misc,
            attr: self.attr,
            ext_pid: self.ext_pid,
            ext_fid: self.ext_fid,
        }
    }
}

#[cfg(test)]
mod test {
    use super::Body;
    use testaso::testaso;

    testaso! {
        struct Body: 4, 128 => {
            misc: 0,
            cet_attr: 8,
            reserved0: 10,
            ext_fid: 12,
            attr: 28,
            mrenclave: 60,
            reserved1: 92,
            ext_pid: 108,
            pid: 124,
            svn: 126
        }
    }
}
