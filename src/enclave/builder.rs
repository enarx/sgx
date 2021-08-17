// SPDX-License-Identifier: Apache-2.0

use super::{ioctls, Enclave};
use crate::loader::{Flags, Loader};
use crate::types::page::{self, Class, SecInfo};
use crate::types::{secs::*, sig::*};

use lset::Span;
use mmarinus::{perms, Kind, Map};
use primordial::Page;

use std::fs::{File, OpenOptions};
use std::io::Result;
use std::mem::forget;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

/// An SGX enclave builder
///
/// TODO add more comprehensive docs.
pub struct Builder {
    file: File,
    mmap: Map<perms::Unknown>,
    perm: Vec<(Span<usize>, SecInfo)>,
    tcsp: Vec<usize>,
}

impl Builder {
    /// Creates a new `Builder` instance. The input linear memory `span` is mapped
    /// into SGX's EPC. This function issues `ECREATE` instruction.
    ///
    /// TODO add more comprehensive docs
    pub fn new(
        span: impl Into<Span<usize>>,
        ssa_pages: NonZeroU32,
        parameters: Parameters,
    ) -> Result<Self> {
        let span = span.into();

        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")?;

        // Map the memory for the enclave
        let mmap = Map::map(span.count)
            .at(span.start)
            .anonymously()
            .known::<perms::None>(Kind::Private)?
            .into();

        // Create the enclave.
        let secs = Secs::new(span, ssa_pages, parameters);
        let create = ioctls::Create::new(&secs);
        ioctls::ENCLAVE_CREATE.ioctl(&mut file, &create)?;

        Ok(Self {
            file,
            mmap,
            perm: Vec::new(),
            tcsp: Vec::new(),
        })
    }

    /// Consumes this `Builder` and finalizes SGX enclave by generating
    /// signing keys, initializing the enclave, etc. This function issues
    /// `EINIT` instruction.
    ///
    /// TODO add more comprehensive docs.
    pub fn build(mut self, signature: &Signature) -> Result<Arc<Enclave>> {
        // Initialize the enclave.
        let init = ioctls::Init::new(signature);
        ioctls::ENCLAVE_INIT.ioctl(&mut self.file, &init)?;

        // Fix up mapped permissions.
        self.perm.sort_by(|l, r| l.0.start.cmp(&r.0.start));
        for (span, si) in self.perm {
            let rwx = match si.class {
                Class::Tcs => libc::PROT_READ | libc::PROT_WRITE,
                Class::Reg => {
                    let mut prot = libc::PROT_NONE;

                    if si.flags.contains(page::Flags::R) {
                        prot |= libc::PROT_READ;
                    }

                    if si.flags.contains(page::Flags::W) {
                        prot |= libc::PROT_WRITE;
                    }

                    if si.flags.contains(page::Flags::X) {
                        prot |= libc::PROT_EXEC;
                    }

                    prot
                }
                _ => panic!("Unsupported class!"),
            };

            // Change the permissions on an existing region of memory.
            forget(unsafe {
                Map::map(span.count)
                    .onto(span.start)
                    .from(&mut self.file, 0)
                    .unknown(Kind::Shared, rwx)?
            });

            //let line = lset::Line::from(span);
            //eprintln!("{:016x}-{:016x} {:?}", line.start, line.end, si);
        }

        Ok(Arc::new(Enclave {
            _mem: self.mmap,
            tcs: RwLock::new(self.tcsp),
        }))
    }
}

impl Loader for Builder {
    type Error = std::io::Error;

    fn load(
        &mut self,
        pages: impl AsRef<[Page]>,
        offset: usize,
        secinfo: SecInfo,
        flags: impl Into<flagset::FlagSet<Flags>>,
    ) -> Result<()> {
        let offset = offset * Page::size();
        let pages = pages.as_ref();
        let flags = flags.into();

        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        // Update the enclave.
        let mut ap = ioctls::AddPages::new(pages, offset, &secinfo, flags);
        ioctls::ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

        // Calculate an absolute span for this region.
        let span = Span {
            start: self.mmap.addr() + offset,
            count: pages.len() * Page::size(),
        };

        // Save permissions fixups for later.
        self.perm.push((span, secinfo));

        // Keep track of TCS pages.
        if secinfo.class == page::Class::Tcs {
            for i in 0..pages.len() {
                self.tcsp.push(span.start + i * Page::size());
            }
        }

        Ok(())
    }
}
