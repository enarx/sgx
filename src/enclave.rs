// SPDX-License-Identifier: Apache-2.0

//! Enclave object

extern crate std;

use crate::page::{Class, Flags, SecInfo, Secs};
use crate::signature::Signature;

use std::fs::{File, OpenOptions};
use std::io::Result;
use std::marker::PhantomData;

use iocuddle::Group;

const SGX_IOCTL: u8 = 0xA4;

/// Wraps an enclave file descriptor.
pub struct Enclave(File);

impl From<Enclave> for File {
    fn from(enclave: Enclave) -> File {
        enclave.0
    }
}

impl Enclave {
    /// The path of the device file.
    pub const DEVICE: &'static str = "/dev/sgx_enclave";

    /// Create a new instance.
    pub fn new() -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::DEVICE)
            .map(Self)
    }

    /// Duplicate the file descriptor.
    pub fn try_clone(&mut self) -> Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    /// ENCLS[ECREATE] wrapper
    pub fn create(&mut self, secs: &Secs) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write(0x00) }
            .ioctl(&mut self.0, &Create(secs as *const _ as _, PhantomData))
            .map(|_| ())
    }

    /// ENCLS[EADD] wrapper
    pub fn add_pages(
        &mut self,
        bytes: &[u8],
        offset: usize,
        secinfo: &SecInfo,
        measure: bool,
    ) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write_read(0x01) }
            .ioctl(
                &mut self.0,
                &mut AddPages {
                    src: bytes.as_ptr() as _,
                    offset: offset as _,
                    length: bytes.len() as _,
                    secinfo: secinfo as *const _ as _,
                    flags: measure as _,
                    count: 0,
                    phantom: PhantomData,
                },
            )
            .map(|_| ())
    }

    /// ENCLS[EINIT] wrapper
    pub fn init(&mut self, signature: &Signature) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write(0x02) }
            .ioctl(&mut self.0, &Init(signature as *const _ as _, PhantomData))
            .map(|_| ())
    }

    /// ENCLS[EMODPR] wrapper
    pub fn restrict_permissions(
        &mut self,
        offset: usize,
        length: usize,
        permissions: Flags,
    ) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write_read(0x05) }
            .ioctl(
                &mut self.0,
                &mut RestrictPermissions {
                    offset: offset as _,
                    length: length as _,
                    secinfo: &SecInfo::new(Class::Regular, permissions) as *const _ as _,
                    result: 0,
                    count: 0,
                    phantom: PhantomData,
                },
            )
            .map(|_| ())
    }

    /// ENCLS[EMODT] wrapper
    pub fn modify_types(&mut self, offset: usize, length: usize, class: Class) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write_read(0x06) }
            .ioctl(
                &mut self.0,
                &mut ModifyTypes {
                    offset: offset as _,
                    length: length as _,
                    secinfo: &SecInfo::new(class, Flags::empty()) as *const _ as _,
                    result: 0,
                    count: 0,
                    phantom: PhantomData,
                },
            )
            .map(|_| ())
    }

    /// ENCLS[EREMOVE] wrapper
    pub fn remove_pages(&mut self, offset: usize, length: usize) -> Result<()> {
        // # Safety
        //
        // When used for a wrong device file, ioctl could cause undefined behaviour.
        unsafe { Group::new(SGX_IOCTL).write_read(0x07) }
            .ioctl(
                &mut self.0,
                &mut RemovePages {
                    offset: offset as _,
                    length: length as _,
                    count: 0,
                },
            )
            .map(|_| ())
    }
}

struct Create<'a>(u64, PhantomData<&'a ()>);

#[repr(C)]
struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

#[repr(C)]
pub struct Init<'a>(u64, PhantomData<&'a ()>);

#[repr(C)]
pub struct RestrictPermissions<'a> {
    offset: u64,
    length: u64,
    secinfo: u64,
    result: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

#[repr(C)]
struct ModifyTypes<'a> {
    offset: u64,
    length: u64,
    secinfo: u64,
    result: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

#[repr(C)]
struct RemovePages {
    offset: u64,
    length: u64,
    count: u64,
}

#[cfg(test)]
mod tests {
    use crate::enclave::Enclave;
    use crate::page::{Class, Flags};

    const EINVAL: i32 = 22;

    #[test]
    fn restrict_permissions() {
        let mut enclave = Enclave::new().unwrap();
        assert_eq!(
            enclave
                .restrict_permissions(0, 0, Flags::empty())
                .map_err(|e| e.raw_os_error()),
            Err(Some(EINVAL))
        );
    }

    #[test]
    fn modify_types() {
        let mut enclave = Enclave::new().unwrap();
        assert_eq!(
            enclave
                .modify_types(0, 0, Class::Regular)
                .map_err(|e| e.raw_os_error()),
            Err(Some(EINVAL))
        );
    }

    #[test]
    fn remove_pages() {
        let mut enclave = Enclave::new().unwrap();
        assert_eq!(
            enclave.remove_pages(0, 0).map_err(|e| e.raw_os_error()),
            Err(Some(EINVAL))
        );
    }
}
