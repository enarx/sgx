// SPDX-License-Identifier: Apache-2.0

//! This module implements Intel SGX-related IOCTLs using the iocuddle crate.
//! All references to Section or Tables are from
//! [Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3D: System Programming Guide, Part 4](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf)

use crate::page::{SecInfo, Secs};
use crate::signature::Signature;

use core::marker::PhantomData;

use iocuddle::*;

const SGX_IOC: Group = Group::new(0xA4);

pub const ENCLAVE_CREATE: Ioctl<Write, &Create<'_>> = unsafe { SGX_IOC.write(0x00) };
pub const ENCLAVE_ADD_PAGES: Ioctl<WriteRead, &AddPages<'_>> = unsafe { SGX_IOC.write_read(0x01) };
pub const ENCLAVE_INIT: Ioctl<Write, &Init<'_>> = unsafe { SGX_IOC.write(0x02) };
pub const ENCLAVE_RESTRICT_PERMISSIONS: Ioctl<WriteRead, &RestrictPermissions<'_>> =
    unsafe { SGX_IOC.write_read(0x06) };

#[repr(C)]
#[derive(Debug)]
/// Parameters for ENCLAVE_CREATE.
pub struct Create<'a>(u64, PhantomData<&'a ()>);

impl<'a> Create<'a> {
    /// Create a new instance.
    pub fn new(secs: &'a Secs) -> Self {
        Create(secs as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Parameters for ENCLAVE_ADD_PAGES.
pub struct AddPages<'a> {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> AddPages<'a> {
    /// Create a new instance.
    pub fn new(bytes: &'a [u8], offset: usize, secinfo: &'a SecInfo, measure: bool) -> Self {
        const MEASURE: u64 = 1 << 0;

        let flags = match measure {
            true => MEASURE,
            false => 0,
        };

        Self {
            src: bytes.as_ptr() as _,
            offset: offset as _,
            length: bytes.len() as _,
            secinfo: secinfo as *const _ as _,
            flags,
            count: 0,
            phantom: PhantomData,
        }
    }

    /// Read the count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[repr(C)]
#[derive(Debug)]
/// Parameters for ENCLAVE_INIT.
pub struct Init<'a>(u64, PhantomData<&'a ()>);

impl<'a> Init<'a> {
    /// Create a new instance.
    pub fn new(sig: &'a Signature) -> Self {
        Init(sig as *const _ as _, PhantomData)
    }
}

#[repr(C)]
#[derive(Debug)]
/// Parameters for ENCLAVE_RESTRICT_PERMISSIONS.
pub struct RestrictPermissions<'a> {
    /// In: starting page offset
    offset: u64,
    /// In: length of the address range (multiple of the page size)
    length: u64,
    /// In: SECINFO containing the relaxed permissions
    secinfo: u64,
    /// Out: ENCLU[EMODPR] return value
    result: u64,
    /// Out: length of the address range successfully changed
    count: u64,
    phantom: PhantomData<&'a ()>,
}

impl<'a> RestrictPermissions<'a> {
    /// Create a new RestrictPermissions instance.
    pub fn new(offset: usize, length: usize, secinfo: &'a SecInfo) -> Self {
        Self {
            offset: offset as _,
            length: length as _,
            secinfo: secinfo as *const _ as _,
            result: 0,
            count: 0,
            phantom: PhantomData,
        }
    }

    /// Read the result attribute.
    pub fn result(&self) -> u64 {
        self.count
    }

    /// Read the count attribute.
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::Flags;
    use std::fs::OpenOptions;

    const EINVAL: i32 = 22;
    const ENOTTY: i32 = 25;

    #[test]
    fn restrict_permissions() {
        let mut device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")
            .unwrap();

        let secinfo = SecInfo::reg(Flags::empty());
        let mut parameters = RestrictPermissions::new(0, 0, &secinfo);

        let ret = match ENCLAVE_RESTRICT_PERMISSIONS.ioctl(&mut device_file, &mut parameters) {
            Ok(_) => 0,
            Err(err) => err.raw_os_error().unwrap(),
        };

        assert!(ret == ENOTTY || ret == EINVAL);
    }
}
