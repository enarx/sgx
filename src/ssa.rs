// SPDX-License-Identifier: Apache-2.0

//! State Save Area (SSA)
//!
//! The types in this module are typically used by an enclave.
//!
//! When an AEX occurs while running in an enclave, the architectural state is
//! saved in the thread’s current SSA frame. An enclave can view the CPU state
//! from a previous AEX by finding the current SSA frame using the CSSA and
//! casing a pointer to this frame to a `StateSaveArea` reference.

#![allow(clippy::unreadable_literal)]

use core::mem::{size_of_val, transmute};

pub use x86_64::structures::idt::ExceptionVector as Vector;
pub use xsave::XSave;

/// Section 38.9.1.1, Table 38-9
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExitType {
    Hardware,
    Software,
}

/// Section 38.9.1, Table 38-8
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct GenPurposeRegs {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64,
    pub ursp: u64,
    pub urbp: u64,
    exitinfo: u32,
    reserved: u32,
    pub fsbase: u64,
    pub gsbase: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ExInfo {
    pub maddr: u64,
    pub errcd: u32,
    reserved: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Misc {
    pub exinfo: ExInfo,
}

/// When an AEX occurs while running in an enclave, the architectural state is saved
/// in the thread’s current StateSaveArea (SSA Frame), which is pointed to by TCS.CSSA.
///
/// Section 38.9, Table 38-7
#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
pub struct StateSaveArea<T = [u8; 824]> {
    /// Area for saving and restoring the XSAVE-managed state components
    pub xsave: XSave,

    /// Padding
    pub extra: T,

    /// Contains Exception Info (error condition, memory address)
    pub misc: Misc,

    /// Contains Exit Info (exit and exception type)
    pub gpr: GenPurposeRegs,
}

impl<T> StateSaveArea<T> {
    const VALID: u32 = 1 << 31;

    #[inline]
    pub fn exit_type(&self) -> Option<ExitType> {
        assert_eq!(size_of_val(self) % 4096, 0);

        if self.gpr.exitinfo & Self::VALID == 0 {
            return None;
        }

        match (self.gpr.exitinfo >> 8) & 0b111 {
            0b011 => Some(ExitType::Hardware),
            0b110 => Some(ExitType::Software),
            _ => None,
        }
    }

    #[inline]
    pub fn vector(&self) -> Option<Vector> {
        match self.gpr.exitinfo & Self::VALID {
            0 => None,
            _ => Some(unsafe {
                transmute::<u8, x86_64::structures::idt::ExceptionVector>(self.gpr.exitinfo as u8)
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use testaso::testaso;

    testaso! {
        struct GenPurposeRegs: 8, 184 => {
            rax: 0,
            rcx: 8,
            rdx: 16,
            rbx: 24,
            rsp: 32,
            rbp: 40,
            rsi: 48,
            rdi: 56,
            r8: 64,
            r9: 72,
            r10: 80,
            r11: 88,
            r12: 96,
            r13: 104,
            r14: 112,
            r15: 120,
            rflags: 128,
            rip: 136,
            ursp: 144,
            urbp: 152,
            exitinfo: 160,
            reserved: 164,
            fsbase: 168,
            gsbase: 176
        }

        struct ExInfo: 8, 16 => {
            maddr: 0,
            errcd: 8,
            reserved: 12
        }

        struct Misc: 8, 16 => {
            exinfo: 0
        }

        struct StateSaveArea<[u8; 824]>: 4096, 4096 => {
            xsave: 0,
            extra: 3072,
            misc: 3896,
            gpr: 3912
        }
    }
}
