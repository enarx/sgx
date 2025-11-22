// SPDX-License-Identifier: Apache-2.0

//! SGX PCK Certificate parsing
//!
//! see 1.3.5 Intel® SGX PCK Certificate of https://download.01.org/intel-sgx/sgx-dcap/1.10.3/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Enumerated, Sequence};

#[derive(Sequence)]
pub struct SgxExtensionRaw<'a> {
    pub ppid: PpID<'a>,
    pub tcb: Tcb<'a>,
    pub pceid: PceID<'a>,
    pub fmspc: FmSpc<'a>,
    pub sgx_type: SGXType,
    pub platform_instance: Option<PlatformInstanceID<'a>>, // Only on multi-CPU "Platform" systems
    pub platform_config: Option<PlatformConfiguration>,    // Only on multi-CPU "Platform" systems
}

impl AssociatedOid for SgxExtensionRaw<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
}

#[derive(Sequence)]
pub struct PpID<'a> {
    pub oid: ObjectIdentifier,

    #[asn1(type = "OCTET STRING")]
    pub bytes: &'a [u8],
}

impl AssociatedOid for PpID<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.1");
}

#[derive(Sequence)]
pub struct Tcb<'a> {
    pub oid: ObjectIdentifier, // 1.2.840.113741.1.13.1.2
    pub inner: TCBInner<'a>,
}

impl AssociatedOid for Tcb<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
}

#[derive(Sequence)]
pub struct TCBInner<'a> {
    pub tcb1: TCBElement, // 1.2.840.113741.1.13.1.2.1
    pub tcb2: TCBElement, // 1.2.840.113741.1.13.1.2.2
    pub tcb3: TCBElement,
    pub tcb4: TCBElement,
    pub tcb5: TCBElement,
    pub tcb6: TCBElement,
    pub tcb7: TCBElement,
    pub tcb8: TCBElement,
    pub tcb9: TCBElement,
    pub tcb10: TCBElement,
    pub tcb11: TCBElement,
    pub tcb12: TCBElement,
    pub tcb13: TCBElement,
    pub tcb14: TCBElement,
    pub tcb15: TCBElement,
    pub tcb16: TCBElement,
    pub pcesvn: TcbPceSvn,
    pub cpusvn: TcbCpuSvn<'a>,
}

#[derive(Sequence)]
pub struct TCBElement {
    pub oid: ObjectIdentifier,
    pub value: u8,
}

#[derive(Sequence)]
pub struct TcbPceSvn {
    pub oid: ObjectIdentifier,
    pub value: u8,
}

impl AssociatedOid for TcbPceSvn {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.17");
}

#[derive(Sequence)]
pub struct TcbCpuSvn<'a> {
    pub oid: ObjectIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub bytes: &'a [u8],
}

impl AssociatedOid for TcbCpuSvn<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.18");
}

#[derive(Sequence)]
pub struct PceID<'a> {
    pub oid: ObjectIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub bytes: &'a [u8],
}

impl AssociatedOid for PceID<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.3");
}

#[derive(Sequence)]
pub struct FmSpc<'a> {
    pub oid: ObjectIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub bytes: &'a [u8],
}

impl AssociatedOid for FmSpc<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
}

#[derive(Sequence)]
pub struct SGXType {
    pub oid: ObjectIdentifier,
    pub sgx_type: SGXEnumeration,
}

impl AssociatedOid for SGXType {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.5");
}

#[derive(Enumerated, Copy, Clone)]
#[repr(u8)]
pub enum SGXEnumeration {
    Standard = 0,
    Scalable = 1,
}

// The following items are only present on multi-CPU systems

#[derive(Sequence)]
pub struct PlatformInstanceID<'a> {
    pub oid: ObjectIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub bytes: &'a [u8],
}

impl AssociatedOid for PlatformInstanceID<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.6");
}

#[derive(Sequence)]
pub struct PlatformConfiguration {
    pub oid: ObjectIdentifier,
    pub inner: PlatformConfigurationInner,
}

impl AssociatedOid for PlatformConfiguration {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.7");
}

#[derive(Sequence)]
pub struct PlatformConfigurationInner {
    pub dynamic: DynamicPlatform,
    pub cached_keys: CachedKeys,
    pub smt: SMTEnabled,
}

#[derive(Sequence)]
pub struct DynamicPlatform {
    pub oid: ObjectIdentifier,
    pub is_dynamic: bool,
}

impl AssociatedOid for DynamicPlatform {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.7.1");
}

#[derive(Sequence)]
pub struct CachedKeys {
    pub oid: ObjectIdentifier,
    pub cached_keys: bool,
}

impl AssociatedOid for CachedKeys {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.7.2");
}

#[derive(Sequence)]
pub struct SMTEnabled {
    pub oid: ObjectIdentifier,
    pub has_smt: bool,
}

impl AssociatedOid for SMTEnabled {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.7.3");
}
