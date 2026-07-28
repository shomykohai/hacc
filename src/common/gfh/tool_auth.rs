use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::header::GfhHeader;
use super::{Gfh, GfhError, GfhSigPadType};
use crate::error::{Error, Result};
use crate::gfh::CtM1Key;
use crate::gfh::header::GfhType;
use crate::traits::TryRead;

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct GfhToolAuth {
    pub header: GfhHeader,
    pub cust_name: [u8; 32],
    pub attr: u32,
    pub brom_verified_num: u32,
    pub da_hash_num: u32,
    pub da_hash: [[u8; 32]; 10],
    pub sbc_public_key: CtM1Key,
    pub sla_public_key: CtM1Key,
    pub daa_public_key: CtM1Key,
}

impl GfhToolAuth {
    const DAA_ATTR_MASK: u32 = 0x0000FFFF;
    const DAA_M1_CLEAR_MASK: u32 = 0x0FFFFFFF;
    const DAA_PSS_ATTR: u32 = 0xC2620000;
    const MAX_DA_HASH_NUM: u32 = 10;
    const SIZE: usize = size_of::<Self>();
    const SLA_ATTR_MASK: u32 = 0xFFFF0FFF;
    const SLA_M1_ATTR: u32 = 0x1000;
    const SLA_M1_CLEAR_MASK: u32 = 0x0FFFFFFF;
    const SLA_PSS_ATTR: u32 = 0x6000;

    pub const fn attr(&self) -> u32 {
        self.attr
    }

    pub fn customer_name(&self) -> &str {
        core::str::from_utf8(&self.cust_name).unwrap_or("MTK").trim_end_matches('\0')
    }

    pub const fn set_attr(&mut self, attr: u32) {
        self.attr = attr;
    }

    pub fn set_customer_name(&mut self, name: &str) {
        let mut new_name = [0u8; 32];
        let bytes = name.as_bytes();
        new_name[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        self.cust_name = new_name;
    }

    pub const fn set_sla_pad_type(&mut self, pad_type: GfhSigPadType) {
        self.attr &= Self::SLA_ATTR_MASK;
        match pad_type {
            GfhSigPadType::Pss => {
                self.attr |= Self::SLA_PSS_ATTR;
            }
            GfhSigPadType::M1 => {
                self.attr |= Self::SLA_M1_ATTR;
                self.attr &= Self::SLA_M1_CLEAR_MASK;
            }
        }
    }

    pub const fn set_daa_pad_type(&mut self, pad_type: GfhSigPadType) {
        self.attr &= Self::DAA_ATTR_MASK;
        match pad_type {
            GfhSigPadType::Pss => {
                self.attr |= Self::DAA_PSS_ATTR;
            }
            GfhSigPadType::M1 => {
                self.attr &= Self::DAA_M1_CLEAR_MASK;
            }
        }
    }

    pub const fn get_sla_pad_type(&self) -> GfhSigPadType {
        if (self.attr & Self::SLA_PSS_ATTR) == Self::SLA_PSS_ATTR {
            GfhSigPadType::Pss
        } else {
            GfhSigPadType::M1
        }
    }

    pub const fn get_daa_pad_type(&self) -> GfhSigPadType {
        if (self.attr & Self::DAA_PSS_ATTR) == Self::DAA_PSS_ATTR {
            GfhSigPadType::Pss
        } else {
            GfhSigPadType::M1
        }
    }
}

impl Gfh for GfhToolAuth {
    fn header(&self) -> &GfhHeader {
        &self.header
    }

    fn validate(&self) -> Result<()> {
        self.header().validate()?;

        if self.header().gfh_type() != GfhType::ToolAuth {
            return Err(Error::Gfh(GfhError::InvalidType(
                GfhType::ToolAuth,
                self.header().gfh_type(),
            )));
        }

        if self.da_hash_num > Self::MAX_DA_HASH_NUM {
            return Err(Error::Gfh(GfhError::ToolAuthDaHashNumTooLarge(
                self.da_hash_num,
                Self::MAX_DA_HASH_NUM,
            )));
        }

        if self.brom_verified_num > self.da_hash_num {
            return Err(Error::Gfh(GfhError::ToolAuthBromVerifiedTooLarge(
                self.brom_verified_num,
                self.da_hash_num,
            )));
        }

        Ok(())
    }
}

impl<'a> TryRead<'a> for GfhToolAuth {
    fn try_read(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Gfh(GfhError::TooShort(data.len(), Self::SIZE)));
        }

        let gfh = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        gfh.validate()?;

        Ok(gfh)
    }
}
