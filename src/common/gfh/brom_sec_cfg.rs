use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::header::GfhHeader;
use super::{Gfh, GfhError};
use crate::error::{Error, Result};
use crate::gfh::header::GfhType;
use crate::traits::TryRead;
use crate::{get_bit, set_or_clear_bit};

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct GfhBromSecCfg {
    header: GfhHeader,
    attr: u32,
    cust_name: [u8; 32],
    permament_brom_cmd_disable: u32,
}

impl GfhBromSecCfg {
    const SIZE: usize = size_of::<Self>();

    pub const fn attr(&self) -> u32 {
        self.attr
    }

    pub const fn set_attr(&mut self, attr: u32) {
        self.attr = attr;
    }

    pub const fn jtag_enabled(&self) -> bool {
        get_bit!(self.attr, 0) == 1
    }

    pub const fn debug_enabled(&self) -> bool {
        get_bit!(self.attr, 1) == 1
    }

    pub fn customer_name(&self) -> &str {
        core::str::from_utf8(&self.cust_name).unwrap_or("MTK").trim_end_matches('\0')
    }

    pub const fn permament_brom_cmd_disable(&self) -> u32 {
        self.permament_brom_cmd_disable
    }

    pub const fn set_jtag_enabled(&mut self, enabled: bool) {
        set_or_clear_bit!(self.attr, 0, enabled);
    }

    pub const fn set_debug_enabled(&mut self, enabled: bool) {
        set_or_clear_bit!(self.attr, 1, enabled);
    }
}

impl Gfh for GfhBromSecCfg {
    fn header(&self) -> &GfhHeader {
        &self.header
    }

    fn validate(&self) -> Result<()> {
        self.header().validate()?;

        if self.header().gfh_type() != GfhType::BromSecCfg {
            return Err(Error::Gfh(GfhError::InvalidType(
                GfhType::BromSecCfg,
                self.header().gfh_type(),
            )));
        }
        Ok(())
    }
}

impl<'a> TryRead<'a> for GfhBromSecCfg {
    fn try_read(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Gfh(GfhError::TooShort(data.len(), Self::SIZE)));
        }

        let gfh = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        gfh.validate()?;

        Ok(gfh)
    }
}
