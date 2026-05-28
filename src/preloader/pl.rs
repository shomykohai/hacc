use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::common::gfh::{GfhFile, GfhFileType, GfhFlashDev};
use crate::gfh::GfhFileInfo;
use crate::traits::TryRead;
use crate::{Error, Result};

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
struct BlDescriptor {
    bl_exists_magic: u32,
    bl_dev: GfhFlashDev,
    _reserved: u8,
    bl_type: GfhFileType,
    bl_begin_addr: u32,
    bl_boundary_addr: u32,
    bl_attribute: u32,
}

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
struct Brlyt {
    identifier: [u8; 8],
    version: u32,
    boot_region_address: u32,
    main_region_address: u32,
    bl_desc: [BlDescriptor; 8],
}

impl Brlyt {
    pub const fn gfh_offset(&self) -> u32 {
        self.bl_desc[0].bl_begin_addr
    }
}

impl<'a> TryRead<'a> for Brlyt {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < size_of::<Self>() {
            return Err(Error::Preloader(PreloaderError::BrlytMalformed));
        }

        Self::try_read_from_bytes(&data[..size_of::<Self>()]).map_err(|_| Error::Zerocopy)
    }
}

#[derive(Debug)]
pub struct Preloader<'a> {
    gfh: GfhFile<'a>,
    emi_offset: usize,
    emi_size: usize,
}

#[derive(TError, Debug)]
pub enum PreloaderError {
    #[error("Preloader data is too short")]
    TooShort,

    #[error("GFH header not found in preloader")]
    GfhHeaderNotFound,

    #[error("BRLYT header is malformed")]
    BrlytMalformed,
}

impl<'a> Preloader<'a> {
    pub const BRLYT_ID: &'static [u8] = b"BRLYT\0\0\0";
    pub const BRLYT_OFFSET: usize = 0x200;
    pub const EMI_ID: &'static [u8] = b"MTK_BLOADER_INFO";

    pub const fn gfh(&self) -> &GfhFile<'a> {
        &self.gfh
    }

    pub fn emi(&self) -> Option<&'a [u8]> {
        (self.emi_size != 0)
            .then_some(&self.gfh.content()[self.emi_offset..self.emi_offset + self.emi_size])
    }
}

impl<'a> TryRead<'a> for Preloader<'a> {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < size_of::<GfhFileInfo>() + Preloader::BRLYT_OFFSET + size_of::<Brlyt>() {
            return Err(Error::Preloader(PreloaderError::TooShort));
        }

        let gfh_offset = if data.get(Preloader::BRLYT_OFFSET..Preloader::BRLYT_OFFSET + 8)
            == Some(Preloader::BRLYT_ID)
            && let Ok(brlyt) = Brlyt::try_read(&data[Preloader::BRLYT_OFFSET..])
        {
            brlyt.gfh_offset() as usize
        } else {
            0
        };

        let data = &data[gfh_offset..];
        let gfh = GfhFile::try_read(data)?;

        let emi_offset = gfh
            .content()
            .windows(Preloader::EMI_ID.len())
            .position(|window| window == Preloader::EMI_ID);

        let emi_size = emi_offset.map_or(0, |offset| gfh.content().len() - offset);

        Ok(Self { gfh, emi_offset: emi_offset.unwrap_or(0), emi_size })
    }
}
