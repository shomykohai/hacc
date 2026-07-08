use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::header::{GfhHeader, GfhType};
use super::{
    GfhAntiClone,
    GfhBlExtCfg,
    GfhBlInfo,
    GfhBromCfgV3,
    GfhBromCfgV4,
    GfhBromSecCfg,
    GfhFileInfo,
    GfhSigType,
    GfhToolAuth,
};
use crate::Result;
use crate::traits::TryRead;

#[derive(Debug, TError)]
pub enum GfhError {
    // General
    #[error("GFH data is too short: expected at least {0} bytes, found {1} bytes")]
    TooShort(usize, usize),

    // Header
    #[error("Invalid GFH header magic: expected {0:#X}, found {1:#X}")]
    InvalidHeaderMagic(u32, u32),
    #[error("Invalid GFH Type, expected {0:?}, found {1:?}")]
    InvalidType(GfhType, GfhType),

    // File info
    #[error("Invalid file info identifier: expected FILE_INFO")]
    FileInvalidIdentifier,
    #[error("File length ({0:#X}) exceeds maximum allowed size ({1:#X})")]
    FileLengthOverflow(u32, u32),
    #[error("Content offset ({0:#X}) and signature length ({1:#X}) exceed file length ({2:#X})")]
    FileOffsetOutOfBounds(u32, u32, u32),

    // Tool auth
    #[error("Number of DA hashes ({0:#X}) in tool auth exceeds maximum allowed ({1:#X})")]
    ToolAuthDaHashNumTooLarge(u32, u32),

    #[error("Tool auth has more BROM verified hashes ({0:#X}) than DA hashes ({1:#X})")]
    ToolAuthBromVerifiedTooLarge(u32, u32),
}

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct CtM1Key {
    e_len: u32,
    n_len: u32,
    m_coeff: u16,
    cut_length: u16,
    e_key: [u16; 128],
    n_key: [u16; 128],
}

impl CtM1Key {
    pub fn new(e_key: &[u16], n_key: &[u16], m_coeff: u16, cut_length: u16) -> Self {
        let mut e_key_arr = [0u16; 128];
        let mut n_key_arr = [0u16; 128];

        e_key_arr[..e_key.len()].copy_from_slice(e_key);
        n_key_arr[..n_key.len()].copy_from_slice(n_key);

        Self {
            e_len: (e_key.len() * 2) as u32,
            n_len: (n_key.len() * 2) as u32,
            m_coeff,
            cut_length,
            e_key: e_key_arr,
            n_key: n_key_arr,
        }
    }

    pub const fn e_len(&self) -> u32 {
        self.e_len
    }

    pub const fn n_len(&self) -> u32 {
        self.n_len
    }

    pub const fn m_coeff(&self) -> u16 {
        self.m_coeff
    }

    pub const fn cut_length(&self) -> u16 {
        self.cut_length
    }

    pub fn e_key(&self) -> &[u16] {
        &self.e_key[..(self.e_len as usize / 2)]
    }

    pub fn n_key(&self) -> &[u16] {
        &self.n_key[..(self.n_len as usize / 2)]
    }
}

impl<'a> TryRead<'a> for CtM1Key {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < size_of::<Self>() {
            return Err(GfhError::TooShort(size_of::<Self>(), data.len()).into());
        }

        Self::try_read_from_bytes(&data[..size_of::<Self>()])
            .map_err(|_| GfhError::TooShort(size_of::<Self>(), data.len()).into())
    }
}

pub enum GfhSigPadType {
    M1,
    Pss,
}

pub trait Gfh {
    fn header(&self) -> &GfhHeader;
    fn size(&self) -> usize {
        self.header().size() as usize
    }

    fn type_id(&self) -> GfhType {
        self.header().gfh_type()
    }

    fn validate(&self) -> Result<()> {
        self.header().validate()
    }
}

pub enum GfhKind {
    AntiClone(GfhAntiClone),
    FileInfo(GfhFileInfo),
    BlInfo(GfhBlInfo),
    BlExtCfg(GfhBlExtCfg),
    BromSecCfg(GfhBromSecCfg),
    BromCfgV3(GfhBromCfgV3),
    BromCfgV4(GfhBromCfgV4),
    ToolAuth(GfhToolAuth),
    Unknown(GfhHeader),
}

impl GfhKind {
    pub fn header(&self) -> &GfhHeader {
        match self {
            Self::AntiClone(gfh) => gfh.header(),
            Self::FileInfo(gfh) => gfh.header(),
            Self::BlInfo(gfh) => gfh.header(),
            Self::BlExtCfg(gfh) => gfh.header(),
            Self::BromSecCfg(gfh) => gfh.header(),
            Self::BromCfgV3(gfh) => gfh.header(),
            Self::BromCfgV4(gfh) => gfh.header(),
            Self::ToolAuth(gfh) => gfh.header(),
            Self::Unknown(header) => header,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AntiClone(gfh) => gfh.validate(),
            Self::FileInfo(gfh) => gfh.validate(),
            Self::BlInfo(gfh) => gfh.validate(),
            Self::BlExtCfg(gfh) => gfh.validate(),
            Self::BromSecCfg(gfh) => gfh.validate(),
            Self::BromCfgV3(gfh) => gfh.validate(),
            Self::BromCfgV4(gfh) => gfh.validate(),
            Self::ToolAuth(gfh) => gfh.validate(),
            Self::Unknown(header) => header.validate(),
        }
    }
}

#[derive(Debug)]
pub struct GfhFile<'a> {
    file_info: GfhFileInfo,
    content: &'a [u8],
}

impl<'a> GfhFile<'a> {
    pub const fn file_info(&self) -> &GfhFileInfo {
        &self.file_info
    }

    pub fn content(&self) -> &'a [u8] {
        let offset = self.file_info.content_offset() as usize;
        let length = self.file_info.content_len();
        self.content.get(offset..offset + length).unwrap_or(&[])
    }

    pub fn signature(&self) -> Option<&[u8]> {
        if self.file_info.sig_type() != GfhSigType::None && self.file_info.sig_len() > 0 {
            let sig_offset =
                self.file_info.content_offset() as usize + self.file_info().content_len();
            Some(&self.content[sig_offset..(sig_offset + self.file_info.sig_len() as usize)])
        } else {
            None
        }
    }

    pub fn gfhs(&self) -> impl Iterator<Item = GfhKind> + '_ {
        let mut offset = 0;
        let content_len = self.content.len();

        core::iter::from_fn(move || {
            if offset >= content_len {
                return None;
            }

            let header = GfhHeader::try_read(&self.content[offset..]).ok()?;
            let gfh_size = header.size() as usize;

            if offset + gfh_size > content_len {
                return None;
            }

            let gfh_data = &self.content[offset..offset + gfh_size];
            offset += gfh_size;

            match header.gfh_type() {
                GfhType::AntiClone => GfhAntiClone::try_read(gfh_data).ok().map(GfhKind::AntiClone),
                GfhType::FileInfo => GfhFileInfo::try_read(gfh_data).ok().map(GfhKind::FileInfo),
                GfhType::BlInfo => GfhBlInfo::try_read(gfh_data).ok().map(GfhKind::BlInfo),
                GfhType::BlExtCfg => GfhBlExtCfg::try_read(gfh_data).ok().map(GfhKind::BlExtCfg),
                GfhType::BromSecCfg => {
                    GfhBromSecCfg::try_read(gfh_data).ok().map(GfhKind::BromSecCfg)
                }
                GfhType::BromCfg => {
                    if header.version() == 4 {
                        GfhBromCfgV4::try_read(gfh_data).ok().map(GfhKind::BromCfgV4)
                    } else {
                        GfhBromCfgV3::try_read(gfh_data).ok().map(GfhKind::BromCfgV3)
                    }
                }

                GfhType::ToolAuth => GfhToolAuth::try_read(gfh_data).ok().map(GfhKind::ToolAuth),
                _ => Some(GfhKind::Unknown(header)),
            }
        })
    }

    pub fn get_gfh(&self, gfh_type: GfhType) -> Option<GfhKind> {
        self.gfhs().find(|gfh| gfh.header().gfh_type() == gfh_type)
    }
}

impl<'a> TryRead<'a> for GfhFile<'a> {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        let file_info = GfhFileInfo::try_read(data)?;
        file_info.validate()?;

        let file_len = file_info.file_len();

        let file = Self { file_info, content: &data[..file_len] };

        for gfh in file.gfhs() {
            gfh.validate()?;
        }

        Ok(file)
    }
}
