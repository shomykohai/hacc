use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::header::GfhHeader;
use super::{Gfh, GfhError, GfhSigPadType};
use crate::error::{Error, Result};
use crate::gfh::header::GfhType;
use crate::traits::TryRead;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
pub enum GfhFileType {
    FileNone = 0x0000,
    ArmBl = 0x0001,
    ArmExtBl = 0x0002,
    DualmacDspBl = 0x0003,
    SctrlCert = 0x0004,
    ToolAuth = 0x0005,
    MtkDebugAuth = 0x0006,
    Epp = 0x0007,
    Reserved2 = 0x0008,
    Reserved3 = 0x0009,
    RootCert = 0x000A,
    ApBl = 0x000B,

    PrimaryMaui = 0x0100,
    SecondaryMaui = 0x0101,
    OnDemandPaging = 0x0102,
    ThirdRom = 0x0103,
    DspRom = 0x0104,
    CachedDspRom = 0x0105,
    PrimaryFactoryBin = 0x0106,
    SecondaryFactoryBin = 0x0107,
    Viva = 0x0108,
    LteDspRom = 0x0109,
    VMauiBinaryEnd = 0x017F,

    CustomPack = 0x0180,
    LanguagePack = 0x0181,
    JumpTable = 0x0182,
    VResourceBinaryEnd = 0x01FF,

    FotaUe = 0x0200,
    ArmExtBlBackup = 0x0201,
    VMiscBinaryEnd = 0x0202,

    SecureRoS = 0x0300,
    SecureRoMe = 0x0301,
    VSecureRoEnd = 0x0302,

    CardDownloadPackage = 0x0400,
    ConfidentialBinary = 0x0401,
    VExternalFileEnd = 0x0402,

    FileSystem = 0x0480,
    VFileSystemBinaryEnd = 0x0481,

    BootCertCtrl = 0x0500,
    VSrdEnd = 0x0501,

    CustomerBin1 = 0x7000,
    CustomerBin2 = 0x7001,
    CustomerBin3 = 0x7002,
    VCustomizedFileEnd = 0x70FF,

    GfhFileTypeForMt6290 = 0x8000,

    GfhFileEnd = 0xFFFF,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
pub enum GfhSigType {
    None,
    Sha256,
    Single,
    SingleAndSha256,
    Multi,
    CertChain,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
pub enum GfhFlashDev {
    None,
    Nor,
    NandSeq,
    NandTtbl,
    NandFdm50,
    EmmcBoot,
    EmmcData,
    Sf,
    Xboot,
    SpiNand,
    Ufs = 12,
    Combo = 14,
}

#[derive(Debug, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct GfhFileInfo {
    header: GfhHeader,
    identifier: [u8; 12],
    file_ver: u32,
    file_type: GfhFileType,
    flash_dev: GfhFlashDev,
    sig_type: GfhSigType,
    load_addr: u32,
    file_len: u32,
    max_size: u32,
    content_offset: u32,
    sig_len: u32,
    jump_offset: u32,
    attr: u32,
}

impl GfhFileInfo {
    const FILE_INFO_IDENTIFIER: [u8; 12] = *b"FILE_INFO\0\0\0";
    const MAX_SIZE: u32 = u32::MAX;
    const PSS_PAD_ATTR: u32 = 0xC2600000;
    const SIZE: usize = size_of::<Self>();

    pub const fn file_ver(&self) -> u32 {
        self.file_ver
    }

    pub const fn file_type(&self) -> GfhFileType {
        self.file_type
    }

    pub const fn sig_type(&self) -> GfhSigType {
        self.sig_type
    }

    pub const fn flash_dev(&self) -> GfhFlashDev {
        self.flash_dev
    }

    pub const fn load_addr(&self) -> u32 {
        self.load_addr
    }

    pub const fn max_size(&self) -> usize {
        self.max_size as usize
    }

    pub const fn file_len(&self) -> usize {
        self.file_len as usize
    }

    pub const fn content_offset(&self) -> u32 {
        self.content_offset
    }

    pub const fn content_len(&self) -> usize {
        self.file_len as usize - self.content_offset as usize - self.sig_len as usize
    }

    pub const fn sig_len(&self) -> u32 {
        self.sig_len
    }

    pub const fn jump_offset(&self) -> u32 {
        self.jump_offset
    }

    pub const fn attr(&self) -> u32 {
        self.attr
    }

    pub const fn set_pad_type(&mut self, pad_type: GfhSigPadType) {
        let pad_attr = match pad_type {
            GfhSigPadType::M1 => 0,
            GfhSigPadType::Pss => Self::PSS_PAD_ATTR,
        };

        self.attr = (self.attr & 0xFFFF) | pad_attr;
    }

    pub const fn set_sig_type(&mut self, sig_type: GfhSigType) {
        self.sig_type = sig_type;
    }

    pub const fn set_flash_dev(&mut self, flash_dev: GfhFlashDev) {
        self.flash_dev = flash_dev;
    }

    pub const fn set_file_type(&mut self, file_type: GfhFileType) {
        self.file_type = file_type;
    }

    pub const fn set_file_ver(&mut self, file_ver: u32) {
        self.file_ver = file_ver;
    }

    pub const fn set_load_addr(&mut self, load_addr: u32) {
        self.load_addr = load_addr;
    }

    pub const fn set_file_len(&mut self, content_size: u32) {
        self.file_len = content_size + Self::SIZE as u32 + self.sig_len;
    }

    pub const fn set_max_size(&mut self, max_size: u32) {
        self.max_size = max_size;
    }

    pub const fn set_content_offset(&mut self, content_offset: u32) {
        self.content_offset = content_offset;
    }

    pub const fn set_sig_len(&mut self, sig_len: u32) {
        self.file_len = self.file_len + sig_len - self.sig_len;
        self.sig_len = sig_len;
    }

    pub const fn set_jump_offset(&mut self, jump_offset: u32) {
        self.jump_offset = jump_offset;
    }
}

impl Gfh for GfhFileInfo {
    fn header(&self) -> &GfhHeader {
        &self.header
    }

    fn validate(&self) -> Result<()> {
        self.header.validate()?;

        if self.identifier != Self::FILE_INFO_IDENTIFIER {
            return Err(Error::Gfh(GfhError::FileInvalidIdentifier));
        }

        if self.file_len > self.max_size {
            return Err(Error::Gfh(GfhError::FileLengthOverflow(self.file_len, Self::MAX_SIZE)));
        }

        if self.content_offset > self.file_len
            || self.sig_len > self.file_len
            || self.content_offset + self.sig_len > self.file_len
            || ((self.jump_offset < self.content_offset
                || self.file_len - self.sig_len <= self.jump_offset)
                && self.jump_offset != 0)
        {
            return Err(Error::Gfh(GfhError::FileOffsetOutOfBounds(
                self.content_offset,
                self.sig_len,
                self.file_len,
            )));
        }

        Ok(())
    }
}

impl Default for GfhFileInfo {
    fn default() -> Self {
        Self {
            header: GfhHeader::new(GfhType::FileInfo, Self::SIZE as u16),
            identifier: Self::FILE_INFO_IDENTIFIER,
            file_ver: 0,
            file_type: GfhFileType::FileNone,
            flash_dev: GfhFlashDev::None,
            sig_type: GfhSigType::None,
            load_addr: 0,
            file_len: 0,
            max_size: 0,
            content_offset: 0,
            sig_len: 0,
            jump_offset: 0,
            attr: 0,
        }
    }
}

impl<'a> TryRead<'a> for GfhFileInfo {
    fn try_read(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Gfh(GfhError::TooShort(data.len(), Self::SIZE)));
        }

        let file_info =
            Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        file_info.validate()?;

        Ok(file_info)
    }
}
