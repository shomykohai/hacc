#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

use memchr::memmem;
use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::{Error, Result, TryRead};

const MAX_REGIONS: usize = 10;

#[derive(Debug, Clone, Copy, Immutable, IntoBytes, TryFromBytes, KnownLayout, PartialEq, Eq)]
#[repr(u32)]
pub enum DaHeaderVersion {
    Unknown = 0,
    V3 = 3,
    V4 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DaVersion {
    V3,
    V5,
    V6,
}

#[derive(TError, Debug)]
pub enum DaError {
    #[error("DA data is too short")]
    TooShort,

    #[error("DA signature is invalid")]
    InvalidSignature,

    #[error("DA header magic is invalid: expected {0:#010X}, found {1:#010X}")]
    InvalidMagic(u32, u32),

    #[error("DA entry has too few regions: expected at least 3, found {0}")]
    RegionCountTooSmall(usize),

    #[error("DA entry has too many regions: expected at most {0}, found {1}")]
    RegionCountTooLarge(usize, usize),

    #[error("DA region is invalid: offset {0}, length {1}, region_length {2:#010X}")]
    InvalidRegion(usize, usize, usize),

    #[error("DA region data is out of bounds: offset {0}, length {1}, data length {2}")]
    RegionDataOutOfBounds(usize, usize, usize),
}

#[derive(Default, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct DaRegion {
    /// Offset within the file itself, where the region starts
    offset: u32,
    /// Length of the region
    length: u32,
    /// Address in which the region will be loaded in the device
    addr: u32,
    /// Same as length, minus the signature (offset - sig_len)
    region_length: u32,
    /// Length of the signature, if any
    sig_len: u32,
}

impl DaRegion {
    pub const SIZE: usize = size_of::<Self>();

    pub const fn new(offset: u32, length: u32, addr: u32, sig_len: u32) -> Self {
        Self { offset, length, addr, region_length: length - sig_len, sig_len }
    }

    pub const fn offset(&self) -> usize {
        self.offset as usize
    }

    pub const fn length(&self) -> usize {
        self.length as usize
    }

    pub const fn addr(&self) -> u32 {
        self.addr
    }

    pub const fn region_length(&self) -> usize {
        self.length() - self.sig_len()
    }

    pub const fn sig_len(&self) -> usize {
        self.sig_len as usize
    }

    pub const fn end_offset(&self) -> usize {
        self.offset() + self.region_length()
    }

    pub const fn has_signature(&self) -> bool {
        self.sig_len > 0
    }

    pub const fn is_valid(&self) -> bool {
        // Some DAs have regions with zero length (Good job, MediaTek!), so we validate
        // region_length on regions where length is non zero.
        self.length != 0 || self.region_length > 0
    }
}

#[derive(Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct DaEntryHeaderV4 {
    magic: u16,
    hw_code: u16,
    hw_sub_code: u16,
    hw_ver: u16,
    sw_ver: u16,
    _reserved: u16,
    feature_set: u32,
    entry_index: u16,
    region_count: u16,
    regions: [DaRegion; MAX_REGIONS],
}

#[derive(Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct DaEntryHeaderV3 {
    magic: u16,
    hw_code: u16,
    hw_sub_code: u16,
    hw_ver: u16,
    sw_ver: u16,
    _reserved: u16,
    entry_index: u16,
    region_count: u16,
    regions: [DaRegion; MAX_REGIONS],
}

pub enum DaEntryHeader<'a> {
    #[cfg(feature = "alloc")]
    V3(Cow<'a, DaEntryHeaderV3>),
    #[cfg(feature = "alloc")]
    V4(Cow<'a, DaEntryHeaderV4>),

    #[cfg(not(feature = "alloc"))]
    V3(&'a DaEntryHeaderV3),
    #[cfg(not(feature = "alloc"))]
    V4(&'a DaEntryHeaderV4),
}

pub struct DaEntry<'a> {
    #[cfg(feature = "alloc")]
    data: Cow<'a, [u8]>,
    #[cfg(not(feature = "alloc"))]
    data: &'a [u8],
    version: DaHeaderVersion,
    entry: DaEntryHeader<'a>,
}

impl<'a> DaEntry<'a> {
    const MIN_REGION_COUNT: usize = 2;
    const V5_PATTERN: &'static [u8] = b"REVEIVING DEV CTRL CMD(0x%x)";
    const V6_PATTERN: &'static [u8] = b"<?xml version=";

    pub fn regions(&self) -> &[DaRegion] {
        match &self.entry {
            DaEntryHeader::V3(header) => &header.regions[..header.region_count as usize],
            DaEntryHeader::V4(header) => &header.regions[..header.region_count as usize],
        }
    }

    pub fn get_region(&self, index: usize) -> Option<&DaRegion> {
        if index >= self.region_count() {
            return None;
        }

        self.regions().get(index)
    }

    pub fn hw_code(&self) -> u16 {
        match &self.entry {
            DaEntryHeader::V3(header) => header.hw_code,
            DaEntryHeader::V4(header) => header.hw_code,
        }
    }

    pub fn hw_sub_code(&self) -> u16 {
        match &self.entry {
            DaEntryHeader::V3(header) => header.hw_sub_code,
            DaEntryHeader::V4(header) => header.hw_sub_code,
        }
    }

    pub fn region_count(&self) -> usize {
        match &self.entry {
            DaEntryHeader::V3(header) => header.region_count as usize,
            DaEntryHeader::V4(header) => header.region_count as usize,
        }
    }

    pub const fn header_version(&self) -> DaHeaderVersion {
        self.version
    }

    pub fn version(&self) -> DaVersion {
        let data = self.da1_data();

        if memmem::find(data, Self::V5_PATTERN).is_some() {
            DaVersion::V5
        } else if memmem::find(data, Self::V6_PATTERN).is_some() {
            DaVersion::V6
        } else {
            DaVersion::V3
        }
    }

    /// Returns the data of the region, including the signature.
    pub fn get_region_data(&self, index: usize) -> Option<&[u8]> {
        let region = self.get_region(index)?;
        let offset = region.offset();
        let length = region.length();

        if offset + length > self.data.len() {
            return None;
        }

        Some(&self.data[offset..offset + length])
    }

    /// Returns the signature of the region, if any.
    pub fn get_region_sig(&self, index: usize) -> Option<&[u8]> {
        let region = self.get_region(index)?;
        let offset = region.offset();
        let end_off = region.end_offset();
        let length = region.length();

        if end_off - offset > self.data.len() {
            return None;
        }

        Some(&self.data[end_off..length])
    }

    /// Returns the content of the region, excluding the signature.
    pub fn get_region_content(&self, index: usize) -> Option<&[u8]> {
        let region = self.get_region(index)?;
        let offset = region.offset();
        let end_off = region.end_offset();

        if end_off - offset > self.data.len() {
            return None;
        }

        Some(&self.data[offset..end_off])
    }

    pub fn da1(&self) -> &DaRegion {
        // It is safe to unwrap here because we already
        // validate the entry when parsing the DA.
        if self.region_count() == 2 {
            self.get_region(0).unwrap()
        } else {
            self.get_region(1).unwrap()
        }
    }

    pub fn da2(&self) -> &DaRegion {
        if self.region_count() == 2 {
            self.get_region(1).unwrap()
        } else {
            self.get_region(2).unwrap()
        }
    }

    pub fn da1_data(&self) -> &[u8] {
        if self.region_count() == 2 {
            self.get_region_data(0).expect("Region should exist")
        } else {
            self.get_region_data(1).expect("Region should exist")
        }
    }

    pub fn da2_data(&self) -> &[u8] {
        if self.region_count() == 2 {
            self.get_region_data(1).expect("Region should exist")
        } else {
            self.get_region_data(2).expect("Region should exist")
        }
    }

    pub fn da1_code(&self) -> &[u8] {
        if self.region_count() == 2 {
            self.get_region_content(0).expect("Region should exist")
        } else {
            self.get_region_content(1).expect("Region should exist")
        }
    }

    pub fn da2_code(&self) -> &[u8] {
        if self.region_count() == 2 {
            self.get_region_content(1).expect("Region should exist")
        } else {
            self.get_region_content(2).expect("Region should exist")
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.region_count() < Self::MIN_REGION_COUNT {
            return Err(Error::Da(DaError::RegionCountTooSmall(self.region_count())));
        }

        if self.region_count() > MAX_REGIONS {
            return Err(Error::Da(DaError::RegionCountTooLarge(MAX_REGIONS, self.region_count())));
        }

        self.regions().iter().take(self.region_count()).try_for_each(|region| {
            if !region.is_valid() {
                return Err(Error::Da(DaError::InvalidRegion(
                    region.offset(),
                    region.length(),
                    region.region_length(),
                )));
            }

            if region.offset() + region.length() > self.data.len() {
                return Err(Error::Da(DaError::RegionDataOutOfBounds(
                    region.offset(),
                    region.length(),
                    self.data.len(),
                )));
            }

            Ok(())
        })
    }
}

#[cfg(feature = "alloc")]
impl<'a> DaEntry<'a> {
    pub fn get_region_data_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let region = self.get_region(index)?;
        let offset = region.offset();
        let length = region.length();

        if offset + length > self.data.len() {
            return None;
        }

        Some(&mut self.data.to_mut()[offset..offset + length])
    }

    pub fn get_region_content_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let region = self.get_region(index)?;
        let offset = region.offset();
        let end_off = region.end_offset();

        if end_off - offset > self.data.len() {
            return None;
        }

        Some(&mut self.data.to_mut()[offset..end_off])
    }

    pub fn get_region_mut(&mut self, index: usize) -> Option<&mut DaRegion> {
        if index >= self.region_count() {
            return None;
        }
        match &mut self.entry {
            DaEntryHeader::V3(header) => Some(&mut header.to_mut().regions[index]),
            DaEntryHeader::V4(header) => Some(&mut header.to_mut().regions[index]),
        }
    }

    pub fn da1_data_mut(&mut self) -> &mut [u8] {
        if self.region_count() == 2 {
            self.get_region_data_mut(0).expect("Region should exist")
        } else {
            self.get_region_data_mut(1).expect("Region should exist")
        }
    }

    pub fn da2_data_mut(&mut self) -> &mut [u8] {
        if self.region_count() == 2 {
            self.get_region_data_mut(1).expect("Region should exist")
        } else {
            self.get_region_data_mut(2).expect("Region should exist")
        }
    }
}

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct DaHeader {
    id: [u8; 32],
    desc: [u8; 64],
    version: DaHeaderVersion,
    magic: u32,
    da_count: u32,
}

impl DaHeader {
    pub const DA_ID: &'static [u8; 32] = b"MTK_DOWNLOAD_AGENT\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    pub const DA_MAGIC: u32 = 0x22668899;
    pub const SIZE: usize = size_of::<Self>();

    pub fn id(&self) -> &str {
        core::str::from_utf8(&self.id).unwrap_or("MTK_DOWNLOAD_AGENT").trim_end_matches('\0')
    }

    pub fn desc(&self) -> &str {
        core::str::from_utf8(&self.desc).unwrap_or("").trim_end_matches('\0')
    }

    pub const fn version(&self) -> DaHeaderVersion {
        self.version
    }

    pub const fn magic(&self) -> u32 {
        self.magic
    }

    pub const fn da_count(&self) -> u32 {
        self.da_count
    }

    pub const fn set_version(&mut self, version: DaHeaderVersion) {
        self.version = version;
    }

    pub const fn set_da_count(&mut self, count: u32) {
        self.da_count = count;
    }
}

impl Default for DaHeader {
    fn default() -> Self {
        Self {
            id: *Self::DA_ID,
            desc: [0u8; 64],
            version: DaHeaderVersion::Unknown,
            magic: Self::DA_MAGIC,
            da_count: 0,
        }
    }
}

impl<'a> TryRead<'a> for DaHeader {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Zerocopy);
        }

        let header = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        if header.id() != "MTK_DOWNLOAD_AGENT" {
            return Err(Error::Da(DaError::InvalidSignature));
        }

        if header.magic() != Self::DA_MAGIC {
            return Err(Error::Da(DaError::InvalidMagic(Self::DA_MAGIC, header.magic())));
        }

        Ok(header)
    }
}

#[derive(Debug)]
pub struct Da<'a> {
    #[cfg(feature = "alloc")]
    data: Cow<'a, [u8]>,
    #[cfg(not(feature = "alloc"))]
    data: &'a [u8],
    header: DaHeader,
}

impl<'a> Da<'a> {
    pub const fn header(&self) -> &DaHeader {
        &self.header
    }

    #[cfg(not(feature = "alloc"))]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    #[cfg(feature = "alloc")]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[cfg(feature = "alloc")]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.to_mut()
    }

    pub fn entries(&self) -> impl Iterator<Item = DaEntry<'_>> + '_ {
        let mut offset = DaHeader::SIZE;
        (0..self.header.da_count()).filter_map(move |_| {
            if offset >= self.data.len() {
                return None;
            }

            #[cfg(feature = "alloc")]
            let entry_data = self.data.clone();
            #[cfg(not(feature = "alloc"))]
            let entry_data = self.data;

            let entry = DaEntry {
                data: entry_data,
                version: self.header.version(),
                entry: match self.header.version() {
                    DaHeaderVersion::V3 => {
                        let end = offset + size_of::<DaEntryHeaderV3>();
                        let header =
                            DaEntryHeaderV3::try_ref_from_bytes(&self.data[offset..end]).ok()?;
                        offset = end;

                        #[cfg(feature = "alloc")]
                        let header = Cow::Borrowed(header);

                        DaEntryHeader::V3(header)
                    }
                    DaHeaderVersion::V4 => {
                        let end = offset + size_of::<DaEntryHeaderV4>();
                        let header =
                            DaEntryHeaderV4::try_ref_from_bytes(&self.data[offset..end]).ok()?;
                        offset = end;

                        #[cfg(feature = "alloc")]
                        let header = Cow::Borrowed(header);

                        DaEntryHeader::V4(header)
                    }
                    _ => return None,
                },
            };

            entry.validate().ok()?;

            Some(entry)
        })
    }

    pub fn entry(&self, index: usize) -> Option<DaEntry<'_>> {
        self.entries().nth(index)
    }
}

impl<'a> TryRead<'a> for Da<'a> {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        let header = DaHeader::try_read(data)?;

        #[cfg(feature = "alloc")]
        let data = Cow::Borrowed(data);

        Ok(Self { data, header })
    }
}
