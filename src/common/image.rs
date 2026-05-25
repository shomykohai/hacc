#[cfg(feature = "alloc")]
use alloc::borrow::Cow;
use core::ops::Range;

use bilge::bitsize;
use bilge::prelude::*;
use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::error::{Error, Result};

#[derive(Debug, TError)]
pub enum InvalidImageHeaderError {
    #[error("Invalid magic number: expected {0:#X}, found {1:#X}")]
    InvalidMagic(u32, u32),
    #[error("Invalid size: {0:#x}")]
    InvalidSize(u32),
    #[error("Invalid header size: expected {0}, found {1}")]
    InvalidHeaderSize(usize, u32),
    #[error("Invalid image type: {0:#X}")]
    InvalidImageType(u32),
    #[error("Invalid image group: {0:#X}")]
    InvalidImageGroup(u32),
}

#[derive(Debug, TError)]
pub enum ImageError {
    #[error("Partition name cannot exceed 32 characters")]
    PartitionNameTooLong,
    #[error("Partition name cannot be empty")]
    PartitionNameEmpty,
    #[error("Partition content cannot be empty")]
    PartitionContentEmpty,
    #[error("Invalid image header: {0}")]
    InvalidHeader(#[from] InvalidImageHeaderError),
    #[error("Partition not found")]
    PartitionNotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImageAPKind {
    APBin,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImageMDKind {
    MdLte,
    MdC2k,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImageCertKind {
    Cert1,
    Cert1Md,
    Cert2,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImageGroup {
    Ap,
    Md,
    Cert,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImageKind {
    Ap(ImageAPKind),
    Md(ImageMDKind),
    Cert(ImageCertKind),
}

impl From<ImageKind> for ImageType {
    fn from(kind: ImageKind) -> Self {
        let (group_val, id_val) = match kind {
            ImageKind::Ap(ap_kind) => (0, match ap_kind {
                ImageAPKind::APBin => 0,
            }),
            ImageKind::Md(md_kind) => (1, match md_kind {
                ImageMDKind::MdLte => 0,
                ImageMDKind::MdC2k => 1,
            }),
            ImageKind::Cert(cert_kind) => (2, match cert_kind {
                ImageCertKind::Cert1 => 0,
                ImageCertKind::Cert1Md => 1,
                ImageCertKind::Cert2 => 2,
            }),
        };

        Self { value: (group_val << 24) | id_val }
    }
}

#[bitsize(32)]
#[derive(DebugBits, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
pub struct ImageType(u32);

impl ImageType {
    const fn group(&self) -> Result<ImageGroup> {
        let val = self.value >> 24;
        match val {
            0 => Ok(ImageGroup::Ap),
            1 => Ok(ImageGroup::Md),
            2 => Ok(ImageGroup::Cert),
            _ => Err(Error::Image(ImageError::InvalidHeader(
                InvalidImageHeaderError::InvalidImageGroup(val),
            ))),
        }
    }

    fn id(&self) -> Result<ImageKind> {
        let id = self.value & 0xFF;

        Ok(match self.group()? {
            ImageGroup::Ap => {
                let kind = match id {
                    0 => ImageAPKind::APBin,
                    _ => {
                        return Err(Error::Image(ImageError::InvalidHeader(
                            InvalidImageHeaderError::InvalidImageType(id),
                        )));
                    }
                };
                ImageKind::Ap(kind)
            }

            ImageGroup::Md => {
                let kind = match id {
                    0 => ImageMDKind::MdLte,
                    1 => ImageMDKind::MdC2k,
                    _ => {
                        return Err(Error::Image(ImageError::InvalidHeader(
                            InvalidImageHeaderError::InvalidImageType(id),
                        )));
                    }
                };
                ImageKind::Md(kind)
            }

            ImageGroup::Cert => {
                let kind = match id {
                    0 => ImageCertKind::Cert1,
                    1 => ImageCertKind::Cert1Md,
                    2 => ImageCertKind::Cert2,
                    _ => {
                        return Err(Error::Image(ImageError::InvalidHeader(
                            InvalidImageHeaderError::InvalidImageType(id),
                        )));
                    }
                };
                ImageKind::Cert(kind)
            }
        })
    }
}

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct ImageHeader {
    magic: u32,
    dsize: u32,
    name: [u8; 32],
    addr: u32,
    mode: u32,
    /* Extensions */
    ext_magic: u32,
    hdr_size: u32,
    hdr_ver: u32,
    img_type: ImageType,
    img_list_end: u32,
    align_size: u32,
    dsize_ext: u32,
    addr_ext: u32,
    scrambled: u32,
    _reserved: [u8; 428],
}

impl ImageHeader {
    pub const DEFAULT_ALIGN_SZ: u32 = 0x10;
    pub const MAGIC: u32 = 0x58881688;
    pub const MAGIC_EXT: u32 = 0x58891689;

    pub fn new(name: &str, length: u64, img_type: ImageType) -> Self {
        let mut name_bytes = [0u8; 32];
        let bytes = name.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name_bytes[..len].copy_from_slice(&bytes[..len]);
        Self {
            magic: Self::MAGIC,
            dsize: length as u32,
            name: name_bytes,
            addr: 0,
            mode: 0,
            ext_magic: Self::MAGIC_EXT,
            hdr_size: size_of::<Self>() as u32,
            hdr_ver: 1,
            img_type,
            img_list_end: 1,
            align_size: Self::DEFAULT_ALIGN_SZ,
            dsize_ext: (length >> 32) as u32,
            addr_ext: 0,
            scrambled: 0,
            _reserved: [0u8; 428],
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.hdr_size == size_of::<Self>() as u32
    }

    pub const fn is_extended(&self) -> bool {
        self.ext_magic == Self::MAGIC_EXT
    }

    pub const fn data_size(&self) -> u64 {
        if self.is_extended() && self.dsize_ext != u32::MAX {
            ((self.dsize_ext as u64) << 32) | (self.dsize as u64)
        } else {
            self.dsize as u64
        }
    }

    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name).unwrap_or("").trim_end_matches('\0')
    }

    pub const fn addr(&self) -> u64 {
        if self.is_extended() && self.addr_ext != u32::MAX {
            ((self.addr_ext as u64) << 32) | (self.addr as u64)
        } else {
            self.addr as u64
        }
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }

    pub const fn size(&self) -> u32 {
        self.hdr_size
    }

    pub const fn hdr_ver(&self) -> u32 {
        self.hdr_ver
    }

    pub const fn image_group(&self) -> Result<ImageGroup> {
        self.img_type.group()
    }

    pub fn image_id(&self) -> Result<ImageKind> {
        self.img_type.id()
    }

    pub const fn align_size(&self) -> u32 {
        self.align_size
    }

    pub const fn is_last(&self) -> bool {
        self.img_list_end == 1
    }

    pub const fn scrambled(&self) -> u32 {
        self.scrambled
    }
}

#[derive(Debug)]
pub struct ImagePartition<'a> {
    pub header: ImageHeader,
    pub range: Range<usize>,
    pub content: &'a [u8],
}

#[derive(Debug, Default)]
pub struct Image<'a> {
    #[cfg(feature = "alloc")]
    pub data: Cow<'a, [u8]>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'a [u8],
}

impl<'a> Image<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            #[cfg(feature = "alloc")]
            data: Cow::Borrowed(data),
            #[cfg(not(feature = "alloc"))]
            data,
        }
    }

    fn part_iter(&self) -> impl Iterator<Item = ImagePartition<'_>> {
        let mut offset = 0;
        core::iter::from_fn(move || {
            if offset >= self.data.len() || self.data.len() < offset + size_of::<ImageHeader>() {
                None
            } else {
                let header = ImageHeader::try_read_from_bytes(
                    &self.data[offset..offset + size_of::<ImageHeader>()],
                )
                .ok()?;

                let start = offset;
                let data_start = start + header.size() as usize;
                let data_end = data_start + header.data_size() as usize;

                offset = (data_end + header.align_size() as usize - 1)
                    & !(header.align_size() as usize - 1);

                if data_end > self.data.len() {
                    return None;
                }

                Some(ImagePartition {
                    header,
                    range: start..data_end,
                    content: &self.data[data_start..data_end],
                })
            }
        })
    }

    pub fn partitions(&self) -> impl Iterator<Item = ImagePartition<'_>> {
        self.part_iter().filter(|p| p.header.image_group().is_ok_and(|g| g != ImageGroup::Cert))
    }

    pub fn has_partition(&self, name: &str) -> bool {
        self.partitions().any(|p| p.header.name() == name)
    }

    pub fn get_partition(&self, name: &str) -> Option<ImagePartition<'_>> {
        self.partitions().find(|p| p.header.name() == name)
    }

    pub fn get_part_certs(&self, name: &str) -> impl Iterator<Item = ImagePartition<'_>> {
        self.part_iter()
            .skip_while(move |p| p.header.name() != name)
            .skip(1)
            .take_while(|p| p.header.image_group().is_ok_and(|g| g == ImageGroup::Cert))
    }

    #[cfg(feature = "alloc")]
    pub fn add_partition(&mut self, name: &str, content: &[u8], img_type: ImageKind) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Image(ImageError::PartitionNameEmpty));
        } else if name.len() > 32 {
            return Err(Error::Image(ImageError::PartitionNameTooLong));
        } else if content.is_empty() {
            return Err(Error::Image(ImageError::PartitionContentEmpty));
        }

        let last_part = self.part_iter().last();
        let last_part_start = last_part.as_ref().map(|p| p.range.start);

        let offset = last_part.as_ref().map_or(0, |last| {
            let align = last.header.align_size() as usize;
            (last.range.end + align - 1) & !(align - 1)
        });

        let header = ImageHeader::new(name, content.len() as u64, img_type.into());
        let data = self.data.to_mut();

        if data.len() < offset {
            data.resize(offset, 0);
        }

        data.resize(offset + header.size() as usize, 0);
        header
            .write_to(&mut data[offset..offset + header.size() as usize])
            .map_err(|_| Error::Zerocopy)?;

        data.extend_from_slice(content);

        if let Some(start) = last_part_start {
            let header =
                ImageHeader::try_mut_from_bytes(&mut data[start..start + size_of::<ImageHeader>()])
                    .map_err(|_| Error::Zerocopy)?;

            header.img_list_end = 0;
        }

        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn remove_partition(&mut self, name: &str) -> Result<()> {
        let prev_start =
            self.part_iter().take_while(|p| p.header.name() != name).last().map(|p| p.range.start);

        let mut iter = self.part_iter().skip_while(|p| p.header.name() != name);
        let part = iter.next().ok_or(Error::Image(ImageError::PartitionNotFound))?;
        let start = part.range.start;
        let mut end = part.range.end;

        while let Some(part) = iter.next()
            && part.header.image_group()? == ImageGroup::Cert
        {
            end = part.range.end;
        }

        drop(iter);

        let data = self.data.to_mut();
        data.drain(start..end);

        if let Some(start) = prev_start {
            let header =
                ImageHeader::try_mut_from_bytes(&mut data[start..start + size_of::<ImageHeader>()])
                    .map_err(|_| Error::Zerocopy)?;
            header.img_list_end = 1;
        }

        Ok(())
    }
}
