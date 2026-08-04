use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::LockState;
use crate::error::{Error, Result};
use crate::traits::TryRead;
#[cfg(feature = "alloc")]
use crate::traits::TryWrite;

#[derive(Debug, TError)]
pub enum RpmbInfoError {
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid size")]
    InvalidSize,
}

#[derive(Debug, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct SecRpmbInfo {
    start_magic: u32,
    rpmb_ver: u32,
    lock_state: LockState,
    _reserved: [u8; 240],
    end_magic: u32,
}

impl Default for SecRpmbInfo {
    fn default() -> Self {
        Self::new(LockState::Lock)
    }
}

impl SecRpmbInfo {
    pub const DEFAULT_VER: u32 = 1;
    pub const END_MAGIC: u32 = 0x43455352;
    const SIZE: usize = size_of::<Self>();
    pub const START_MAGIC: u32 = 0x52534543;

    pub const fn new(lock_state: LockState) -> Self {
        Self {
            start_magic: Self::START_MAGIC,
            rpmb_ver: Self::DEFAULT_VER,
            lock_state,
            _reserved: [0u8; 240],
            end_magic: Self::END_MAGIC,
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.start_magic == Self::START_MAGIC && self.end_magic == Self::END_MAGIC
    }

    pub const fn size(&self) -> usize {
        Self::SIZE
    }

    pub const fn version(&self) -> u32 {
        self.rpmb_ver
    }

    pub const fn lock_state(&self) -> LockState {
        self.lock_state
    }

    pub const fn set_lock_state(&mut self, lock_state: LockState) {
        self.lock_state = lock_state;
    }
}

impl<'a> TryRead<'a> for SecRpmbInfo {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Rpmb(RpmbInfoError::InvalidSize));
        }

        let rpmb = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        if !rpmb.is_valid() {
            return Err(Error::Rpmb(RpmbInfoError::InvalidData));
        }

        Ok(rpmb)
    }
}

#[cfg(feature = "alloc")]
impl TryWrite for SecRpmbInfo {
    fn try_write(&self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.len() < Self::SIZE {
            return Err(Error::Rpmb(RpmbInfoError::InvalidSize));
        }

        self.write_to(&mut buffer[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        Ok(Self::SIZE)
    }
}
