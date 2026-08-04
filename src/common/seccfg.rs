use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::LockState;
use crate::error::{Error, Result};
use crate::traits::TryRead;
#[cfg(feature = "alloc")]
use crate::traits::TryWrite;

#[derive(Debug, TError)]
pub enum SecCfgError {
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid size")]
    InvalidSize,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout,
)]
#[repr(C)]
pub enum DmVerityState {
    #[default]
    StatusOk = 0,
    GeneralError = 1,
}

#[derive(Debug, Default, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C)]
pub struct SecCfgV4 {
    start_magic: u32,
    seccfg_ver: u32,
    seccfg_size: u32,
    lock_state: LockState,
    dm_verity_state: DmVerityState,
    sboot_runtime: u32,
    end_magic: u32,
    cipher: [u8; 32],
}

impl SecCfgV4 {
    pub const END_MAGIC: u32 = 0x45454545;
    const SIZE: usize = size_of::<Self>();
    pub const START_MAGIC: u32 = 0x4D4D4D4D;

    pub const fn new(lock_state: LockState) -> Self {
        Self {
            start_magic: Self::START_MAGIC,
            seccfg_ver: 4,
            seccfg_size: size_of::<Self>() as u32,
            lock_state,
            dm_verity_state: DmVerityState::StatusOk,
            sboot_runtime: 0,
            end_magic: Self::END_MAGIC,
            cipher: [0u8; 32],
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.start_magic == Self::START_MAGIC && self.end_magic == Self::END_MAGIC
    }

    pub const fn size(&self) -> usize {
        self.seccfg_size as usize
    }

    pub const fn version(&self) -> u32 {
        self.seccfg_ver
    }

    pub const fn lock_state(&self) -> LockState {
        self.lock_state
    }

    pub const fn dm_verity_state(&self) -> DmVerityState {
        self.dm_verity_state
    }

    pub const fn sboot_runtime(&self) -> u32 {
        self.sboot_runtime
    }

    pub const fn hash(&self) -> &[u8; 32] {
        &self.cipher
    }

    pub const fn set_lock_state(&mut self, lock_state: LockState) {
        self.lock_state = lock_state;
    }

    pub const fn set_dm_verity_state(&mut self, state: DmVerityState) {
        self.dm_verity_state = state;
    }

    pub const fn set_hash(&mut self, hash: &[u8; 32]) {
        self.cipher.copy_from_slice(hash);
    }
}

impl<'a> TryRead<'a> for SecCfgV4 {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::SecCfg(SecCfgError::InvalidSize));
        }

        let seccfg = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        if !seccfg.is_valid() {
            return Err(Error::SecCfg(SecCfgError::InvalidData));
        }

        Ok(seccfg)
    }
}

#[cfg(feature = "alloc")]
impl TryWrite for SecCfgV4 {
    fn try_write(&self, data: &mut [u8]) -> Result<usize> {
        if data.len() < Self::SIZE {
            return Err(Error::SecCfg(SecCfgError::InvalidSize));
        }

        self.write_to(&mut data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        Ok(Self::SIZE)
    }
}
