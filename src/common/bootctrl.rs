use bilge::prelude::{Bitsized, Integer, u1, u3, u4, u7};
use bilge::{self, DebugBits, FromBits, bitsize};
#[cfg(feature = "crc32")]
use crc32fast::Hasher as Crc32Hasher;
use thiserror::Error as TError;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::error::{Error, Result};
use crate::traits::TryRead;
#[cfg(feature = "alloc")]
use crate::traits::TryWrite;

pub const OFFSET_SLOT_SUFFIX: usize = 0x800;
pub const BOOTCTRL_MAGIC: u32 = 0x42414342;
pub const BOOTCTRL_MAX_RETRY: u3 = u3::from_u8(7);
pub const BOOTCTRL_MAX_PRIORITY: u4 = u4::from_u8(15);
pub const BOOTCTRL_DEFAULT_SLOT_COUNT: u3 = u3::from_u8(2);
pub const BOOTCTRL_SLOT_A_SUFFIX: &str = "_a";
pub const BOOTCTRL_SLOT_B_SUFFIX: &str = "_b";

#[derive(Debug, TError)]
pub enum BootControlError {
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid size")]
    InvalidSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum BootPartition {
    A = 1,
    B = 2,
}

/// Metadata of a Slot.
/// Slots are used to determine which
/// partitions will get used during boot
/// for A/B devices.
#[bitsize(16)]
#[derive(Clone, Copy, DebugBits, PartialEq, Eq, FromBits)]
pub struct SlotMetadataBits {
    /// How much priority this slot has over
    /// the other. Max is 15 (0b1111)
    pub priority: u4,
    /// Boot tries remaining on this slot before
    /// it gets marked as unbootable
    pub tries_remaining: u3,
    /// Whether the slot has booted successfully
    pub successful_boot: u1,
    /// Whether DM-Verity is corrupted on this slot
    pub verity_corrupted: u1,
    reserved: u7,
}

impl Default for SlotMetadataBits {
    fn default() -> Self {
        Self::new(BOOTCTRL_MAX_PRIORITY, BOOTCTRL_MAX_RETRY, u1::new(0), u1::new(0))
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout,
)]
#[repr(transparent)]
pub struct SlotMetadata(u16);

impl SlotMetadata {
    pub fn bits(self) -> SlotMetadataBits {
        SlotMetadataBits::from(self.0)
    }

    pub fn update(&mut self, bits: SlotMetadataBits) {
        self.0 = u16::from(bits);
    }
}

#[bitsize(16)]
#[derive(Default, DebugBits, Clone, Copy, PartialEq, Eq, FromBits)]
pub struct BootControlInfoBits {
    /// Number of slot managed by BootControl.
    /// Up to 4 slots, but seem to always be 2.
    pub slot_count: u3,
    /// Tries before booting to recovery.
    /// Unused
    pub recovery_tries_remaining: u3,
    pub merge_status: u3,
    reserved: u7,
}

/// Transparant wrapper over u16 for BootControlInfo bitfields.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes, TryFromBytes, KnownLayout,
)]
#[repr(transparent)]
pub struct BootControlInfo(u16);

impl BootControlInfo {
    pub fn bits(self) -> BootControlInfoBits {
        BootControlInfoBits::from(self.0)
    }

    pub fn update(&mut self, bits: BootControlInfoBits) {
        self.0 = u16::from(bits);
    }
}

/// BootControl configuration.
/// This struct is used to manage the A/B metadata for devices
/// supporting multiple slots.
/// https://source.android.com/docs/core/ota/ab/ab_implement
#[derive(Debug, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct BootControl {
    /// The suffix of the current active slot
    /// Either `_a` or `_b`
    suffix: [u8; 4],
    /// Always 0x42414342
    magic: u32,
    /// Version of BootControl API.
    /// Seem to always be 1.
    version: u8,
    /// Bit Field (u16) containing general
    /// info about the slots (slot count)
    control_info: BootControlInfo,
    /// MediaTek put padding here for alignment
    pad: u8,
    /// Specific info for each slot
    slots: [SlotMetadata; 4],
    reserved: [u8; 8],
    /// CRC32 of the previous data
    crc: u32,
}

impl Default for BootControl {
    fn default() -> Self {
        let mut info_bits = BootControlInfoBits::default();
        info_bits.set_slot_count(BOOTCTRL_DEFAULT_SLOT_COUNT);
        let mut control_info = BootControlInfo::default();
        control_info.update(info_bits);

        #[allow(unused_mut)]
        let mut bootctrl = Self {
            suffix: *b"_a\0\0",
            magic: BOOTCTRL_MAGIC,
            version: 1,
            control_info,
            pad: 0,
            slots: [
                SlotMetadata(u16::from(SlotMetadataBits::default())),
                SlotMetadata(u16::from(SlotMetadataBits::default())),
                SlotMetadata(0),
                SlotMetadata(0),
            ],
            reserved: [0; 8],
            crc: 0,
        };

        #[cfg(feature = "crc32")]
        {
            bootctrl.crc = bootctrl.compute_crc();
        }

        bootctrl
    }
}

impl BootControl {
    const SIZE: usize = size_of::<Self>();

    #[allow(clippy::missing_const_for_fn)]
    pub fn is_valid(&self) -> bool {
        #[cfg(feature = "crc32")]
        let crc_valid = self.compute_crc() == self.crc;

        #[cfg(not(feature = "crc32"))]
        let crc_valid = true;

        self.magic == BOOTCTRL_MAGIC && crc_valid
    }

    pub const fn crc32(&self) -> u32 {
        self.crc
    }

    #[cfg(feature = "crc32")]
    fn compute_crc(&self) -> u32 {
        let data = self.as_bytes();
        let mut hasher = Crc32Hasher::new();
        hasher.update(&data[..Self::SIZE - 4]);
        hasher.finalize()
    }

    #[cfg(feature = "crc32")]
    fn update_crc(&mut self) {
        self.crc = self.compute_crc();
    }

    #[cfg(not(feature = "crc32"))]
    pub const fn update_crc(&mut self, new_crc: u32) {
        self.crc = new_crc;
    }

    pub fn get_slot(&self, slot: BootPartition) -> SlotMetadataBits {
        match slot {
            BootPartition::A => self.slots[0].bits(),
            BootPartition::B => self.slots[1].bits(),
        }
    }

    pub fn get_active_slot(&self) -> BootPartition {
        let slot_a = self.slots[0].bits();
        let slot_b = self.slots[1].bits();

        if slot_a.priority() >= slot_b.priority() { BootPartition::A } else { BootPartition::B }
    }

    pub fn set_active_slot(&mut self, slot: BootPartition) {
        let (active, other) = match slot {
            BootPartition::A => (0, 1),
            BootPartition::B => (1, 0),
        };

        let mut slots = self.slots;

        let mut active_bits = slots[active].bits();
        active_bits.set_priority(BOOTCTRL_MAX_PRIORITY);
        active_bits.set_tries_remaining(BOOTCTRL_MAX_RETRY);
        active_bits.set_successful_boot(u1::new(0));
        active_bits.set_verity_corrupted(u1::new(0));
        slots[active].update(active_bits);

        let mut other_bits = slots[other].bits();
        other_bits.set_priority(BOOTCTRL_MAX_PRIORITY - u4::new(1));
        slots[other].update(other_bits);

        self.slots = slots;

        self.suffix = match slot {
            BootPartition::A => *b"_a\0\0",
            BootPartition::B => *b"_b\0\0",
        };

        #[cfg(feature = "crc32")]
        self.update_crc();
    }

    pub fn get_current_suffix(&self) -> Option<&str> {
        let suffix_str = core::str::from_utf8(&self.suffix).ok()?;
        if suffix_str.starts_with(BOOTCTRL_SLOT_A_SUFFIX) {
            Some(BOOTCTRL_SLOT_A_SUFFIX)
        } else if suffix_str.starts_with(BOOTCTRL_SLOT_B_SUFFIX) {
            Some(BOOTCTRL_SLOT_B_SUFFIX)
        } else {
            None
        }
    }
}

impl<'a> TryRead<'a> for BootControl {
    fn try_read(data: &'a [u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BootControl(BootControlError::InvalidSize));
        }

        let bctrl = Self::try_read_from_bytes(&data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        if !bctrl.is_valid() {
            return Err(Error::BootControl(BootControlError::InvalidData));
        }

        Ok(bctrl)
    }
}

#[cfg(feature = "alloc")]
impl TryWrite for BootControl {
    fn try_write(&self, data: &mut [u8]) -> Result<usize> {
        if data.len() < Self::SIZE {
            return Err(Error::BootControl(BootControlError::InvalidSize));
        }

        self.write_to(&mut data[..Self::SIZE]).map_err(|_| Error::Zerocopy)?;

        Ok(Self::SIZE)
    }
}
