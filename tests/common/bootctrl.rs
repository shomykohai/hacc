use hacc::traits::{TryRead, TryWrite};
use hacc::{BootControl, BootPartition, OFFSET_SLOT_SUFFIX};

const MISC_IMAGE: &[u8] = include_bytes!("../../tests/files/misc.bin");
const INITIAL_CRC: u32 = 0xC5020EE9;
#[cfg(feature = "crc32")]
const FINAL_CRC: u32 = 0x4A5F3306;

#[test]
fn bootctrl_parse() {
    let mut bctl = BootControl::try_read(&MISC_IMAGE[OFFSET_SLOT_SUFFIX..]).unwrap();

    assert_eq!(bctl.get_active_slot(), BootPartition::A);
    assert_eq!(bctl.get_current_suffix(), Some("_a"));
    assert_eq!(bctl.crc32(), INITIAL_CRC);

    bctl.set_active_slot(BootPartition::B);

    assert_eq!(bctl.get_active_slot(), BootPartition::B);
    assert_eq!(bctl.get_current_suffix(), Some("_b"));
    #[cfg(feature = "crc32")]
    assert_eq!(bctl.crc32(), FINAL_CRC);
}

#[cfg(feature = "alloc")]
#[test]
fn bootctrl_write_and_read_back() {
    let mut bctl = BootControl::try_read(&MISC_IMAGE[OFFSET_SLOT_SUFFIX..]).unwrap();

    bctl.set_active_slot(BootPartition::B);

    let mut buffer = vec![0u8; 32];
    let bytes_written = bctl.try_write(&mut buffer).expect("Failed to write BootControl");

    assert_eq!(bytes_written, size_of::<BootControl>());

    let read_back = BootControl::try_read(&buffer).expect("Failed to read back BootControl");

    assert_eq!(read_back.get_active_slot(), BootPartition::B);
    assert_eq!(read_back.get_current_suffix(), Some("_b"));
    #[cfg(feature = "crc32")]
    assert_eq!(read_back.crc32(), FINAL_CRC);
}
