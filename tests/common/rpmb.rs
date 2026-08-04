use hacc::traits::TryRead;
#[cfg(feature = "alloc")]
use hacc::traits::TryWrite;
use hacc::{LockState, SecRpmbInfo};

const RPMB_INFO: &[u8] = include_bytes!("../../tests/files/rpmb_info.bin");
#[test]
fn rpmb_info_create_and_validate() {
    let rpmb = SecRpmbInfo::new(LockState::Lock);

    assert!(rpmb.is_valid(), "Rpmb info should be valid");
    assert_eq!(rpmb.version(), 1);
    assert_eq!(rpmb.lock_state(), LockState::Lock);
}

#[test]
fn rpmb_info_lock_states() {
    for lock_state in [
        LockState::Default,
        LockState::MpDefault,
        LockState::Unlock,
        LockState::Lock,
        LockState::Verified,
        LockState::Custom,
    ] {
        let rpmb = SecRpmbInfo::new(lock_state);
        assert!(rpmb.is_valid());
        assert_eq!(rpmb.lock_state(), lock_state);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn rpmb_info_try_read_and_write() {
    let original = SecRpmbInfo::new(LockState::Lock);

    let mut buffer = [0u8; size_of::<SecRpmbInfo>()];
    let bytes_written = original.try_write(&mut buffer).expect("Failed to write");

    assert_eq!(bytes_written, std::mem::size_of::<SecRpmbInfo>());

    let read_back = SecRpmbInfo::try_read(&buffer).expect("Failed to read");

    assert!(read_back.is_valid());
    assert_eq!(read_back.lock_state(), original.lock_state());
}

#[test]
fn rpmb_info_invalid_size() {
    let invalid_data = [0u8; 10];
    let result = SecRpmbInfo::try_read(&invalid_data);
    assert!(result.is_err(), "Should fail with invalid size");
}

#[test]
fn rpmb_info_invalid_data() {
    let data = [0u8; size_of::<SecRpmbInfo>()];

    let result = SecRpmbInfo::try_read(&data);

    assert!(result.is_err(), "Should fail with invalid data");
}

#[test]
fn rpmb_info_from_file() {
    let rpmb = SecRpmbInfo::try_read(RPMB_INFO).expect("Failed to read RPMB info from file");

    assert!(rpmb.is_valid(), "RPMB info should be valid");
    assert_eq!(rpmb.version(), 1);
    assert_eq!(rpmb.lock_state(), LockState::Lock);
}
