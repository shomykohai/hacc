use hacc::seccfg::DmVerityState;
use hacc::traits::{TryRead, TryWrite};
use hacc::{LockState, SecCfgV4};

const SECCFG_V4_IMAGE: &[u8] = include_bytes!("../../tests/files/seccfg.bin");
#[test]
fn seccfg_create_and_validate() {
    let seccfg = SecCfgV4::new(LockState::Unlock);

    assert!(seccfg.is_valid(), "Seccfg should be valid");
    assert_eq!(seccfg.size(), size_of::<SecCfgV4>());
    assert_eq!(seccfg.version(), 4);
    assert_eq!(seccfg.lock_state(), LockState::Unlock);
}

#[test]
fn seccfg_lock_states() {
    for lock_state in [
        LockState::Default,
        LockState::MpDefault,
        LockState::Unlock,
        LockState::Lock,
        LockState::Verified,
        LockState::Custom,
    ] {
        let seccfg = SecCfgV4::new(lock_state);
        assert!(seccfg.is_valid());
        assert_eq!(seccfg.lock_state(), lock_state);
    }
}

#[test]
fn seccfg_try_read_and_write() {
    let original = SecCfgV4::new(LockState::Lock);

    let mut buffer = vec![0u8; 1024];
    let bytes_written = original.try_write(&mut buffer).expect("Failed to write");

    assert_eq!(bytes_written, std::mem::size_of::<SecCfgV4>());

    let read_back = SecCfgV4::try_read(&buffer).expect("Failed to read");

    assert!(read_back.is_valid());
    assert_eq!(read_back.lock_state(), original.lock_state());
    assert_eq!(read_back.dm_verity_state(), original.dm_verity_state());
    assert_eq!(read_back.sboot_runtime(), original.sboot_runtime());
    assert_eq!(read_back.hash(), original.hash());
}

#[test]
fn seccfg_modify_fields() {
    let mut seccfg = SecCfgV4::new(LockState::Default);

    seccfg.set_lock_state(LockState::Unlock);
    seccfg.set_dm_verity_state(DmVerityState::GeneralError);
    seccfg.set_hash(&[0xFF; 32]);

    assert_eq!(seccfg.lock_state(), LockState::Unlock);
    assert_eq!(seccfg.dm_verity_state(), DmVerityState::GeneralError);
    assert_eq!(seccfg.hash(), &[0xFF; 32]);

    let mut buffer = vec![0u8; 0x200];
    seccfg.try_write(&mut buffer).expect("Failed to write");

    let read_back = SecCfgV4::try_read(&buffer).expect("Failed to read");
    assert_eq!(read_back.lock_state(), LockState::Unlock);
    assert_eq!(read_back.dm_verity_state(), DmVerityState::GeneralError);
    assert_eq!(read_back.hash(), &[0xFF; 32]);
}

#[test]
fn seccfg_invalid_size() {
    let invalid = [0u8; 4];
    let result = SecCfgV4::try_read(&invalid);

    assert!(result.is_err(), "Should fail with invalid size");
}

#[test]
fn seccfg_invalid_magic() {
    let data = [0u8; size_of::<SecCfgV4>()];

    let result = SecCfgV4::try_read(&data);

    assert!(result.is_err(), "Should fail with invalid magic");
}

#[test]
fn seccfg_from_image() {
    let seccfg = SecCfgV4::try_read(SECCFG_V4_IMAGE).expect("Failed to read SecCfg from image");

    let known_hash: [u8; 32] = [
        0x47, 0xF7, 0x0F, 0xF4, 0x01, 0x8E, 0x93, 0xCF, 0x82, 0x5C, 0xD0, 0x99, 0xF4, 0x74, 0xB7,
        0x91, 0x33, 0x52, 0xF8, 0x63, 0x0C, 0x62, 0x47, 0xEE, 0x7C, 0xA7, 0xA6, 0x16, 0x70, 0x45,
        0x49, 0x29,
    ];

    assert!(seccfg.is_valid(), "Seccfg from image should be valid");
    assert_eq!(seccfg.version(), 4);
    assert_eq!(seccfg.lock_state(), LockState::Unlock);
    assert_eq!(seccfg.dm_verity_state(), DmVerityState::StatusOk);
    assert_eq!(seccfg.sboot_runtime(), 0);
    assert_eq!(seccfg.hash(), &known_hash);
}
