use hacc::gfh::{GfhFile, GfhFileInfo, GfhFileType, GfhFlashDev, GfhSigType, GfhType};
use hacc::traits::TryRead;

const PRELOADER: &[u8] = include_bytes!("../../tests/files/preloader.img");

#[test]
fn gfh_parse() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");

    assert_eq!(file.gfhs().count(), 6);
    assert!(file.signature().is_some());
    assert!(file.get_gfh(GfhType::AntiClone).is_some());
    assert!(file.get_gfh(GfhType::ConfidentialBinInfo).is_none())
}

#[test]
fn gfh_parse_invalid_and_empty() {
    let data = [0u8; 64];
    assert!(GfhFile::try_read(&data).is_err());

    let empty = [];
    assert!(GfhFile::try_read(&empty).is_err());

    let truncated = &PRELOADER[..10];
    assert!(GfhFile::try_read(truncated).is_err());
}

#[test]
fn gfh_file_info_properties() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");
    let file_info = file.file_info();

    assert!(file_info.file_len() > 0);
    assert!(file_info.content_offset() < file_info.file_len() as u32);
    assert!(file_info.max_size() > 0);
    assert_eq!(file_info.file_type(), GfhFileType::ArmBl);
}

#[test]
fn gfh_content_and_signature() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");

    let content = file.content();
    assert!(!content.is_empty());

    if let Some(sig) = file.signature() {
        assert!(!sig.is_empty());
    }
}

#[test]
fn gfh_sections_properties() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");

    let section_count = file.gfhs().count();
    assert!(section_count > 0);

    for gfh in file.gfhs() {
        assert!(gfh.validate().is_ok());
        assert!(gfh.header().size() > 0);
        let size = gfh.header().size() as usize;
        assert!(size < 1024 * 1024);
    }

    assert!(file.gfhs().any(|s| s.header().gfh_type() == GfhType::FileInfo));
}

#[test]
fn gfh_get_sections() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");

    assert!(file.get_gfh(GfhType::AntiClone).is_some());
    assert!(file.get_gfh(GfhType::EppInfo).is_none());
    assert!(file.get_gfh(GfhType::MauiInfo).is_none());
}

#[test]
fn gfh_content_offset_and_bounds() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");
    let file_info = file.file_info();

    assert!(file_info.content_offset() < file_info.file_len() as u32);
    assert!(file_info.content_len() <= file_info.file_len());

    let content = file.content();
    assert_eq!(content.len(), file_info.content_len());
}

#[test]
fn gfh_signature_consistency() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");
    let file_info = file.file_info();

    let sig_type = file_info.sig_type();
    let has_signature = file.signature().is_some();
    let sig_type_none = sig_type == GfhSigType::None;

    assert_eq!(has_signature, !sig_type_none);

    if file_info.sig_len() > 0 {
        assert!(file.signature().is_some());
    }
}

#[test]
fn gfh_file_len_consistency() {
    let file = GfhFile::try_read(PRELOADER).expect("Failed to parse GFH file");
    let file_info = file.file_info();

    assert_eq!(
        file_info.content_len() + file_info.sig_len() as usize,
        file_info.file_len() - file_info.content_offset() as usize
    );
}

#[test]
fn gfh_set_file_type() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_file_type(GfhFileType::ArmBl);
    assert_eq!(file_info.file_type(), GfhFileType::ArmBl);

    file_info.set_file_type(GfhFileType::ArmExtBl);
    assert_eq!(file_info.file_type(), GfhFileType::ArmExtBl);
}

#[test]
fn gfh_set_sig_type() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_sig_type(GfhSigType::Sha256);
    assert_eq!(file_info.sig_type(), GfhSigType::Sha256);

    file_info.set_sig_type(GfhSigType::Single);
    assert_eq!(file_info.sig_type(), GfhSigType::Single);
}

#[test]
fn gfh_set_addresses_and_lengths() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_load_addr(0x1000);
    assert_eq!(file_info.load_addr(), 0x1000);

    file_info.set_content_offset(512);
    assert_eq!(file_info.content_offset(), 512);

    file_info.set_max_size(0x100000);
    assert_eq!(file_info.max_size(), 0x100000);

    file_info.set_jump_offset(0x2000);
    assert_eq!(file_info.jump_offset(), 0x2000);
}

#[test]
fn gfh_set_file_version() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_file_ver(1);
    assert_eq!(file_info.file_ver(), 1);

    file_info.set_file_ver(255);
    assert_eq!(file_info.file_ver(), 255);
}

#[test]
fn gfh_set_flash_device() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_flash_dev(GfhFlashDev::NandSeq);
    assert_eq!(file_info.flash_dev(), GfhFlashDev::NandSeq);

    file_info.set_flash_dev(GfhFlashDev::EmmcBoot);
    assert_eq!(file_info.flash_dev(), GfhFlashDev::EmmcBoot);
}

#[test]
fn gfh_set_sig_length() {
    let mut file_info = GfhFileInfo::default();
    file_info.set_file_len(0x1000);

    let initial_file_len = file_info.file_len();
    file_info.set_sig_len(256);

    assert_eq!(file_info.sig_len(), 256);
    assert!(file_info.file_len() > initial_file_len);

    let new_file_len = file_info.file_len();
    file_info.set_sig_len(512);
    assert_eq!(file_info.sig_len(), 512);
    assert!(file_info.file_len() > new_file_len);
}

#[test]
fn gfh_set_file_length() {
    let mut file_info = GfhFileInfo::default();

    file_info.set_file_len(0x2000);
    assert!(file_info.file_len() > 0);

    file_info.set_file_len(0x4000);
    assert!(file_info.file_len() > 0x2000);
}

#[test]
fn gfh_default_values() {
    let file_info = GfhFileInfo::default();

    assert_eq!(file_info.file_type(), GfhFileType::FileNone);
    assert_eq!(file_info.sig_type(), GfhSigType::None);
    assert_eq!(file_info.flash_dev(), GfhFlashDev::None);
    assert_eq!(file_info.file_len(), 0);
    assert_eq!(file_info.content_offset(), 0);
}
