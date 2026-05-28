use hacc::Preloader;
use hacc::traits::TryRead;

const PRELOADER: &[u8] = include_bytes!("../../tests/files/preloader.img");
const EMI_SIZE: usize = 0x50C;
const PL_CONTENT_SIZE: usize = 0x9A4F4;

#[test]
fn preloader_parse() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");

    assert!(preloader.gfh().gfhs().count() > 0);
}

#[test]
fn preloader_gfh_access() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let gfh = preloader.gfh();

    assert!(gfh.file_info().file_len() > 0);
    assert!(!gfh.content().is_empty());
}

#[test]
fn preloader_emi_detection_and_size() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let emi = preloader.emi().unwrap();

    assert!(!emi.is_empty());
    assert_eq!(&emi[..16], Preloader::EMI_ID);
    assert_eq!(emi.len(), EMI_SIZE);
}

#[test]
fn preloader_gfh_sections_validation() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let section_count = preloader.gfh().gfhs().count();

    assert!(section_count > 0);

    for gfh in preloader.gfh().gfhs() {
        assert!(gfh.validate().is_ok());
        assert!(gfh.header().size() > 0);
    }
}

#[test]
fn preloader_content_size_consistency() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let gfh = preloader.gfh();
    let content = gfh.content();
    let file_info = gfh.file_info();

    assert!(!content.is_empty());
    assert_eq!(content.len(), PL_CONTENT_SIZE);
    assert_eq!(content.len(), file_info.content_len());
}

#[test]
fn preloader_signature_consistency() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let gfh = preloader.gfh();
    let file_info = gfh.file_info();

    assert!(file_info.sig_len() > 0);
    let sig = gfh.signature().unwrap();
    assert_eq!(sig.len() as u32, file_info.sig_len());
}

#[test]
fn preloader_file_info_bounds() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let file_info = preloader.gfh().file_info();

    assert!(file_info.file_len() > 0);
    assert!(file_info.max_size() > 0);
    assert!(file_info.content_offset() < file_info.file_len() as u32);
}

#[test]
fn preloader_emi_within_content() {
    let preloader = Preloader::try_read(PRELOADER).expect("Failed to parse preloader");
    let emi = preloader.emi().unwrap();
    let content = preloader.gfh().content();

    assert!(emi.len() <= content.len());
}

#[test]
fn preloader_invalid_data() {
    let invalid = [0u8; 64];
    assert!(Preloader::try_read(&invalid).is_err());

    let truncated = &PRELOADER[..10];
    assert!(Preloader::try_read(truncated).is_err());

    let empty = [];
    assert!(Preloader::try_read(&empty).is_err());
}
