use hacc::traits::TryRead;
use hacc::{Da, DaHeader, DaHeaderVersion, DaVersion};
use include_bytes_aligned::include_bytes_aligned;

const DA_V5: &[u8] = include_bytes_aligned!(4, "../files/DA_V5.bin");
const DA_DESC: &str = "MTK_AllInOne_DA_v3.3001.2023/02/20.16:47_590669";

#[test]
fn da_v5_parse() {
    let da = Da::try_read(DA_V5).expect("Failed to read DA V5 header");

    assert_eq!(da.header().id(), "MTK_DOWNLOAD_AGENT");
    assert_eq!(da.header().version(), DaHeaderVersion::V4);
    assert_eq!(da.header().magic(), DaHeader::DA_MAGIC);
    assert_eq!(da.header().desc(), DA_DESC);
    assert_eq!(da.entries().count(), 1);

    for entry in da.entries() {
        assert_eq!(entry.version(), DaVersion::V5);
    }
}
