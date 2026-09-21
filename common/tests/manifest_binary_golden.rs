//! Pins the binary manifest format v1 to a checked-in fixture.
//!
//! `fixtures/manifest_binary_v1.json` is the manifest (legacy encoding),
//! `fixtures/manifest_binary_v1.bin` is what `encode` produced for it when
//! the format was frozen. If either direction stops matching, the format
//! changed: bump `VERSION` and add a new fixture instead of editing this one
//! — rows encoded with v1 exist in production once the write flag is on.

use common::FileManifest;
use common::manifest::{self, binary};

const JSON: &str = include_str!("fixtures/manifest_binary_v1.json");
const BIN: &[u8] = include_bytes!("fixtures/manifest_binary_v1.bin");

#[test]
fn golden_encode_matches_fixture() {
    let m = FileManifest::from_json(JSON.trim()).unwrap();
    let encoded = binary::encode(&m).unwrap();
    assert_eq!(
        encoded,
        BIN,
        "binary v1 encoding of the golden manifest drifted (len {} vs {})",
        encoded.len(),
        BIN.len()
    );
}

#[test]
fn golden_decode_matches_fixture() {
    let decoded = binary::decode(BIN).unwrap();
    assert_eq!(decoded.to_json().unwrap(), JSON.trim());
    let via_any = manifest::decode_any(BIN).unwrap();
    assert_eq!(via_any.to_json().unwrap(), JSON.trim());
}

#[test]
fn golden_fixture_is_in_line_sized() {
    assert_eq!(&BIN[..4], b"ARMF");
    assert_eq!(BIN[4], binary::VERSION);
    assert!(BIN.len() <= 1_300, "{} bytes", BIN.len());
    assert!(
        JSON.trim().len() > 2_032,
        "legacy {} bytes",
        JSON.trim().len()
    );
}

/// Regenerates the fixture pair. Run once when freezing a NEW version:
/// `cargo test -p common --test manifest_binary_golden regen -- --ignored`.
#[test]
#[ignore]
fn regen() {
    let hex32 = |seed: u8| format!("{seed:02x}").repeat(32);
    let m = FileManifest {
        file_hash: hex32(0xab),
        placement_version: 3,
        placement_epoch: 54_126,
        size: 6 * 1024 * 1024 + 12_345,
        stripe_config: common::StripeConfig {
            size: 8 * 1024 * 1024,
            k: 10,
            m: 20,
        },
        shards: (0..30)
            .map(|i| common::ShardInfo {
                index: i,
                blob_hash: hex32(i as u8 + 1),
            })
            .collect(),
        filename: Some("quarterly-report-2026-Q3-final-v2.pdf".into()),
        content_type: Some("application/pdf".into()),
        shard_holders: (0..30).map(|i| 100 + i as u32 * 7).collect(),
    };
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::write(
        dir.join("manifest_binary_v1.json"),
        format!("{}\n", m.to_json().unwrap()),
    )
    .unwrap();
    std::fs::write(
        dir.join("manifest_binary_v1.bin"),
        binary::encode(&m).unwrap(),
    )
    .unwrap();
}
