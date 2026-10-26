//! Product decoder compatibility with a pinned 0.13.3 fixture and invalid frames.
use meow_rules::mrs_parser::{
    decompress_payload, parse_geosite_payload, parse_header, write_geosite_mrs, GeositePayload,
};

// Produced by the previously pinned zstd 0.13.3, not by the decoder under test.
const PREVIOUS_MRS: &[u8] = &[
    77, 82, 83, 33, 1, 0, 0, 0, 0, 1, 40, 181, 47, 253, 0, 88, 25, 1, 0, 0, 0, 0, 1, 0, 2, 99, 110,
    0, 0, 0, 2, 0, 10, 101, 120, 97, 109, 112, 108, 101, 46, 99, 110, 0, 9, 98, 97, 105, 100, 117,
    46, 99, 111, 109,
];

#[test]
fn previous_release_mrs_decodes_to_the_original_domains() {
    let (_, compressed) = parse_header(PREVIOUS_MRS).unwrap();
    let bytes = decompress_payload(compressed).unwrap();
    let result = parse_geosite_payload(&bytes, None).unwrap();
    assert_eq!(
        result.categories,
        vec![("cn".into(), vec!["example.cn".into(), "baidu.com".into()])]
    );
}

#[test]
fn invalid_and_truncated_frames_fail_before_a_valid_mrs_is_decoded() {
    let (_, valid) = parse_header(PREVIOUS_MRS).unwrap();
    for invalid in [
        &[0, 1, 2, 3][..],
        &valid[..valid.len() - 1],
        &[0x26, 0xb5, 0x2f, 0xfd, 0][..],
    ] {
        assert!(decompress_payload(invalid).is_err());
    }
    let bytes = decompress_payload(valid).unwrap();
    let result = parse_geosite_payload(&bytes, None).unwrap();
    assert_eq!(result.categories[0].1, vec!["example.cn", "baidu.com"]);
}

#[test]
fn current_encoder_and_product_decoder_preserve_mrs_content() {
    let original = GeositePayload {
        categories: vec![("ads".into(), vec!["ad.example.test".into()])],
    };
    let encoded = write_geosite_mrs(&original).unwrap();
    let (_, compressed) = parse_header(&encoded).unwrap();
    let decoded = decompress_payload(compressed).unwrap();
    assert_eq!(
        parse_geosite_payload(&decoded, None).unwrap().categories,
        original.categories
    );
}
