use schc_core::{
    Compressor, Decompressor, Direction, Position, RuleContext, SchcError, SidRegistry,
};

fn sid_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    )
}

fn rule_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/udp_coap.json"
    )
}

fn packet_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/packets/coap_get.bin"
    )
}

fn expected_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/expected/coap_get.schc"
    )
}

fn context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(rule_fixture()).unwrap();

    RuleContext::from_json_str(&json, registry).unwrap()
}

fn compressor() -> Compressor {
    Compressor::new(context()).unwrap()
}

fn coap_get_packet() -> Vec<u8> {
    hex::decode(
        "60000000000c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000c37d0\
         4001002a",
    )
    .unwrap()
}

#[test]
fn compressor_emits_rule_id_for_matching_packet() {
    let compressor = compressor();
    let packet = coap_get_packet();

    let compressed = compressor.compress(Direction::Up, &packet).unwrap();

    assert_eq!(compressed[0] >> 4, 0b0011);
    assert_eq!(compressed.bit_len(), 34);
    assert_eq!(compressed.bytes(), &[0x34, 0x00, 0x00, 0x0a, 0x80]);
}

#[test]
fn compressor_reports_no_matching_rule_for_equal_mismatch() {
    let compressor = compressor();
    let mut packet = coap_get_packet();
    packet[6] = 0x3a;

    let error = compressor.compress(Direction::Up, &packet).unwrap_err();

    assert!(matches!(error, SchcError::NoMatchingRule));
}

#[test]
fn compress_then_decompress_restores_ipv6_udp_coap_packet() {
    let context = context();
    let packet = coap_get_packet();

    let compressor = Compressor::new(context.clone()).unwrap();
    let compressed = compressor.compress(Direction::Up, &packet).unwrap();
    let decompressor = Decompressor::new(context).unwrap();
    let restored = decompressor
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
}

#[test]
fn generate_fixtures() {
    if std::env::var_os("SCHC_UPDATE_FIXTURES").is_none() {
        return;
    }

    let packet = coap_get_packet();
    let compressed = compressor().compress(Direction::Up, &packet).unwrap();

    std::fs::create_dir_all(
        std::path::Path::new(packet_fixture())
            .parent()
            .expect("packet fixture path has a parent"),
    )
    .unwrap();
    std::fs::create_dir_all(
        std::path::Path::new(expected_fixture())
            .parent()
            .expect("expected fixture path has a parent"),
    )
    .unwrap();
    std::fs::write(packet_fixture(), packet).unwrap();
    std::fs::write(expected_fixture(), compressed.bytes()).unwrap();
}

#[test]
fn golden_coap_get_round_trip_matches_fixtures() {
    let packet = std::fs::read(packet_fixture()).unwrap();
    let expected = std::fs::read(expected_fixture()).unwrap();
    let context = context();

    let compressor = Compressor::new(context.clone()).unwrap();
    let compressed = compressor.compress(Direction::Up, &packet).unwrap();
    assert_eq!(compressed.bytes(), expected);

    let decompressor = Decompressor::new(context).unwrap();
    let restored = decompressor.decompress(Position::Core, &expected).unwrap();
    assert_eq!(restored, packet);
}
