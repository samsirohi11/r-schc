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

fn dynamic_token_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 4,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "direction": "bi", "target": "11", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-app-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-coap-version", "length_bits": 2, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-coap-type", "length_bits": 2, "direction": "bi", "target": "00", "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-tkl", "length_bits": 4, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-code", "length_bits": 8, "direction": "bi", "target": "02", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-coap-mid", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-token", "length": { "type": "token-length" }, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#;
    RuleContext::from_json_str(json, registry).unwrap()
}

fn coap_token_packet() -> Vec<u8> {
    hex::decode(
        "60000000000e114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000e7905\
         42021234aabb",
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
fn compressor_uses_tkl_to_send_token_length() {
    let compressor = Compressor::new(dynamic_token_context()).unwrap();
    let compressed = compressor
        .compress(Direction::Up, &coap_token_packet())
        .unwrap();

    assert_eq!(compressed.bytes()[0] >> 4, 4);
    assert!(compressed.bit_len() > 4);
}

#[test]
fn coap_token_round_trip_uses_dynamic_length() {
    let context = dynamic_token_context();
    let packet = coap_token_packet();

    let compressor = Compressor::new(context.clone()).unwrap();
    let compressed = compressor.compress(Direction::Up, &packet).unwrap();
    let decompressor = Decompressor::new(context).unwrap();

    let restored = decompressor
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
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
