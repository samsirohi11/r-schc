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

fn coap_path_payload_packet_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/packets/coap_path_payload.bin"
    )
}

fn coap_path_payload_expected_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/expected/coap_path_payload.schc"
    )
}

fn icmpv6_echo_packet_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/packets/icmpv6_echo.bin"
    )
}

fn icmpv6_echo_expected_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/expected/icmpv6_echo.schc"
    )
}

fn context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(rule_fixture()).unwrap();

    RuleContext::from_json_str(&json, registry).unwrap()
}

fn dynamic_coap_rule_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/dynamic_coap.json"
    )
}

fn udp_payload_rule_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/udp_payload.json"
    )
}

fn icmpv6_echo_rule_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/icmpv6_echo.json"
    )
}

fn coap_option_by_number_rule_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/coap_option_by_number.json"
    )
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

fn coap_options_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(dynamic_coap_rule_fixture()).unwrap();
    RuleContext::from_json_str(&json, registry).unwrap()
}

fn coap_option_by_number_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(coap_option_by_number_rule_fixture()).unwrap();
    RuleContext::from_json_str(&json, registry).unwrap()
}

fn udp_payload_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(udp_payload_rule_fixture()).unwrap();
    RuleContext::from_json_str(&json, registry).unwrap()
}

fn coap_token_packet() -> Vec<u8> {
    hex::decode(
        "60000000000e114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000e7905\
         42021234aabb",
    )
    .unwrap()
}

fn udp_payload_packet() -> Vec<u8> {
    hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap()
}

fn coap_path_payload_packet() -> Vec<u8> {
    hex::decode(
        "600000000018114020010db8000000000000000000000001\
         20010db80000000000000000000000021633163300188da9\
         42021234aabbb474656d70ff32312e35",
    )
    .unwrap()
}

fn coap_option_by_number_packet() -> Vec<u8> {
    hex::decode(
        "600000000017114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633001750a1\
         42011234aabbb163118eff32312e35",
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
fn udp_payload_residue_round_trips_when_rule_has_payload_field() {
    let context = udp_payload_context();
    let packet = udp_payload_packet();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
}

#[test]
fn coap_options_and_payload_round_trip_with_variable_lengths() {
    let context = coap_options_context();
    let packet = coap_path_payload_packet();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
}

#[test]
fn coap_option_by_number_and_payload_marker_round_trip() {
    let context = coap_option_by_number_context();
    let packet = coap_option_by_number_packet();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
}

#[test]
fn decompression_honors_sent_udp_checksum() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let mut json = std::fs::read_to_string(udp_payload_rule_fixture()).unwrap();
    json = json.replace(
        r#"{ "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }"#,
        r#"{ "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }"#,
    );
    let context = RuleContext::from_json_str(&json, registry).unwrap();
    let mut packet = udp_payload_packet();
    packet[46] = 0x12;
    packet[47] = 0x34;

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(&restored[46..48], &[0x12, 0x34]);
    assert_eq!(restored, packet);
}

fn icmpv6_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(icmpv6_echo_rule_fixture()).unwrap();
    RuleContext::from_json_str(&json, registry).unwrap()
}

fn icmpv6_echo_packet() -> Vec<u8> {
    hex::decode(
        "60000000000c3a4020010db8000000000000000000000001\
         20010db80000000000000000000000028000333e12340001\
         70696e67",
    )
    .unwrap()
}

fn icmpv6_error_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 5,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "direction": "bi", "target": "3a", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "ff", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-type", "length_bits": 8, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-code", "length_bits": 8, "direction": "bi", "target": "04", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },

          { "field": "fid-ipv6-version", "length_bits": 4, "field_position": 2, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "field_position": 2, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "11", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "ff", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-dev-port", "length_bits": 16, "field_position": 2, "direction": "bi", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-app-port", "length_bits": 16, "field_position": 2, "direction": "bi", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-length", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-udp-checksum", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }
        ]
      }]
    }
    "#;
    RuleContext::from_json_str(json, registry).unwrap()
}

fn icmpv6_error_packet() -> Vec<u8> {
    hex::decode(
        "6000000000383aff20010db8000000000000000000000002\
         20010db80000000000000000000000010104312600000000\
         60000000000811ff20010db8000000000000000000000001\
         20010db80000000000000000000000021633163300087803",
    )
    .unwrap()
}

#[test]
fn icmpv6_echo_round_trip() {
    let context = icmpv6_context();
    let packet = icmpv6_echo_packet();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, packet);
}

#[test]
fn icmpv6_error_embedded_packet_round_trip_reverses_inner_direction() {
    let context = icmpv6_error_context();
    let packet = icmpv6_error_packet();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Down, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Device, compressed.bytes())
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
#[ignore = "set SCHC_UPDATE_FIXTURES=1 to rewrite golden fixtures"]
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

    let coap_packet = coap_path_payload_packet();
    let coap_compressed = Compressor::new(coap_options_context())
        .unwrap()
        .compress(Direction::Up, &coap_packet)
        .unwrap();
    std::fs::create_dir_all(
        std::path::Path::new(coap_path_payload_packet_fixture())
            .parent()
            .expect("packet fixture path has a parent"),
    )
    .unwrap();
    std::fs::create_dir_all(
        std::path::Path::new(coap_path_payload_expected_fixture())
            .parent()
            .expect("expected fixture path has a parent"),
    )
    .unwrap();
    std::fs::write(coap_path_payload_packet_fixture(), coap_packet).unwrap();
    std::fs::write(
        coap_path_payload_expected_fixture(),
        coap_compressed.bytes(),
    )
    .unwrap();

    let icmp_packet = icmpv6_echo_packet();
    let icmp_compressed = Compressor::new(icmpv6_context())
        .unwrap()
        .compress(Direction::Up, &icmp_packet)
        .unwrap();
    std::fs::create_dir_all(
        std::path::Path::new(icmpv6_echo_packet_fixture())
            .parent()
            .expect("packet fixture path has a parent"),
    )
    .unwrap();
    std::fs::create_dir_all(
        std::path::Path::new(icmpv6_echo_expected_fixture())
            .parent()
            .expect("expected fixture path has a parent"),
    )
    .unwrap();
    std::fs::write(icmpv6_echo_packet_fixture(), icmp_packet).unwrap();
    std::fs::write(icmpv6_echo_expected_fixture(), icmp_compressed.bytes()).unwrap();
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

#[test]
fn golden_coap_path_payload_round_trip_matches_fixtures() {
    let packet = std::fs::read(coap_path_payload_packet_fixture()).unwrap();
    let expected = std::fs::read(coap_path_payload_expected_fixture()).unwrap();
    let context = coap_options_context();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    assert_eq!(compressed.bytes(), expected);

    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, &expected)
        .unwrap();
    assert_eq!(restored, packet);
}

#[test]
fn golden_icmpv6_echo_round_trip_matches_fixtures() {
    let packet = std::fs::read(icmpv6_echo_packet_fixture()).unwrap();
    let expected = std::fs::read(icmpv6_echo_expected_fixture()).unwrap();
    let context = icmpv6_context();

    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    assert_eq!(compressed.bytes(), expected);

    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, &expected)
        .unwrap();
    assert_eq!(restored, packet);
}

#[test]
fn decompressor_rejects_mapping_index_out_of_range() {
    let context = context();
    let decompressor = Decompressor::new(context).unwrap();

    let error = decompressor
        .decompress(Position::Core, &[0xff, 0xff])
        .unwrap_err();

    assert!(matches!(
        error,
        SchcError::NoMatchingRule | SchcError::InvalidResidue(_)
    ));
}

#[test]
fn decompressor_rejects_full_byte_trailing_residue_without_payload_field() {
    let context = context();
    let decompressor = Decompressor::new(context).unwrap();

    let mut compressed = compressor()
        .compress(Direction::Up, &coap_get_packet())
        .unwrap()
        .bytes()
        .to_vec();
    compressed.push(0xaa);

    let error = decompressor
        .decompress(Position::Core, &compressed)
        .unwrap_err();

    assert!(matches!(error, SchcError::InvalidResidue(_)));
}

#[test]
fn decompressor_rejects_nonzero_sub_byte_padding() {
    let context = context();
    let decompressor = Decompressor::new(context).unwrap();

    let compressed = compressor()
        .compress(Direction::Up, &coap_get_packet())
        .unwrap();
    // The compressed datagram ends with zero sub-byte padding. Flip the last
    // padding bit to make it non-zero.
    let mut bytes = compressed.bytes().to_vec();
    *bytes.last_mut().unwrap() |= 0x01;

    let error = decompressor
        .decompress(Position::Core, &bytes)
        .unwrap_err();

    assert!(matches!(error, SchcError::InvalidResidue(_)));
}

#[test]
fn decompressor_accepts_zero_sub_byte_padding() {
    let context = context();
    let decompressor = Decompressor::new(context).unwrap();

    let compressed = compressor()
        .compress(Direction::Up, &coap_get_packet())
        .unwrap();
    // The compressed datagram already ends with zero sub-byte padding; verify
    // that decompression succeeds without modifying the padding bits.
    let restored = decompressor
        .decompress(Position::Core, compressed.bytes())
        .unwrap();

    assert_eq!(restored, coap_get_packet());
}

#[test]
fn compression_without_payload_field_rejects_packet_with_payload() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(udp_payload_rule_fixture()).unwrap();
    // Remove the explicit UDP payload field so the rule no longer accounts for
    // UDP payload bytes. The compressor must not silently accept a packet whose
    // payload bytes no field consumed.
    let json = json.replace(
        r#""cda": "compute" },
        { "field": "fid-udp-payload", "length": { "type": "variable", "unit": "bytes" }, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }"#,
        r#""cda": "compute" }"#,
    );
    let context = RuleContext::from_json_str(&json, registry).unwrap();
    let packet = udp_payload_packet();

    let error = Compressor::new(context)
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap_err();

    assert!(matches!(error, SchcError::NoMatchingRule));
}

/// A rule set with two rules that share bidirectional IPv6 and CoAP header
/// fields but diverge by UDP port direction: rule 1 matches uplink packets,
/// rule 2 matches downlink packets. Both rules are complete (they account for
/// every byte of the packet) so the compressor can accept a matching packet.
fn direction_split_context() -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [
        {
          "rule_id": 1,
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
            { "field": "fid-coap-tkl", "length_bits": 4, "direction": "bi", "target": "00", "mo": "ignore", "cda": "value-sent" },
            { "field": "fid-coap-code", "length_bits": 8, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-coap-mid", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
          ]
        },
        {
          "rule_id": 2,
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
            { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "down", "target": "1633", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-udp-app-port", "length_bits": 16, "direction": "down", "target": "1633", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-udp-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
            { "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
            { "field": "fid-coap-version", "length_bits": 2, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-coap-type", "length_bits": 2, "direction": "bi", "target": "00", "mo": "ignore", "cda": "value-sent" },
            { "field": "fid-coap-tkl", "length_bits": 4, "direction": "bi", "target": "00", "mo": "ignore", "cda": "value-sent" },
            { "field": "fid-coap-code", "length_bits": 8, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-coap-mid", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
          ]
        }
      ]
    }
    "#;
    RuleContext::from_json_str(json, registry).unwrap()
}

/// Uplink IPv6/UDP/CoAP packet: source is the device, destination is the
/// application. Matches rule 1 of the direction-split context.
fn direction_split_uplink_packet() -> Vec<u8> {
    hex::decode(
        "60000000000c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000c37d0\
         4001002a",
    )
    .unwrap()
}

/// Downlink IPv6/UDP/CoAP packet: source is the application, destination is
/// the device. The IPv6 source and destination are swapped relative to the
/// uplink packet; the UDP ports remain 1633/1633, so the computed UDP checksum
/// remains valid because the pseudo-header address sum is unchanged. Matches rule 2 of
/// the direction-split context.
fn direction_split_downlink_packet() -> Vec<u8> {
    hex::decode(
        "60000000000c114020010db8000000000000000000000002\
         20010db800000000000000000000000116331633000c37d0\
         4001002a",
    )
    .unwrap()
}

#[test]
fn direction_split_uplink_selects_uplink_rule() {
    let context = direction_split_context();
    let compressor = Compressor::new(context.clone()).unwrap();

    let compressed = compressor
        .compress(Direction::Up, &direction_split_uplink_packet())
        .unwrap();

    // The first nibble is the 4-bit rule ID. Uplink must select rule 1.
    assert_eq!(compressed.bytes()[0] >> 4, 1);

    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();
    assert_eq!(restored, direction_split_uplink_packet());
}

#[test]
fn direction_split_downlink_selects_downlink_rule() {
    let context = direction_split_context();
    let compressor = Compressor::new(context.clone()).unwrap();

    let compressed = compressor
        .compress(Direction::Down, &direction_split_downlink_packet())
        .unwrap();

    // The first nibble is the 4-bit rule ID. Downlink must select rule 2.
    assert_eq!(compressed.bytes()[0] >> 4, 2);

    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Device, compressed.bytes())
        .unwrap();
    assert_eq!(restored, direction_split_downlink_packet());
}

#[test]
fn direction_split_uplink_packet_does_not_match_downlink_rule() {
    let context = direction_split_context();
    let compressor = Compressor::new(context).unwrap();

    // The downlink packet must not compress in the uplink direction: the
    // downlink-only UDP port branches are skipped for Direction::Up, and the
    // uplink-only branches do not match the swapped addresses.
    let error = compressor
        .compress(Direction::Up, &direction_split_downlink_packet())
        .unwrap_err();

    assert!(matches!(error, SchcError::NoMatchingRule));
}

#[test]
fn direction_split_downlink_packet_does_not_match_uplink_rule() {
    let context = direction_split_context();
    let compressor = Compressor::new(context).unwrap();

    // The uplink packet must not compress in the downlink direction: the
    // uplink-only UDP port branches are skipped for Direction::Down, and the
    // downlink-only branches do not match the swapped addresses.
    let error = compressor
        .compress(Direction::Down, &direction_split_uplink_packet())
        .unwrap_err();

    assert!(matches!(error, SchcError::NoMatchingRule));
}
