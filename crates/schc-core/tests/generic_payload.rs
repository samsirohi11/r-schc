use schc_core::{
    Compressor, Decompressor, Direction, FieldRef, Position, RuleContext, SchcError, SidRegistry,
};

fn registry() -> SidRegistry {
    SidRegistry::load_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    ))
    .unwrap()
}

fn context(fields: &str) -> RuleContext {
    let json = format!(r#"{{"rules":[{{"rule_id":7,"rule_id_length":4,"fields":[{fields}]}}]}}"#);
    RuleContext::from_json_str(&json, registry()).unwrap()
}

fn field(
    name: &str,
    length: &str,
    position: usize,
    direction: &str,
    target: &str,
    mo: &str,
    cda: &str,
) -> String {
    format!(
        r#"{{"field":"{name}","length":{length},"field_position":{position},"direction":"{direction}","target":{target},"mo":"{mo}","cda":"{cda}"}}"#
    )
}

fn fixed(
    name: &str,
    bits: usize,
    position: usize,
    direction: &str,
    target: &str,
    mo: &str,
    cda: &str,
) -> String {
    format!(
        r#"{{"field":"{name}","length_bits":{bits},"field_position":{position},"direction":"{direction}","target":{target},"mo":"{mo}","cda":"{cda}"}}"#
    )
}

fn ipv6(next_header: &str, hop_limit: &str, position: usize) -> Vec<String> {
    vec![
        fixed(
            "fid-ipv6-version",
            4,
            position,
            "bi",
            "\"06\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-trafficclass",
            8,
            position,
            "bi",
            "\"00\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-flowlabel",
            20,
            position,
            "bi",
            "\"000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-payload-length",
            16,
            position,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
        fixed(
            "fid-ipv6-nextheader",
            8,
            position,
            "bi",
            &format!("\"{next_header}\""),
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-hoplimit",
            8,
            position,
            "bi",
            &format!("\"{hop_limit}\""),
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-devprefix",
            64,
            position,
            "bi",
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-deviid",
            64,
            position,
            "bi",
            "\"0000000000000001\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-appprefix",
            64,
            position,
            "bi",
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-appiid",
            64,
            position,
            "bi",
            "\"0000000000000002\"",
            "equal",
            "not-sent",
        ),
    ]
}

fn udp(position: usize) -> Vec<String> {
    vec![
        fixed(
            "fid-udp-dev-port",
            16,
            position,
            "bi",
            "\"1633\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-udp-app-port",
            16,
            position,
            "bi",
            "\"1633\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-udp-length",
            16,
            position,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
        fixed(
            "fid-udp-checksum",
            16,
            position,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
    ]
}

fn generic_udp_context() -> RuleContext {
    let mut fields = ipv6("11", "40", 1);
    fields.extend(udp(1));
    fields.push(field(
        "fid-payload",
        r#"{"type":"variable","unit":"bytes"}"#,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    context(&fields.join(","))
}

fn generic_udp_fixed_payload_context(bits: usize) -> RuleContext {
    let mut fields = ipv6("11", "40", 1);
    fields.extend(udp(1));
    fields.push(fixed(
        "fid-payload",
        bits,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    context(&fields.join(","))
}

fn generic_coap_context() -> RuleContext {
    let mut fields = ipv6("11", "40", 1);
    fields.extend(udp(1));
    fields.extend([
        fixed(
            "fid-coap-version",
            2,
            1,
            "bi",
            "\"01\"",
            "equal",
            "not-sent",
        ),
        fixed("fid-coap-type", 2, 1, "bi", "null", "ignore", "value-sent"),
        fixed("fid-coap-tkl", 4, 1, "bi", "\"00\"", "equal", "not-sent"),
        fixed("fid-coap-code", 8, 1, "bi", "\"01\"", "equal", "not-sent"),
        fixed("fid-coap-mid", 16, 1, "bi", "null", "ignore", "value-sent"),
    ]);
    fields.push(field(
        "fid-payload",
        r#"{"type":"variable","unit":"bytes"}"#,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    context(&fields.join(","))
}

fn generic_icmp_context() -> RuleContext {
    let mut fields = ipv6("3a", "40", 1);
    fields.extend([
        fixed("fid-icmpv6-type", 8, 1, "bi", "\"80\"", "equal", "not-sent"),
        fixed("fid-icmpv6-code", 8, 1, "bi", "\"00\"", "equal", "not-sent"),
        fixed(
            "fid-icmpv6-checksum",
            16,
            1,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
    ]);
    fields.push(field(
        "fid-payload",
        r#"{"type":"variable","unit":"bytes"}"#,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    context(&fields.join(","))
}

fn generic_error_context(unused_cda: &str, unused_target: &str) -> RuleContext {
    let mut fields = ipv6("3a", "ff", 1);
    fields.extend([
        fixed("fid-icmpv6-type", 8, 1, "bi", "\"01\"", "equal", "not-sent"),
        fixed("fid-icmpv6-code", 8, 1, "bi", "\"04\"", "equal", "not-sent"),
        fixed(
            "fid-icmpv6-checksum",
            16,
            1,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
        fixed(
            "fid-unused",
            32,
            1,
            "bi",
            unused_target,
            "ignore",
            unused_cda,
        ),
    ]);
    fields.extend(ipv6("11", "ff", 2));
    fields.extend(udp(2));
    fields.push(field(
        "fid-payload",
        r#"{"type":"variable","unit":"bytes"}"#,
        2,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    context(&fields.join(","))
}

fn round_trip(context: RuleContext, direction: Direction, position: Position, packet: &[u8]) {
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(direction, packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(position, compressed.bytes())
        .unwrap();
    assert_eq!(restored, packet);
}

#[test]
fn top_level_udp_generic_payload_round_trips() {
    let packet = hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap();
    round_trip(
        generic_udp_context(),
        Direction::Up,
        Position::Core,
        &packet,
    );
}

#[test]
fn top_level_udp_generic_payload_is_bit_exact() {
    let packet = hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap();
    let compressed = Compressor::new(generic_udp_context())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();

    assert_eq!(compressed.bit_len(), 48);
    assert_eq!(compressed.bytes(), b"\x75hello");
}

#[test]
fn fixed_generic_payload_length_must_match_remaining_bytes() {
    let packet = hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap();
    let error = Compressor::new(generic_udp_fixed_payload_context(8))
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap_err();

    assert!(matches!(error, SchcError::NoMatchingRule));
}

#[test]
fn coap_generic_payload_round_trips_with_marker() {
    let packet = hex::decode(
        "60000000000f114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000fcf60\
         4001002aff6869",
    )
    .unwrap();
    round_trip(
        generic_coap_context(),
        Direction::Up,
        Position::Core,
        &packet,
    );
}

#[test]
fn coap_generic_empty_payload_omits_marker() {
    let packet = hex::decode(
        "60000000000c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000c37d0\
         4001002a",
    )
    .unwrap();
    round_trip(
        generic_coap_context(),
        Direction::Up,
        Position::Core,
        &packet,
    );
}

#[test]
fn simple_icmpv6_generic_payload_round_trips() {
    let packet = hex::decode(
        "60000000000c3a4020010db8000000000000000000000001\
         20010db80000000000000000000000028000333e12340001\
         70696e67",
    )
    .unwrap();
    round_trip(
        generic_icmp_context(),
        Direction::Up,
        Position::Core,
        &packet,
    );
}

#[test]
fn error_unused_and_embedded_udp_generic_payload_round_trip() {
    let packet = hex::decode(
        "60000000003a3aff20010db8000000000000000000000002\
         20010db80000000000000000000000010104312400000000\
         60000000000a11ff20010db8000000000000000000000001\
         20010db800000000000000000000000216331633000aff857879",
    )
    .unwrap();
    round_trip(
        generic_error_context("value-sent", "null"),
        Direction::Down,
        Position::Device,
        &packet,
    );
}

#[test]
fn generic_payload_variable_byte_length_supports_extended_prefix() {
    let packet = hex::decode(
        "60000000001c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633001c6dc7\
         3031323334353637383930313233343536373839",
    )
    .unwrap();
    round_trip(
        generic_udp_context(),
        Direction::Up,
        Position::Core,
        &packet,
    );
}

#[test]
fn not_sent_unused_uses_valid_target() {
    let packet = hex::decode(
        "6000000000383aff20010db8000000000000000000000002\
         20010db80000000000000000000000010104312600000000\
         60000000000811ff20010db8000000000000000000000001\
         20010db80000000000000000000000021633163300087803",
    )
    .unwrap();
    round_trip(
        generic_error_context("not-sent", "\"00000000\""),
        Direction::Down,
        Position::Device,
        &packet,
    );
}

#[test]
fn missing_not_sent_unused_target_is_rejected() {
    let fields = fixed("fid-unused", 32, 1, "bi", "null", "ignore", "not-sent");
    let error = RuleContext::from_json_str(
        &format!(r#"{{"rules":[{{"rule_id":1,"rule_id_length":4,"fields":[{fields}]}}]}}"#),
        registry(),
    )
    .unwrap_err();
    assert!(matches!(error, SchcError::InvalidRuleField { .. }));
}

#[test]
fn malformed_scope_and_truncated_error_are_rejected() {
    let mut fields = ipv6("3a", "ff", 1);
    fields.extend([
        fixed("fid-icmpv6-type", 8, 1, "bi", "\"01\"", "equal", "not-sent"),
        fixed("fid-icmpv6-code", 8, 1, "bi", "\"04\"", "equal", "not-sent"),
        fixed(
            "fid-unused",
            32,
            1,
            "bi",
            "\"00000000\"",
            "ignore",
            "not-sent",
        ),
        fixed(
            "fid-udp-dev-port",
            16,
            2,
            "bi",
            "\"1633\"",
            "equal",
            "not-sent",
        ),
    ]);
    let context = context(&fields.join(","));
    let packet = hex::decode(
        "6000000000083aff20010db8000000000000000000000001\
                              20010db80000000000000000000000028000000000000000",
    )
    .unwrap();
    let error = Compressor::new(context)
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap_err();
    assert!(matches!(
        error,
        SchcError::Packet { .. } | SchcError::NoMatchingRule
    ));
}

#[test]
fn independent_sid_fixture_resolves_generic_identities() {
    let registry = SidRegistry::load_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/generic-payload.sid.json"
    ))
    .unwrap();
    assert_eq!(registry.sid("fid-unused").unwrap(), 1700);
    assert_eq!(registry.identifier(1701).unwrap(), "fid-payload");
}

#[test]
fn generic_payload_rejects_bit_length_units() {
    let field = field(
        "fid-payload",
        r#"{"type":"variable","unit":"bits"}"#,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    );
    let error = RuleContext::from_json_str(
        &format!(r#"{{"rules":[{{"rule_id":1,"rule_id_length":4,"fields":[{field}]}}]}}"#),
        registry(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("whole bytes"), "{error}");
}

#[test]
fn generic_field_identities_resolve_to_typed_variants() {
    let context = context(&fixed(
        "fid-payload",
        0,
        1,
        "bi",
        "null",
        "ignore",
        "value-sent",
    ));
    assert_eq!(
        context.rules().rules()[0].fields()[0].field,
        FieldRef::Payload
    );
}
