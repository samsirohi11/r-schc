use schc_core::{
    bit::BitWriter, Compressor, Decompressor, Direction, ExternalValueProvider, FieldRef, Position,
    Result, RuleContext, SchcError, SidRegistry,
};
use std::sync::{Arc, Mutex};

fn registry() -> SidRegistry {
    SidRegistry::load_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/core/ietf-schc@2026-05-07.sid"
    ))
    .unwrap()
}

fn context_with_registry(
    rule_id: u64,
    fields: &[String],
    sid_registry: SidRegistry,
) -> RuleContext {
    let json = format!(
        r#"{{"rules":[{{"rule_id":{rule_id},"rule_id_length":4,"fields":[{}]}}]}}"#,
        fields.join(",")
    );
    RuleContext::from_json_str(&json, sid_registry).unwrap()
}

fn context(rule_id: u64, fields: &[String]) -> RuleContext {
    context_with_registry(rule_id, fields, registry())
}

fn external_registry() -> SidRegistry {
    registry()
}

fn icmp_context(rule_id: u64, fields: &[String]) -> RuleContext {
    context_with_registry(rule_id, fields, registry())
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

fn variable(
    name: &str,
    position: usize,
    direction: &str,
    unit: &str,
    target: &str,
    mo: &str,
    cda: &str,
) -> String {
    format!(
        r#"{{"field":"{name}","length":{{"type":"variable","unit":"{unit}"}},"field_position":{position},"direction":"{direction}","target":{target},"mo":"{mo}","cda":"{cda}"}}"#
    )
}

fn ipv6_udp_fields() -> Vec<String> {
    let mut fields = ipv6_fields();
    fields.extend(udp_fields());
    fields
}

fn ipv6_fields() -> Vec<String> {
    vec![
        fixed(
            "fid-ipv6-version",
            4,
            1,
            "bi",
            "\"06\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-trafficclass",
            8,
            1,
            "bi",
            "\"00\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-flowlabel",
            20,
            1,
            "bi",
            "\"000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-payload-length",
            16,
            1,
            "bi",
            "null",
            "ignore",
            "compute",
        ),
        fixed(
            "fid-ipv6-nextheader",
            8,
            1,
            "bi",
            "\"11\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-hoplimit",
            8,
            1,
            "bi",
            "\"40\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-devprefix",
            64,
            1,
            "bi",
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-deviid",
            64,
            1,
            "bi",
            "\"0000000000000001\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-appprefix",
            64,
            1,
            "bi",
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-ipv6-appiid",
            64,
            1,
            "bi",
            "\"0000000000000002\"",
            "equal",
            "not-sent",
        ),
    ]
}

fn udp_fields() -> Vec<String> {
    vec![
        fixed(
            "fid-udp-dev-port",
            16,
            1,
            "up",
            "\"1633\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-udp-app-port",
            16,
            1,
            "up",
            "\"1633\"",
            "equal",
            "not-sent",
        ),
        fixed("fid-udp-length", 16, 1, "bi", "null", "ignore", "compute"),
        fixed("fid-udp-checksum", 16, 1, "bi", "null", "ignore", "compute"),
    ]
}

fn ipv6_icmp_fields() -> Vec<String> {
    let mut fields = ipv6_udp_fields();
    fields.truncate(10);
    fields[4] = fixed(
        "fid-ipv6-nextheader",
        8,
        1,
        "bi",
        "\"3a\"",
        "equal",
        "not-sent",
    );
    fields
}

fn udp_payload_packet() -> Vec<u8> {
    hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap()
}

fn repeated_coap_packet() -> Vec<u8> {
    hex::decode(
        "600000000019114020010db8000000000000000000000001\
         20010db8000000000000000000000002163316330019e4fc\
         4001002ab474656d70026373ff32312e35",
    )
    .unwrap()
}

fn mixed_option_number_coap_packet() -> Vec<u8> {
    hex::decode(
        "60000000001b114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633001be380\
         4001002a51786474656d70026373ff32312e35",
    )
    .unwrap()
}

fn coap_fields() -> Vec<String> {
    vec![
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
    ]
}

fn external_iid_context(rule_id: u64) -> RuleContext {
    let mut fields = ipv6_udp_fields();
    fields[7] = fixed(
        "fid-ipv6-deviid",
        64,
        1,
        "bi",
        "\"0000000000000001\"",
        "equal",
        "deviid",
    );
    fields[9] = fixed(
        "fid-ipv6-appiid",
        64,
        1,
        "bi",
        "\"0000000000000002\"",
        "equal",
        "appiid",
    );
    context_with_registry(rule_id, &fields, external_registry())
}

type ProviderCalls = Arc<Mutex<Vec<(FieldRef, Direction, usize)>>>;
type ProviderHandle = Arc<RecordingProvider>;

#[derive(Debug)]
struct RecordingProvider {
    device: Vec<u8>,
    application: Vec<u8>,
    calls: Arc<Mutex<Vec<(FieldRef, Direction, usize)>>>,
}

impl ExternalValueProvider for RecordingProvider {
    fn value(&self, field: &FieldRef, direction: Direction, bit_len: usize) -> Result<Vec<u8>> {
        self.calls
            .lock()
            .expect("recording provider mutex is not poisoned")
            .push((field.clone(), direction, bit_len));
        Ok(match field {
            FieldRef::Ipv6("fid-ipv6-deviid") => self.device.clone(),
            FieldRef::Ipv6("fid-ipv6-appiid") => self.application.clone(),
            _ => Vec::new(),
        })
    }
}

fn provider(device: &[u8], application: &[u8]) -> (ProviderHandle, ProviderCalls) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = Arc::new(RecordingProvider {
        device: device.to_vec(),
        application: application.to_vec(),
        calls: Arc::clone(&calls),
    });
    (provider, calls)
}

fn lsb_context(unit: &str) -> RuleContext {
    let mut fields = ipv6_udp_fields();
    fields.push(variable(
        "fid-payload",
        1,
        "bi",
        unit,
        "\"6162636465666768696a6b6c6d6e6f\"",
        "msb(8)",
        "lsb",
    ));
    context(if unit == "bytes" { 8 } else { 9 }, &fields)
}

fn lsb_packet() -> Vec<u8> {
    hex::decode(
        "600000000017114020010db8000000000000000000000001\
         20010db8000000000000000000000002163316330017350a\
         6162636465666768696a6b6c6d6e6f",
    )
    .unwrap()
}

fn icmp_base_fields(message_type: &str) -> Vec<String> {
    let mut fields = ipv6_icmp_fields();
    fields.extend([
        fixed(
            "fid-icmpv6-type",
            8,
            1,
            "bi",
            &format!("\"{message_type}\""),
            "equal",
            "not-sent",
        ),
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
    fields
}

fn echo_fields() -> Vec<String> {
    let mut fields = icmp_base_fields("80");
    fields.extend([
        fixed(
            "fid-icmpv6-identifier",
            16,
            1,
            "bi",
            "\"1234\"",
            "equal",
            "not-sent",
        ),
        fixed(
            "fid-icmpv6-sequence",
            16,
            1,
            "bi",
            "\"0001\"",
            "equal",
            "not-sent",
        ),
    ]);
    fields.push(variable(
        "fid-icmpv6-payload",
        1,
        "bi",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    fields
}

fn icmp_error_fields(message_type: &str, field: &str, target: &str) -> Vec<String> {
    let mut fields = icmp_base_fields(message_type);
    fields.push(fixed(field, 32, 1, "bi", target, "equal", "not-sent"));
    fields.push(variable(
        "fid-payload",
        1,
        "bi",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    fields
}

fn icmp_header_only_error_fields(message_type: &str, field: &str, target: &str) -> Vec<String> {
    let mut fields = icmp_base_fields(message_type);
    fields.push(fixed(field, 32, 1, "bi", target, "equal", "not-sent"));
    fields
}

fn echo_packet() -> Vec<u8> {
    hex::decode(
        "60000000000c3a4020010db8000000000000000000000001\
         20010db80000000000000000000000028000333e12340001\
         70696e67",
    )
    .unwrap()
}

fn packet_too_big_packet() -> Vec<u8> {
    hex::decode(
        "6000000000303a4020010db8000000000000000000000001\
         20010db80000000000000000000000020200a66a00000500\
         6000000000003b4020010db8000000000000000000000001\
         20010db8000000000000000000000002",
    )
    .unwrap()
}

fn embedded_fixed(name: &str, bits: usize, target: &str, mo: &str, cda: &str) -> String {
    fixed(name, bits, 2, "bi", target, mo, cda)
}

fn embedded_external_context() -> RuleContext {
    let mut fields = icmp_base_fields("01");
    fields[5] = fixed(
        "fid-ipv6-hoplimit",
        8,
        1,
        "bi",
        "\"ff\"",
        "equal",
        "not-sent",
    );
    fields[11] = fixed("fid-icmpv6-code", 8, 1, "bi", "\"04\"", "equal", "not-sent");
    fields.push(fixed(
        "fid-unused",
        32,
        1,
        "bi",
        "\"00000000\"",
        "equal",
        "not-sent",
    ));
    fields.extend([
        embedded_fixed("fid-ipv6-version", 4, "\"06\"", "equal", "not-sent"),
        embedded_fixed("fid-ipv6-trafficclass", 8, "\"00\"", "equal", "not-sent"),
        embedded_fixed("fid-ipv6-flowlabel", 20, "\"000000\"", "equal", "not-sent"),
        embedded_fixed("fid-ipv6-payload-length", 16, "null", "ignore", "compute"),
        embedded_fixed("fid-ipv6-nextheader", 8, "\"11\"", "equal", "not-sent"),
        embedded_fixed("fid-ipv6-hoplimit", 8, "\"ff\"", "equal", "not-sent"),
        embedded_fixed(
            "fid-ipv6-devprefix",
            64,
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        embedded_fixed(
            "fid-ipv6-deviid",
            64,
            "\"0000000000000001\"",
            "equal",
            "deviid",
        ),
        embedded_fixed(
            "fid-ipv6-appprefix",
            64,
            "\"20010db800000000\"",
            "equal",
            "not-sent",
        ),
        embedded_fixed(
            "fid-ipv6-appiid",
            64,
            "\"0000000000000002\"",
            "equal",
            "appiid",
        ),
        embedded_fixed("fid-udp-dev-port", 16, "\"1633\"", "equal", "not-sent"),
        embedded_fixed("fid-udp-app-port", 16, "\"1633\"", "equal", "not-sent"),
        embedded_fixed("fid-udp-length", 16, "null", "ignore", "compute"),
        embedded_fixed("fid-udp-checksum", 16, "null", "ignore", "compute"),
    ]);
    context_with_registry(12, &fields, external_registry())
}

fn embedded_external_packet() -> Vec<u8> {
    hex::decode(
        "6000000000383aff20010db8000000000000000000000002\
         20010db80000000000000000000000010104312600000000\
         60000000000811ff20010db8000000000000000000000001\
         20010db80000000000000000000000021633163300087803",
    )
    .unwrap()
}

fn parameter_problem_packet() -> Vec<u8> {
    hex::decode(
        "6000000000303a4020010db8000000000000000000000001\
         20010db80000000000000000000000020400a95200000018\
         6000000000003b4020010db8000000000000000000000001\
         20010db8000000000000000000000002",
    )
    .unwrap()
}

#[test]
fn external_iid_provider_reconstructs_both_64_bit_iids() {
    let packet = udp_payload_packet();
    let context = external_iid_context(13);
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let (provider, calls) = provider(
        &hex::decode("0000000000000001").unwrap(),
        &hex::decode("0000000000000002").unwrap(),
    );
    let restored = Decompressor::with_external_value_provider(context, provider)
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap();

    assert_eq!(restored, packet);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|(_, _, bit_len)| *bit_len == 64));
}

#[test]
fn external_iid_provider_is_required_and_validates_width() {
    let packet = udp_payload_packet();
    let context = external_iid_context(14);
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let missing = Decompressor::new(context.clone())
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap_err();
    assert_eq!(
        missing.to_string(),
        "invalid residue: external IID CDA requires an ExternalValueProvider"
    );

    let (provider, _) = provider(
        &hex::decode("00000000000001").unwrap(),
        &hex::decode("0000000000000002").unwrap(),
    );
    let truncated = Decompressor::with_external_value_provider(context, provider)
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap_err();
    assert!(truncated
        .to_string()
        .contains("expected 8 bytes for 64 bits"));
}

#[test]
fn external_cda_is_restricted_to_its_matching_iid_field() {
    let field = fixed(
        "fid-ipv6-appiid",
        64,
        1,
        "bi",
        "\"0000000000000002\"",
        "equal",
        "deviid",
    );
    let json = format!(r#"{{"rules":[{{"rule_id":15,"rule_id_length":4,"fields":[{field}]}}]}}"#);
    let error = RuleContext::from_json_str(&json, external_registry()).unwrap_err();
    assert!(error
        .to_string()
        .contains("cda-deviid is only valid for fid-ipv6-deviid"));
}

#[test]
fn embedded_external_iid_lookups_use_reversed_inner_direction() {
    let packet = embedded_external_packet();
    let context = embedded_external_context();
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Down, &packet)
        .unwrap();
    let (provider, calls) = provider(
        &hex::decode("0000000000000001").unwrap(),
        &hex::decode("0000000000000002").unwrap(),
    );
    let restored = Decompressor::with_external_value_provider(context, provider)
        .unwrap()
        .decompress_with_bit_len(Position::Device, compressed.bytes(), compressed.bit_len())
        .unwrap();

    assert_eq!(restored, packet);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .all(|(_, direction, _)| *direction == Direction::Up));
}

#[test]
fn icmpv6_echo_fields_leave_only_data_in_payload() {
    let packet = echo_packet();
    let context = icmp_context(7, &echo_fields());
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
fn icmpv6_packet_too_big_reconstructs_mtu() {
    let packet = packet_too_big_packet();
    let context = icmp_context(
        8,
        &icmp_error_fields("02", "fid-icmpv6-mtu", "\"00000500\""),
    );
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
fn icmpv6_header_only_error_carries_unread_embedded_suffix() {
    let packet = packet_too_big_packet();
    let context = icmp_context(
        10,
        &icmp_header_only_error_fields("02", "fid-icmpv6-mtu", "\"00000500\""),
    );
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    assert_eq!(compressed.bit_len(), 4 + (packet.len() - 48) * 8);
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap();
    assert_eq!(restored, packet);
}

#[test]
fn icmpv6_header_only_error_rejects_malformed_embedded_suffix() {
    let packet = packet_too_big_packet();
    let context = icmp_context(
        10,
        &icmp_header_only_error_fields("02", "fid-icmpv6-mtu", "\"00000500\""),
    );
    Compressor::new(context)
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let mut malformed_suffix = packet[48..].to_vec();
    malformed_suffix[4..6].copy_from_slice(&1_u16.to_be_bytes());
    let mut malformed = BitWriter::new();
    malformed.write_bits(10, 4).unwrap();
    for byte in malformed_suffix {
        malformed.write_bits(u64::from(byte), 8).unwrap();
    }

    let error = Decompressor::new(icmp_context(
        10,
        &icmp_header_only_error_fields("02", "fid-icmpv6-mtu", "\"00000500\""),
    ))
    .unwrap()
    .decompress_with_bit_len(Position::Core, &malformed.to_vec(), malformed.bit_len())
    .unwrap_err();
    assert!(matches!(
        error,
        SchcError::Packet {
            protocol: "IPv6",
            reason
        } if reason == "payload length exceeds available bytes"
    ));
}

#[test]
fn icmpv6_parameter_problem_reconstructs_pointer() {
    let packet = parameter_problem_packet();
    let context = icmp_context(
        9,
        &icmp_error_fields("04", "fid-icmpv6-pointer", "\"00000018\""),
    );
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
fn mixed_direction_entries_skip_inactive_entry_and_continue() {
    let mut fields = ipv6_udp_fields();
    fields.push(variable(
        "fid-payload",
        1,
        "down",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    fields.push(variable(
        "fid-payload",
        1,
        "up",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    let context = context(1, &fields);
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
fn byte_slice_rejects_header_only_udp_suffix() {
    let packet = udp_payload_packet();
    let context = context(3, &ipv6_udp_fields());
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let decompressor = Decompressor::new(context).unwrap();

    let exact = decompressor
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap();
    assert_eq!(exact, packet);

    let error = decompressor
        .decompress(Position::Core, compressed.bytes())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid residue: unread packet suffix requires decompress_with_bit_len for exact bit length"
    );
}

#[test]
fn malformed_coap_sibling_does_not_hide_valid_udp_candidate() {
    let mut malformed_coap = vec![fixed(
        "fid-ipv6-version",
        4,
        1,
        "bi",
        "\"06\"",
        "equal",
        "not-sent",
    )];
    malformed_coap.push(fixed(
        "fid-coap-version",
        2,
        1,
        "bi",
        "\"01\"",
        "equal",
        "not-sent",
    ));

    let mut valid_udp = ipv6_udp_fields();
    valid_udp.push(variable(
        "fid-payload",
        1,
        "up",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    let malformed_context = context(2, &malformed_coap);
    let valid_context_json = format!(
        r#"{{"rules":[{{"rule_id":2,"rule_id_length":4,"fields":[{}]}},{{"rule_id":3,"rule_id_length":4,"fields":[{}]}}]}}"#,
        malformed_coap.join(","),
        valid_udp.join(",")
    );
    let context = RuleContext::from_json_str(&valid_context_json, registry()).unwrap();
    let packet = udp_payload_packet();
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();

    assert_eq!(compressed.bytes()[0] >> 4, 3);
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, compressed.bytes())
        .unwrap();
    assert_eq!(restored, packet);

    // Keep the malformed branch itself exercised as a sibling candidate rather
    // than relying on a no-compression fallback to mask it.
    let malformed_only = Compressor::new(malformed_context).unwrap();
    assert!(matches!(
        malformed_only.compress(Direction::Up, &packet),
        Err(SchcError::NoMatchingRule | SchcError::Packet { .. })
    ));
}

fn assert_missing_outer_occurrence_rejected() {
    let fields = vec![fixed(
        "fid-ipv6-version",
        4,
        2,
        "bi",
        "\"06\"",
        "equal",
        "not-sent",
    )];
    let context = context(4, &fields);
    let packet = udp_payload_packet();
    assert!(matches!(
        Compressor::new(context.clone())
            .unwrap()
            .compress(Direction::Up, &packet),
        Err(SchcError::NoMatchingRule)
    ));
    assert!(matches!(
        Decompressor::new(context)
            .unwrap()
            .decompress_with_bit_len(Position::Core, &[0x40], 8),
        Err(SchcError::InvalidResidue(_))
    ));
}

fn coap_occurrence_round_trip(rule_id: u64, second_position: usize) {
    let mut fields = ipv6_udp_fields();
    fields.extend(coap_fields());
    fields.push(variable(
        "coap-option(11)",
        1,
        "up",
        "bytes",
        "\"74656d70\"",
        "equal",
        "not-sent",
    ));
    fields.push(variable(
        "coap-option(11)",
        second_position,
        "up",
        "bytes",
        "\"6373\"",
        "equal",
        "not-sent",
    ));
    fields.push(variable(
        "fid-payload",
        1,
        "bi",
        "bytes",
        "null",
        "ignore",
        "value-sent",
    ));
    let packet = repeated_coap_packet();
    let context = context(rule_id, &fields);
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    assert_eq!(
        Decompressor::new(context)
            .unwrap()
            .decompress(Position::Core, compressed.bytes())
            .unwrap(),
        packet
    );
}

#[test]
fn field_positions_reject_missing_outer_occurrence_and_select_coap_occurrences() {
    assert_missing_outer_occurrence_rejected();
    coap_occurrence_round_trip(5, 2);
    coap_occurrence_round_trip(6, 0);
}

#[test]
fn coap_option_positions_filter_by_number_before_occurrence() {
    let packet = mixed_option_number_coap_packet();
    let mut fields = ipv6_udp_fields();
    fields.extend(coap_fields());
    fields.push(variable(
        "coap-option(5)",
        1,
        "up",
        "bytes",
        "\"78\"",
        "equal",
        "not-sent",
    ));
    fields.push(variable(
        "coap-option(11)",
        1,
        "up",
        "bytes",
        "\"74656d70\"",
        "equal",
        "not-sent",
    ));
    fields.push(variable(
        "coap-option(11)",
        2,
        "up",
        "bytes",
        "\"6373\"",
        "equal",
        "not-sent",
    ));
    let context = context(13, &fields);
    let compressed = Compressor::new(context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap();
    assert_eq!(restored, packet);
}

#[test]
fn coap_header_only_suffix_tracks_repeated_option_boundary() {
    let packet = repeated_coap_packet();
    let mut fields = ipv6_udp_fields();
    fields.extend(coap_fields());
    fields.push(variable(
        "coap-option(11)",
        1,
        "up",
        "bytes",
        "\"74656d70\"",
        "equal",
        "not-sent",
    ));
    fields.push(variable(
        "coap-option(11)",
        0,
        "up",
        "bytes",
        "\"6373\"",
        "equal",
        "not-sent",
    ));
    let rule_context = context(15, &fields);
    let compressed = Compressor::new(rule_context.clone())
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap();
    let restored = Decompressor::new(rule_context)
        .unwrap()
        .decompress_with_bit_len(Position::Core, compressed.bytes(), compressed.bit_len())
        .unwrap();
    assert_eq!(restored, packet);

    // A rule that represents only the later occurrence cannot carry a suffix
    // from the middle of the CoAP option sequence without reordering bytes.
    let mut non_contiguous = ipv6_udp_fields();
    non_contiguous.extend(coap_fields());
    non_contiguous.push(variable(
        "coap-option(11)",
        0,
        "up",
        "bytes",
        "\"6373\"",
        "equal",
        "not-sent",
    ));
    let error = Compressor::new(context(14, &non_contiguous))
        .unwrap()
        .compress(Direction::Up, &packet)
        .unwrap_err();
    assert!(matches!(error, SchcError::NoMatchingRule));
}

#[test]
fn variable_byte_and_bit_lsb_prefixes_round_trip() {
    let packet = lsb_packet();
    for unit in ["bytes", "bits"] {
        let context = lsb_context(unit);
        let compressed = Compressor::new(context.clone())
            .unwrap()
            .compress(Direction::Up, &packet)
            .unwrap();
        let restored = Decompressor::new(context)
            .unwrap()
            .decompress(Position::Core, compressed.bytes())
            .unwrap();
        assert_eq!(restored, packet, "LSB {unit} round trip failed");
        assert_eq!(compressed.bit_len(), 4 + 12 + 112);
    }
}
