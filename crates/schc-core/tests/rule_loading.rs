use schc_core::rule::LengthUnit;
use schc_core::tree::DecisionTree;
use schc_core::{
    Cda, Decompressor, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Position,
    RuleContext, RuleNature, SchcError, SidRegistry, TargetValue,
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

fn m2m_rule_fixture() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/rules/m2m.json")
}

#[test]
fn sid_registry_loads_standard_sid_file_shape() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();

    assert_eq!(registry.sid("fid-ipv6-version").unwrap(), 1000);
    assert_eq!(registry.identifier(3001).unwrap(), "cda-value-sent");
}

#[test]
fn sid_registry_reports_missing_lookup_entries() {
    let registry = SidRegistry::default();

    assert!(matches!(
        registry.sid("missing"),
        Err(SchcError::MissingSidIdentifier { identifier }) if identifier == "missing"
    ));
    assert!(matches!(
        registry.identifier(42),
        Err(SchcError::UnknownSid { sid }) if sid == 42
    ));
}

#[test]
fn json_rules_load_into_typed_context() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(rule_fixture()).unwrap();

    let context = RuleContext::from_json_str(&json, registry).unwrap();

    assert_eq!(context.rules().rules().len(), 1);
    assert_eq!(context.rules().rules()[0].id().value(), 3);
    assert_eq!(context.rules().rules()[0].id().bit_len(), 4);
    assert_eq!(context.rules().rules()[0].fields().len(), 19);
}

#[test]
fn m2m_rules_load_in_r_schc_schema() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(m2m_rule_fixture()).unwrap();

    let context = RuleContext::from_json_str(&json, registry).unwrap();
    let rule_ids = context
        .rules()
        .rules()
        .iter()
        .map(|rule| rule.id().value())
        .collect::<Vec<_>>();

    assert_eq!(rule_ids, [0, 1, 2, 3, 4, 5, 10, 11, 12, 13, 15]);
    assert!(context.rules().rules().iter().all(|rule| {
        rule.fields()
            .iter()
            .any(|field| field.action == Cda::Compute)
    }));
}

#[test]
fn json_rules_parse_nature_and_option_number_fields() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 6,
        "rule_id_length": 4,
        "nature": "no-compression",
        "fields": [
          { "field": "coap-option(17)", "length": { "type": "variable", "unit": "bytes" }, "direction": "down", "target": ["8e"], "mo": "match-mapping", "cda": "mapping-sent" },
          { "field": "fid-coap-payload-marker", "length_bits": 0, "direction": "bi", "target": null, "mo": "ignore", "cda": "not-sent" }
        ]
      }]
    }
    "#;

    let context = RuleContext::from_json_str(json, registry).unwrap();
    let rule = &context.rules().rules()[0];

    assert_eq!(rule.nature(), RuleNature::NoCompression);
    assert_eq!(rule.fields()[0].field, FieldRef::CoapOption { number: 17 });
    assert_eq!(rule.fields()[0].direction, DirectionSelector::Down);
    assert_eq!(rule.fields()[1].field, FieldRef::SyntheticCoapMarker);
}

#[test]
fn no_compression_rule_decompresses_to_packet_bytes() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "nature": "no-compression",
        "fields": []
      }]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();

    // The 4-bit rule ID 0001 is followed by a full packet byte (0x20) and
    // four zero padding bits: 0001_0010_0000_0000 = 0x12 0x00.
    let restored = Decompressor::new(context)
        .unwrap()
        .decompress(Position::Core, &[0x12, 0x00])
        .unwrap();

    assert_eq!(restored, [0x20]);
}

#[test]
fn json_rule_rejects_compute_for_non_computable_fields() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }
        ]
      }]
    }
    "#;

    assert!(matches!(
        RuleContext::from_json_str(json, registry),
        Err(SchcError::InvalidRuleField { .. })
    ));
}

#[test]
fn json_rule_rejects_payload_marker_with_residue() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-coap-payload-marker", "length_bits": 0, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#;

    assert!(matches!(
        RuleContext::from_json_str(json, registry),
        Err(SchcError::InvalidRuleField { .. })
    ));
}

#[test]
fn json_rules_load_dynamic_field_lengths_and_positions() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 9,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-coap-tkl", "length": { "type": "fixed", "bits": 4 }, "field_position": 1, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-token", "length": { "type": "token-length" }, "field_position": 1, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-payload", "length": { "type": "variable", "unit": "bytes" }, "field_position": 1, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-option-uri-path", "length": { "type": "from-previous", "entry_index": 2, "unit": "bytes" }, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#;

    let context = RuleContext::from_json_str(json, registry).unwrap();
    let fields = context.rules().rules()[0].fields();

    assert_eq!(fields[0].length, FieldLength::FixedBits(4));
    assert_eq!(fields[0].field_position, 1);
    assert_eq!(fields[1].length, FieldLength::TokenLength);
    assert_eq!(fields[2].length, FieldLength::VariableBytes);
    assert_eq!(
        fields[3].length,
        FieldLength::FromPreviousField {
            entry_index: 2,
            unit: LengthUnit::Bytes,
        }
    );
    assert_eq!(fields[3].field_position, 2);
}

#[test]
fn decision_tree_builds_from_rule_context() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = std::fs::read_to_string(rule_fixture()).unwrap();
    let context = RuleContext::from_json_str(&json, registry).unwrap();

    let tree = DecisionTree::build(context.rules()).unwrap();

    assert!(tree.branch_count() > 0);
}

#[test]
fn decision_tree_keeps_branches_with_different_next_fields_separate() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [
        {
          "rule_id": 1,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-nextheader", "length_bits": 8, "direction": "bi", "target": "11", "mo": "equal", "cda": "not-sent" }
          ]
        },
        {
          "rule_id": 2,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "equal", "cda": "not-sent" }
          ]
        }
      ]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();

    let tree = DecisionTree::build(context.rules()).unwrap();

    assert_eq!(tree.nodes()[0].branches.len(), 2);
}

#[test]
fn decision_tree_keeps_uplink_and_downlink_branches_separate() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [
        {
          "rule_id": 1,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" }
          ]
        },
        {
          "rule_id": 2,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "down", "target": "1633", "mo": "equal", "cda": "not-sent" }
          ]
        }
      ]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();

    let tree = DecisionTree::build(context.rules()).unwrap();

    // The shared bidirectional IPv6 version field produces one branch at the
    // root. The UDP device port diverges by direction at depth 1, so the
    // second-level node must carry two distinct branches: one uplink-only and
    // one downlink-only. They must not collapse into a single branch.
    assert_eq!(tree.nodes()[0].branches.len(), 1);
    let next = tree.nodes()[0].branches[0].next;
    let divergence = &tree.nodes()[next];
    assert_eq!(divergence.branches.len(), 2);
    let directions: Vec<DirectionSelector> =
        divergence.branches.iter().map(|b| b.direction).collect();
    assert!(directions.contains(&DirectionSelector::Up));
    assert!(directions.contains(&DirectionSelector::Down));
    assert!(!directions.contains(&DirectionSelector::Bidirectional));
}

#[test]
fn decision_tree_keeps_bi_branch_distinct_from_directional_branches() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [
        {
          "rule_id": 1,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "equal", "cda": "not-sent" }
          ]
        },
        {
          "rule_id": 2,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "up", "target": "40", "mo": "equal", "cda": "not-sent" }
          ]
        },
        {
          "rule_id": 3,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "down", "target": "40", "mo": "equal", "cda": "not-sent" }
          ]
        }
      ]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();

    let tree = DecisionTree::build(context.rules()).unwrap();

    // At the divergence depth the bidirectional, uplink-only, and
    // downlink-only hop-limit branches must remain three distinct branches.
    // The bidirectional branch is shared by both directions, but it must not
    // absorb the directional branches.
    let next = tree.nodes()[0].branches[0].next;
    let divergence = &tree.nodes()[next];
    assert_eq!(divergence.branches.len(), 3);
    let mut directions: Vec<DirectionSelector> =
        divergence.branches.iter().map(|b| b.direction).collect();
    directions.sort_by_key(|d| match d {
        DirectionSelector::Bidirectional => 0,
        DirectionSelector::Up => 1,
        DirectionSelector::Down => 2,
    });
    assert_eq!(
        directions,
        vec![
            DirectionSelector::Bidirectional,
            DirectionSelector::Up,
            DirectionSelector::Down,
        ]
    );
}

#[test]
fn decision_tree_keeps_direction_split_branches_with_different_next_fields_separate() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [
        {
          "rule_id": 1,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "up", "target": "40", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" }
          ]
        },
        {
          "rule_id": 2,
          "rule_id_length": 4,
          "fields": [
            { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "down", "target": "40", "mo": "equal", "cda": "not-sent" },
            { "field": "fid-coap-code", "length_bits": 8, "direction": "down", "target": "02", "mo": "equal", "cda": "not-sent" }
          ]
        }
      ]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();

    let tree = DecisionTree::build(context.rules()).unwrap();

    // Both rules share the bidirectional IPv6 version branch. At depth 1 the
    // hop-limit branches diverge by both direction and next field: rule 1 is
    // uplink-only leading to a UDP port, rule 2 is downlink-only leading to a
    // CoAP code. They must remain two distinct branches, not collapse into a
    // single bidirectional branch.
    let next = tree.nodes()[0].branches[0].next;
    let divergence = &tree.nodes()[next];
    assert_eq!(divergence.branches.len(), 2);
    let directions: Vec<DirectionSelector> =
        divergence.branches.iter().map(|b| b.direction).collect();
    assert!(directions.contains(&DirectionSelector::Up));
    assert!(directions.contains(&DirectionSelector::Down));
    // The uplink branch leads toward a UDP port, the downlink branch toward a
    // CoAP code. Each branch targets a distinct next field.
    for branch in &divergence.branches {
        let leaf = &tree.nodes()[branch.next];
        if branch.direction == DirectionSelector::Up {
            assert_eq!(leaf.branches.len(), 1);
            assert_eq!(leaf.branches[0].parse.field, FieldRef::Udp("fid-udp-dev-port"));
        } else {
            assert_eq!(leaf.branches.len(), 1);
            assert_eq!(leaf.branches[0].parse.field, FieldRef::Coap("fid-coap-code"));
        }
    }
}

#[test]
fn cbor_rules_load_into_typed_context() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (int(3), int(0)),
                (
                    int(23),
                    array(vec![
                        normal_field(0, 1000, 4, 4000, bytes(&[0x06]), 2000, 3000),
                        normal_field(1, 1005, 8, 4000, bytes(&[0x40]), 2001, 3001),
                    ]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();

    assert_eq!(context.rules().rules().len(), 1);
    assert_eq!(context.rules().rules()[0].id().value(), 3);
    assert_eq!(context.rules().rules()[0].id().bit_len(), 4);
    assert_eq!(context.rules().rules()[0].fields().len(), 2);
}

#[test]
fn cbor_rule_nature_uses_coreconf_sid_mapping() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![
                map(vec![
                    (int(1), int(4)),
                    (int(2), int(1)),
                    (int(3), int(2941)),
                    (int(23), array(vec![])),
                ]),
                map(vec![
                    (int(1), int(4)),
                    (int(2), int(2)),
                    (int(3), int(2942)),
                    (int(23), array(vec![])),
                ]),
            ]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();

    assert_eq!(
        context.rules().rules()[0].nature(),
        RuleNature::NoCompression
    );
    assert_eq!(
        context.rules().rules()[1].nature(),
        RuleNature::Fragmentation
    );
}

#[test]
fn cbor_rules_load_universal_option_fields() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (
                    int(23),
                    array(vec![map(vec![
                        (int(-1), int(0)),
                        (int(-5), int(11)),
                        (int(-11), int(8)),
                        (int(-12), int(4000)),
                        (int(-10), int(1)),
                        (int(-3), target_list(vec![bytes(&[0xab])])),
                        (int(-9), int(2000)),
                        (int(-16), int(3000)),
                    ])]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    let field = &context.rules().rules()[0].fields()[0];

    assert_eq!(field.field, FieldRef::CoapOption { number: 11 });
    assert_eq!(field.length, FieldLength::FixedBits(8));
    assert_eq!(field.direction, DirectionSelector::Bidirectional);
    assert_eq!(field.matching, MatchingOperator::Equal);
    assert_eq!(field.action, Cda::NotSent);
    assert_eq!(field.target, TargetValue::Bytes(vec![0xab]));
}

#[test]
fn cbor_rules_preserve_field_length_function_sids() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (
                    int(23),
                    array(vec![normal_field_with_length(
                        0,
                        1205,
                        tagged(45, int(9999)),
                        4000,
                        bytes(&[]),
                        2001,
                        3001,
                    )]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    let field = &context.rules().rules()[0].fields()[0];

    assert_eq!(field.length, FieldLength::FunctionSid(9999));
}

#[test]
fn cbor_rules_resolve_known_field_length_function_sids() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (
                    int(23),
                    array(vec![
                        normal_field_with_length(
                            0,
                            1205,
                            tagged(45, int(5002)),
                            4000,
                            bytes(&[]),
                            2001,
                            3001,
                        ),
                        normal_field_with_length(
                            1,
                            1208,
                            tagged(45, int(5004)),
                            4000,
                            bytes(&[]),
                            2001,
                            3001,
                        ),
                        normal_field_with_length_value(NormalFieldWithLengthValue {
                            entry_index: 2,
                            field_sid: 1207,
                            length: tagged(45, int(5001)),
                            length_value: int(0),
                            direction_sid: 4000,
                            target: bytes(&[]),
                            matching_sid: 2001,
                            cda_sid: 3001,
                        }),
                    ]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    let fields = context.rules().rules()[0].fields();

    assert_eq!(fields[0].length, FieldLength::TokenLength);
    assert_eq!(fields[1].length, FieldLength::VariableBits);
    assert_eq!(
        fields[2].length,
        FieldLength::FromPreviousField {
            entry_index: 0,
            unit: LengthUnit::Bytes,
        }
    );
}

fn normal_field_with_length(
    entry_index: i128,
    field_sid: i128,
    length: ciborium::value::Value,
    direction_sid: i128,
    target: ciborium::value::Value,
    matching_sid: i128,
    cda_sid: i128,
) -> ciborium::value::Value {
    map(vec![
        (int(1), int(entry_index)),
        (int(2), int(field_sid)),
        (int(5), length),
        (int(7), int(direction_sid)),
        (int(8), int(1)),
        (int(9), target_list(vec![target])),
        (int(12), int(matching_sid)),
        (int(16), int(cda_sid)),
    ])
}

struct NormalFieldWithLengthValue {
    entry_index: i128,
    field_sid: i128,
    length: ciborium::value::Value,
    length_value: ciborium::value::Value,
    direction_sid: i128,
    target: ciborium::value::Value,
    matching_sid: i128,
    cda_sid: i128,
}

fn normal_field_with_length_value(field: NormalFieldWithLengthValue) -> ciborium::value::Value {
    map(vec![
        (int(1), int(field.entry_index)),
        (int(2), int(field.field_sid)),
        (int(5), field.length),
        (int(6), field.length_value),
        (int(7), int(field.direction_sid)),
        (int(8), int(1)),
        (int(9), target_list(vec![field.target])),
        (int(12), int(field.matching_sid)),
        (int(16), int(field.cda_sid)),
    ])
}

fn normal_field(
    entry_index: i128,
    field_sid: i128,
    length_bits: i128,
    direction_sid: i128,
    target: ciborium::value::Value,
    matching_sid: i128,
    cda_sid: i128,
) -> ciborium::value::Value {
    normal_field_with_length(
        entry_index,
        field_sid,
        int(length_bits),
        direction_sid,
        target,
        matching_sid,
        cda_sid,
    )
}

fn target_list(values: Vec<ciborium::value::Value>) -> ciborium::value::Value {
    array(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| map(vec![(int(1), int(index as i128)), (int(2), value)]))
            .collect(),
    )
}

fn map(values: Vec<(ciborium::value::Value, ciborium::value::Value)>) -> ciborium::value::Value {
    ciborium::value::Value::Map(values)
}

fn array(values: Vec<ciborium::value::Value>) -> ciborium::value::Value {
    ciborium::value::Value::Array(values)
}

fn bytes(value: &[u8]) -> ciborium::value::Value {
    ciborium::value::Value::Bytes(value.to_vec())
}

fn tagged(tag: u64, value: ciborium::value::Value) -> ciborium::value::Value {
    ciborium::value::Value::Tag(tag, Box::new(value))
}

fn int(value: i128) -> ciborium::value::Value {
    ciborium::value::Value::Integer(value.try_into().unwrap())
}

#[test]
fn json_rule_id_rejects_prefix_collision() {
    let registry = SidRegistry::default();
    // Rule IDs in binary: `1` (1 bit) and `10` (2 bits). The 1-bit ID is a
    // bit-prefix of the 2-bit ID, so decompression could select the wrong
    // rule depending on insertion order.
    let json = r#"
    {
      "rules": [
        { "rule_id": 1, "rule_id_length": 1, "nature": "no-compression", "fields": [] },
        { "rule_id": 2, "rule_id_length": 2, "nature": "no-compression", "fields": [] }
      ]
    }
    "#;

    let error = RuleContext::from_json_str(json, registry).unwrap_err();
    assert!(matches!(
        &error,
        SchcError::AmbiguousRuleIdPrefix {
            first_value: 1,
            first_bits: 1,
            second_value: 2,
            second_bits: 2
        }
    ));
    let message = error.to_string();
    assert!(
        message.contains("ambiguous rule ID prefix"),
        "error must identify the ambiguity, got: {message}"
    );
    assert!(
        message.contains("rule ID 1 (1 bits)"),
        "error must name the prefix rule ID, got: {message}"
    );
    assert!(
        message.contains("rule ID 2 (2 bits)"),
        "error must name the longer rule ID, got: {message}"
    );
}

#[test]
fn json_rule_id_reports_shorter_prefix_first_when_longer_id_appears_first() {
    let registry = SidRegistry::default();
    // Rule IDs in binary: `10` (2 bits) appears before `1` (1 bit). The shorter
    // ID is still the bit-prefix and must be reported first in the error.
    let json = r#"
    {
      "rules": [
        { "rule_id": 2, "rule_id_length": 2, "nature": "no-compression", "fields": [] },
        { "rule_id": 1, "rule_id_length": 1, "nature": "no-compression", "fields": [] }
      ]
    }
    "#;

    let error = RuleContext::from_json_str(json, registry).unwrap_err();
    assert!(matches!(
        &error,
        SchcError::AmbiguousRuleIdPrefix {
            first_value: 1,
            first_bits: 1,
            second_value: 2,
            second_bits: 2
        }
    ));
    let message = error.to_string();
    assert!(
        message.contains("ambiguous rule ID prefix"),
        "error must identify the ambiguity, got: {message}"
    );
    assert!(
        message.contains("rule ID 1 (1 bits)"),
        "error must name the prefix rule ID, got: {message}"
    );
    assert!(
        message.contains("rule ID 2 (2 bits)"),
        "error must name the longer rule ID, got: {message}"
    );
}

#[test]
fn json_rule_id_rejects_exact_duplicate() {
    let registry = SidRegistry::default();
    // Two rules with the same rule ID value and bit length (binary `101`).
    let json = r#"
    {
      "rules": [
        { "rule_id": 5, "rule_id_length": 3, "nature": "no-compression", "fields": [] },
        { "rule_id": 5, "rule_id_length": 3, "nature": "no-compression", "fields": [] }
      ]
    }
    "#;

    let error = RuleContext::from_json_str(json, registry).unwrap_err();
    assert!(matches!(
        &error,
        SchcError::AmbiguousRuleIdPrefix {
            first_value: 5,
            first_bits: 3,
            second_value: 5,
            second_bits: 3
        }
    ));
    let message = error.to_string();
    assert!(
        message.contains("ambiguous rule ID prefix"),
        "error must identify the ambiguity, got: {message}"
    );
    assert!(
        message.contains("rule ID 5 (3 bits)"),
        "error must name the duplicate rule ID, got: {message}"
    );
}

#[test]
fn json_rule_id_accepts_non_prefixing_ids() {
    let registry = SidRegistry::default();
    // Rule IDs in binary: `10` (2 bits), `110` (3 bits), `0` (1 bit). None is a
    // bit-prefix of another (top 2 bits of `110` are `11`, top 1 bit of `10` and
    // `110` is `1` which differs from `0`).
    let json = r#"
    {
      "rules": [
        { "rule_id": 2, "rule_id_length": 2, "nature": "no-compression", "fields": [] },
        { "rule_id": 6, "rule_id_length": 3, "nature": "no-compression", "fields": [] },
        { "rule_id": 0, "rule_id_length": 1, "nature": "no-compression", "fields": [] }
      ]
    }
    "#;

    let context = RuleContext::from_json_str(json, registry).unwrap();
    let ids = context
        .rules()
        .rules()
        .iter()
        .map(|rule| (rule.id().value(), rule.id().bit_len()))
        .collect::<Vec<_>>();
    assert_eq!(ids, [(2, 2), (6, 3), (0, 1)]);
}

#[test]
fn cbor_rule_id_rejects_prefix_collision() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    // CORECONF CBOR rule metadata keys: key 1 = rule ID length, key 2 = rule ID
    // value, key 3 = rule nature, key 23 = entries. Two rules whose IDs collide:
    // binary `1` (1 bit) is a bit-prefix of binary `10` (2 bits).
    let root = map(vec![
        (
            int(2574),
            map(vec![
                (
                    int(23),
                    array(vec![
                        map(vec![
                            (int(1), int(1)),
                            (int(2), int(1)),
                            (int(3), int(2941)),
                            (int(23), array(vec![])),
                        ]),
                        map(vec![
                            (int(1), int(2)),
                            (int(2), int(2)),
                            (int(3), int(2941)),
                            (int(23), array(vec![])),
                        ]),
                    ]),
                ),
            ]),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(matches!(
        &error,
        SchcError::AmbiguousRuleIdPrefix {
            first_value: 1,
            first_bits: 1,
            second_value: 2,
            second_bits: 2
        }
    ));
    let message = error.to_string();
    assert!(
        message.contains("ambiguous rule ID prefix"),
        "error must identify the ambiguity, got: {message}"
    );
    assert!(
        message.contains("rule ID 1 (1 bits)"),
        "error must name the prefix rule ID, got: {message}"
    );
    assert!(
        message.contains("rule ID 2 (2 bits)"),
        "error must name the longer rule ID, got: {message}"
    );
}

#[test]
fn json_rule_rejects_mapping_sent_without_mapping_target() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "mapping-sent" }
        ]
      }]
    }
    "#;

    assert!(matches!(
        RuleContext::from_json_str(json, registry),
        Err(SchcError::InvalidRuleField { .. })
    ));
}

#[test]
fn json_rule_rejects_lsb_without_msb() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "lsb" }
        ]
      }]
    }
    "#;

    assert!(matches!(
        RuleContext::from_json_str(json, registry),
        Err(SchcError::InvalidRuleField { .. })
    ));
}

/// Asserts that an invalid CDA/MO combination error message includes the
/// rule index, entry index, and names the CDA (`mapping-sent`) and the
/// missing requirement (a mapping target).
#[test]
fn field_error_includes_rule_entry_and_cda_name_for_mapping_sent() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "mapping-sent" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(
        message.contains("mapping-sent"),
        "must name the CDA, got: {message}"
    );
    assert!(
        message.contains("mapping target"),
        "must name the missing requirement, got: {message}"
    );
}

/// Asserts that an `lsb`-without-`msb` error message includes the rule index,
/// entry index, and names both the CDA (`lsb`) and the matching operator
/// (`msb`).
#[test]
fn field_error_includes_rule_entry_and_cda_mo_names_for_lsb() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "lsb" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(message.contains("lsb"), "must name the CDA, got: {message}");
    assert!(
        message.contains("msb"),
        "must name the matching operator, got: {message}"
    );
}

/// Asserts that a `compute`-for-non-computable-field error message includes
/// the rule index, entry index, the CDA name (`compute`), and the field
/// identifier.
#[test]
fn field_error_includes_rule_entry_and_field_name_for_compute() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(
        message.contains("compute"),
        "must name the CDA, got: {message}"
    );
    assert!(
        message.contains("fid-ipv6-hoplimit"),
        "must name the field identifier, got: {message}"
    );
}

/// Asserts that a CoAP payload marker misuse error message includes the rule
/// index, entry index, and identifies the marker field and the required
/// CDA/MO combination.
#[test]
fn field_error_includes_rule_entry_and_marker_constraint() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-coap-payload-marker", "length_bits": 0, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(
        message.contains("CoAP payload marker"),
        "must identify the marker field, got: {message}"
    );
    assert!(
        message.contains("not-sent"),
        "must name the required CDA, got: {message}"
    );
    assert!(
        message.contains("ignore"),
        "must name the required matching operator, got: {message}"
    );
}

/// Asserts that an unknown CDA string error message includes the rule index,
/// entry index, and names the unknown CDA value.
#[test]
fn field_error_includes_rule_entry_and_unknown_cda_name() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": null, "mo": "ignore", "cda": "bogus-cda" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(
        message.contains("bogus-cda"),
        "must name the unknown CDA, got: {message}"
    );
}

/// Asserts that an unknown matching operator string error message includes
/// the rule index, entry index, and names the unknown MO value.
#[test]
fn field_error_includes_rule_entry_and_unknown_mo_name() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": null, "mo": "bogus-mo", "cda": "value-sent" }
        ]
      }]
    }
    "#;

    let message = RuleContext::from_json_str(json, registry)
        .unwrap_err()
        .to_string();

    assert!(message.contains("rule=0"), "must name rule index, got: {message}");
    assert!(
        message.contains("entry=0"),
        "must name entry index, got: {message}"
    );
    assert!(
        message.contains("bogus-mo"),
        "must name the unknown MO, got: {message}"
    );
}
