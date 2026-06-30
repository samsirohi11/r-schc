use schc_core::rule::LengthUnit;
use schc_core::tree::DecisionTree;
use schc_core::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, RuleContext, SchcError,
    SidRegistry, TargetValue,
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
        (int(3), int(field_sid)),
        (int(4), length),
        (int(6), int(direction_sid)),
        (int(7), int(1)),
        (int(8), target_list(vec![target])),
        (int(11), int(matching_sid)),
        (int(15), int(cda_sid)),
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
