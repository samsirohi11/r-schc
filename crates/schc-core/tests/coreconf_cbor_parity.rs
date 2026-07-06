//! Tests verifying that the CBOR rule loader accepts the IETF SCHC CORECONF
//! compression field key layout.
//!
//! CORECONF normal compression field keys:
//! 1 = entry-index, 2 = field-id, 5 = field-length, 6 = field-length-value,
//! 7 = direction-indicator, 8 = field-position, 9 = target-value,
//! 12 = matching-operator, 13 = matching-operator-value,
//! 16 = comp-decomp-action.

use schc_core::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, RuleContext, SidRegistry,
    TargetValue,
};

fn sid_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    )
}

/// Builds a minimal CORECONF CBOR rule with one compression rule and two
/// fields using the IETF SCHC CORECONF field key layout.
/// The first field uses `mo-equal` with `cda-not-sent`.
/// The second uses `mo-msb` with a matching-operator parameter at key 13 and `cda-lsb`.
fn coreconf_rule() -> ciborium::value::Value {
    map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (
                    int(23),
                    array(vec![
                        normal_coreconf_field(CoreconfField {
                            entry_index: 0,
                            field_sid: 1000,
                            length: int(4),
                            length_value: None,
                            direction_sid: 4000,
                            field_position: 1,
                            target: target_list(vec![bytes(&[0x06])]),
                            matching_sid: 2000,
                            matching_value: None,
                            cda_sid: 3000,
                        }),
                        normal_coreconf_field(CoreconfField {
                            entry_index: 1,
                            field_sid: 1005,
                            length: int(8),
                            length_value: None,
                            direction_sid: 4000,
                            field_position: 1,
                            target: target_list(vec![bytes(&[0x40])]),
                            matching_sid: 2002,
                            matching_value: Some(target_list(vec![bytes(&[0x04])])),
                            cda_sid: 3003,
                        }),
                    ]),
                ),
            ])]),
        )]),
    )])
}

#[test]
fn loads_ietf_schc_coreconf_field_key_layout() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = coreconf_rule();
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();

    assert_eq!(context.rules().rules().len(), 1);
    let rule = &context.rules().rules()[0];
    assert_eq!(rule.id().value(), 3);
    assert_eq!(rule.id().bit_len(), 4);
    assert_eq!(rule.fields().len(), 2);

    let first = &rule.fields()[0];
    assert_eq!(first.field, FieldRef::Ipv6("fid-ipv6-version"));
    assert_eq!(first.entry_index, 0);
    assert_eq!(first.length, FieldLength::FixedBits(4));
    assert_eq!(first.direction, DirectionSelector::Bidirectional);
    assert_eq!(first.field_position, 1);
    assert_eq!(first.target, TargetValue::Bytes(vec![0x06]));
    assert_eq!(first.matching, MatchingOperator::Equal);
    assert_eq!(first.action, Cda::NotSent);

    let second = &rule.fields()[1];
    assert_eq!(second.field, FieldRef::Ipv6("fid-ipv6-hoplimit"));
    assert_eq!(second.entry_index, 1);
    assert_eq!(second.length, FieldLength::FixedBits(8));
    assert_eq!(second.direction, DirectionSelector::Bidirectional);
    assert_eq!(second.field_position, 1);
    assert_eq!(second.target, TargetValue::Bytes(vec![0x40]));
    assert_eq!(second.matching, MatchingOperator::Msb(4));
    assert_eq!(second.action, Cda::Lsb);
}

#[test]
fn coreconf_field_length_function_uses_key_5_and_6() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    // Field length is a tagged function SID (fl-token-length = 5002) with no
    // field-length-value.
    // This verifies that key 5 carries the length and key 6 is the optional length-value.
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (
                    int(23),
                    array(vec![normal_coreconf_field(CoreconfField {
                        entry_index: 0,
                        field_sid: 1205,
                        length: tagged(45, int(5002)),
                        length_value: None,
                        direction_sid: 4000,
                        field_position: 1,
                        target: target_list(vec![bytes(&[])]),
                        matching_sid: 2001,
                        matching_value: None,
                        cda_sid: 3001,
                    })]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    let field = &context.rules().rules()[0].fields()[0];

    assert_eq!(field.field, FieldRef::Coap("fid-coap-token"));
    assert_eq!(field.length, FieldLength::TokenLength);
}

#[test]
fn rejects_non_coreconf_normal_field_key_layout() {
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
                        (int(1), int(0)),
                        (int(3), int(1000)),
                        (int(4), int(4)),
                        (int(6), int(4000)),
                        (int(7), int(1)),
                        (int(8), target_list(vec![bytes(&[0x06])])),
                        (int(11), int(2000)),
                        (int(15), int(3000)),
                    ])]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error.to_string().contains("key 2"),
        "non-CORECONF field key layout should be rejected with a missing field-id key error, got: {error}"
    );
}

struct CoreconfField {
    entry_index: i128,
    field_sid: i128,
    length: ciborium::value::Value,
    length_value: Option<ciborium::value::Value>,
    direction_sid: i128,
    field_position: i128,
    target: ciborium::value::Value,
    matching_sid: i128,
    matching_value: Option<ciborium::value::Value>,
    cda_sid: i128,
}

fn normal_coreconf_field(field: CoreconfField) -> ciborium::value::Value {
    let mut entries = vec![
        (int(1), int(field.entry_index)),
        (int(2), int(field.field_sid)),
        (int(5), field.length),
        (int(7), int(field.direction_sid)),
        (int(8), int(field.field_position)),
        (int(9), field.target),
        (int(12), int(field.matching_sid)),
        (int(16), int(field.cda_sid)),
    ];
    if let Some(length_value) = field.length_value {
        entries.push((int(6), length_value));
    }
    if let Some(matching_value) = field.matching_value {
        entries.push((int(13), matching_value));
    }
    map(entries)
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
