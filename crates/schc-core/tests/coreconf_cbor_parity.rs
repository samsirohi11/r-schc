//! Tests verifying that the CBOR rule loader accepts the IETF SCHC CORECONF
//! compression field key layout.
//!
//! CORECONF normal compression field keys:
//! 1 = entry-index, 2 = field-id, 5 = field-length, 6 = field-length-value,
//! 7 = direction-indicator, 8 = field-position, optional 9 = target-value,
//! 12 = matching-operator, 13 = matching-operator-value,
//! 16 = comp-decomp-action.

use schc_core::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, RuleContext, SidRegistry,
    TargetValue,
};

fn sid_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/core/ietf-schc@2026-05-07.sid"
    )
}

fn sid_value(identifier: &str) -> i128 {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    i128::from(registry.sid(identifier).unwrap())
}

fn sid_cbor(identifier: &str) -> ciborium::value::Value {
    int(sid_value(identifier))
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
                            field_sid: sid_value("fid-ipv6-version"),
                            length: int(4),
                            length_value: None,
                            direction_sid: sid_value("di-bidirectional"),
                            field_position: 1,
                            target: Some(target_list(vec![bytes(&[0x06])])),
                            matching_sid: sid_value("mo-equal"),
                            matching_value: None,
                            cda_sid: sid_value("cda-not-sent"),
                        }),
                        normal_coreconf_field(CoreconfField {
                            entry_index: 1,
                            field_sid: sid_value("fid-ipv6-hoplimit"),
                            length: int(8),
                            length_value: None,
                            direction_sid: sid_value("di-bidirectional"),
                            field_position: 1,
                            target: Some(target_list(vec![bytes(&[0x40])])),
                            matching_sid: sid_value("mo-msb"),
                            matching_value: Some(target_list(vec![bytes(&[0x04])])),
                            cda_sid: sid_value("cda-lsb"),
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
fn canonical_sid_coreconf_loads_management_nature_with_current_field_keys() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (int(3), sid_cbor("nature-management")),
                (
                    int(23),
                    array(vec![normal_coreconf_field(CoreconfField {
                        entry_index: 0,
                        field_sid: sid_value("fid-ipv6-version"),
                        length: int(4),
                        length_value: None,
                        direction_sid: sid_value("di-bidirectional"),
                        field_position: 1,
                        target: Some(target_list(vec![bytes(&[0x06])])),
                        matching_sid: sid_value("mo-equal"),
                        matching_value: None,
                        cda_sid: sid_value("cda-not-sent"),
                    })]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    assert_eq!(
        context.rules().rules()[0].nature(),
        schc_core::RuleNature::Management
    );
    assert_eq!(
        context
            .find_rule(schc_core::RuleId::new(3, 4))
            .unwrap()
            .id(),
        schc_core::RuleId::new(3, 4)
    );
}

#[test]
fn coreconf_field_length_function_uses_key_5_and_6() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    // Field length is a tagged function SID (fl-token-length) with no
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
                        field_sid: sid_value("fid-coap-token"),
                        length: tagged(45, sid_cbor("fl-token-length")),
                        length_value: None,
                        direction_sid: sid_value("di-bidirectional"),
                        field_position: 1,
                        target: Some(target_list(vec![bytes(&[])])),
                        matching_sid: sid_value("mo-ignore"),
                        matching_value: None,
                        cda_sid: sid_value("cda-value-sent"),
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
fn universal_coreconf_entry_accepts_optional_target_for_ignore_value_sent() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![universal_coreconf_field(UniversalField {
        entry_index: 0,
        option_number: 11,
        target: None,
        matching_sid: sid_value("mo-ignore"),
        matching_value: None,
        cda_sid: sid_value("cda-value-sent"),
        space_sid: sid_value("space-id-coap"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    assert_eq!(
        context.rules().rules()[0].fields()[0].target,
        TargetValue::None
    );
}

#[test]
fn normal_coreconf_entries_accept_optional_targets_when_semantics_allow() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    for (field_sid, length, cda_sid) in [
        (
            sid_value("fid-ipv6-hoplimit"),
            8,
            sid_value("cda-value-sent"),
        ),
        (
            sid_value("fid-ipv6-payload-length"),
            16,
            sid_value("cda-compute"),
        ),
    ] {
        let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
            entry_index: 0,
            field_sid,
            length: int(length),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: None,
            matching_sid: sid_value("mo-ignore"),
            matching_value: None,
            cda_sid,
        })]);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&root, &mut cbor).unwrap();

        let context = RuleContext::from_cbor_slice(&cbor, registry.clone()).unwrap();
        assert_eq!(
            context.rules().rules()[0].fields()[0].target,
            TargetValue::None
        );
    }
}

#[test]
fn coreconf_entry_rejects_missing_target_for_equal_matching() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-version"),
        length: int(4),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: None,
        matching_sid: sid_value("mo-equal"),
        matching_value: None,
        cda_sid: sid_value("cda-not-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(error.to_string().contains("byte target"), "{error}");
}

#[test]
fn coreconf_entry_rejects_missing_target_for_not_sent() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-hoplimit"),
        length: int(8),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: None,
        matching_sid: sid_value("mo-ignore"),
        matching_value: None,
        cda_sid: sid_value("cda-not-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(error.to_string().contains("byte target"), "{error}");
}

#[test]
fn universal_coreconf_entry_rejects_unsupported_space() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![universal_coreconf_field(UniversalField {
        entry_index: 0,
        option_number: 11,
        target: Some(target_list(vec![bytes(&[0xab])])),
        matching_sid: sid_value("mo-equal"),
        matching_value: None,
        cda_sid: sid_value("cda-not-sent"),
        space_sid: sid_value("fid-ipv6-version"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported universal field space"),
        "{error}"
    );
}

#[test]
fn universal_value_is_not_narrowed_during_rule_loading() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![universal_coreconf_field(UniversalField {
        entry_index: 0,
        option_number: i128::from(u32::MAX) + 1,
        target: None,
        matching_sid: sid_value("mo-ignore"),
        matching_value: None,
        cda_sid: sid_value("cda-value-sent"),
        space_sid: sid_value("space-id-coap"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    assert_eq!(
        context.rules().rules()[0].fields()[0].field,
        FieldRef::CoapOption {
            number: u64::from(u32::MAX) + 1
        }
    );
}

#[test]
fn singleton_mapping_target_preserves_mapping_shape() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    for (matching_sid, cda_sid) in [
        (sid_value("mo-match-mapping"), sid_value("cda-value-sent")),
        (sid_value("mo-ignore"), sid_value("cda-mapping-sent")),
    ] {
        let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
            entry_index: 0,
            field_sid: sid_value("fid-ipv6-version"),
            length: int(8),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: Some(target_list(vec![bytes(&[0xab])])),
            matching_sid,
            matching_value: None,
            cda_sid,
        })]);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&root, &mut cbor).unwrap();

        let context = RuleContext::from_cbor_slice(&cbor, registry.clone()).unwrap();
        assert_eq!(
            context.rules().rules()[0].fields()[0].target,
            TargetValue::Mapping(vec![vec![0xab]])
        );
    }
}

#[test]
fn empty_mapping_target_is_rejected() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-version"),
        length: int(8),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: Some(target_list(vec![])),
        matching_sid: sid_value("mo-match-mapping"),
        matching_value: None,
        cda_sid: sid_value("cda-mapping-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(error.to_string().contains("non-empty mapping"), "{error}");
}

#[test]
fn target_mapping_is_ordered_by_explicit_index() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-version"),
        length: int(8),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: Some(target_list_with_indexes(vec![
            (1, bytes(&[0xcd])),
            (0, bytes(&[0xab])),
        ])),
        matching_sid: sid_value("mo-match-mapping"),
        matching_value: None,
        cda_sid: sid_value("cda-mapping-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    assert_eq!(
        context.rules().rules()[0].fields()[0].target,
        TargetValue::Mapping(vec![vec![0xab], vec![0xcd]])
    );
}

#[test]
fn duplicate_target_indexes_are_rejected() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-version"),
        length: int(8),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: Some(target_list_with_indexes(vec![
            (0, bytes(&[0xab])),
            (0, bytes(&[0xcd])),
        ])),
        matching_sid: sid_value("mo-match-mapping"),
        matching_value: None,
        cda_sid: sid_value("cda-mapping-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error.to_string().contains("duplicate target index"),
        "{error}"
    );
}

#[test]
fn non_consecutive_target_indexes_are_rejected() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![normal_coreconf_field(CoreconfField {
        entry_index: 0,
        field_sid: sid_value("fid-ipv6-version"),
        length: int(8),
        length_value: None,
        direction_sid: sid_value("di-bidirectional"),
        field_position: 1,
        target: Some(target_list_with_indexes(vec![(1, bytes(&[0xab]))])),
        matching_sid: sid_value("mo-match-mapping"),
        matching_value: None,
        cda_sid: sid_value("cda-mapping-sent"),
    })]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(error.to_string().contains("consecutive from 0"), "{error}");
}

#[test]
fn cbor_entries_are_normalized_by_explicit_entry_index() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![
        normal_coreconf_field(CoreconfField {
            entry_index: 1,
            field_sid: sid_value("fid-ipv6-hoplimit"),
            length: int(8),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: Some(target_list(vec![bytes(&[0xff])])),
            matching_sid: sid_value("mo-equal"),
            matching_value: None,
            cda_sid: sid_value("cda-not-sent"),
        }),
        normal_coreconf_field(CoreconfField {
            entry_index: 0,
            field_sid: sid_value("fid-ipv6-version"),
            length: int(4),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: Some(target_list(vec![bytes(&[0x06])])),
            matching_sid: sid_value("mo-equal"),
            matching_value: None,
            cda_sid: sid_value("cda-not-sent"),
        }),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    assert_eq!(
        context.rules().rules()[0].fields()[0].field,
        FieldRef::Ipv6("fid-ipv6-version")
    );
    assert_eq!(context.rules().rules()[0].fields()[0].entry_index, 0);
}

#[test]
fn duplicate_field_entry_indexes_are_rejected() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![
        normal_coreconf_field(CoreconfField {
            entry_index: 0,
            field_sid: sid_value("fid-ipv6-version"),
            length: int(4),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: Some(target_list(vec![bytes(&[0x06])])),
            matching_sid: sid_value("mo-equal"),
            matching_value: None,
            cda_sid: sid_value("cda-not-sent"),
        }),
        normal_coreconf_field(CoreconfField {
            entry_index: 0,
            field_sid: sid_value("fid-ipv6-hoplimit"),
            length: int(8),
            length_value: None,
            direction_sid: sid_value("di-bidirectional"),
            field_position: 1,
            target: Some(target_list(vec![bytes(&[0xff])])),
            matching_sid: sid_value("mo-equal"),
            matching_value: None,
            cda_sid: sid_value("cda-not-sent"),
        }),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error.to_string().contains("duplicate field entry index"),
        "{error}"
    );
}

#[test]
fn rejects_entries_with_both_field_identity_forms() {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    let root = rule_with_fields(vec![map(vec![
        (int(1), int(0)),
        (int(2), sid_cbor("fid-ipv6-version")),
        (int(3), sid_cbor("space-id-coap")),
        (int(4), int(11)),
        (int(5), int(4)),
        (int(7), sid_cbor("di-bidirectional")),
        (int(8), int(1)),
        (int(9), target_list(vec![bytes(&[0x06])])),
        (int(12), sid_cbor("mo-equal")),
        (int(16), sid_cbor("cda-not-sent")),
    ])]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("either field-id key 2 or both space-id key 3"),
        "entry with ambiguous field identity should be rejected, got: {error}"
    );
}

#[test]
fn rejects_entries_without_current_field_identity_keys() {
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
                        (int(5), int(4)),
                        (int(7), sid_cbor("di-bidirectional")),
                        (int(8), int(1)),
                        (int(9), target_list(vec![bytes(&[0x06])])),
                        (int(12), sid_cbor("mo-equal")),
                        (int(16), sid_cbor("cda-not-sent")),
                    ])]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("either field-id key 2 or both space-id key 3"),
        "entry without a field identity should be rejected, got: {error}"
    );
}

struct CoreconfField {
    entry_index: i128,
    field_sid: i128,
    length: ciborium::value::Value,
    length_value: Option<ciborium::value::Value>,
    direction_sid: i128,
    field_position: i128,
    target: Option<ciborium::value::Value>,
    matching_sid: i128,
    matching_value: Option<ciborium::value::Value>,
    cda_sid: i128,
}

struct UniversalField {
    entry_index: i128,
    option_number: i128,
    target: Option<ciborium::value::Value>,
    matching_sid: i128,
    matching_value: Option<ciborium::value::Value>,
    cda_sid: i128,
    space_sid: i128,
}

fn rule_with_fields(fields: Vec<ciborium::value::Value>) -> ciborium::value::Value {
    map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(3)),
                (int(23), array(fields)),
            ])]),
        )]),
    )])
}

fn universal_coreconf_field(field: UniversalField) -> ciborium::value::Value {
    let mut entries = vec![
        (int(1), int(field.entry_index)),
        (int(3), int(field.space_sid)),
        (int(4), int(field.option_number)),
        (int(5), int(8)),
        (int(7), sid_cbor("di-bidirectional")),
        (int(8), int(1)),
        (int(12), int(field.matching_sid)),
        (int(16), int(field.cda_sid)),
    ];
    if let Some(target) = field.target {
        entries.push((int(9), target));
    }
    if let Some(matching_value) = field.matching_value {
        entries.push((int(13), matching_value));
    }
    map(entries)
}

fn normal_coreconf_field(field: CoreconfField) -> ciborium::value::Value {
    let mut entries = vec![
        (int(1), int(field.entry_index)),
        (int(2), int(field.field_sid)),
        (int(5), field.length),
        (int(7), int(field.direction_sid)),
        (int(8), int(field.field_position)),
        (int(12), int(field.matching_sid)),
        (int(16), int(field.cda_sid)),
    ];
    if let Some(length_value) = field.length_value {
        entries.push((int(6), length_value));
    }
    if let Some(target) = field.target {
        entries.push((int(9), target));
    }
    if let Some(matching_value) = field.matching_value {
        entries.push((int(13), matching_value));
    }
    map(entries)
}

fn target_list(values: Vec<ciborium::value::Value>) -> ciborium::value::Value {
    target_list_with_indexes(values.into_iter().enumerate().collect())
}

fn target_list_with_indexes(
    values: Vec<(usize, ciborium::value::Value)>,
) -> ciborium::value::Value {
    array(
        values
            .into_iter()
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
