//! Compatibility tests for the CORECONF SID file shape.
//!
//! These tests verify that the SID registry can deterministically load the
//! standard CORECONF SID file shape defined for SCHC CORECONF, and
//! that compression-core identities present in that file load into their typed
//! core representations when used in a rule.
//!
//! The fixture mirrors the field layout, namespaces, and `type` value variants
//! of the IETF SCHC SID file (string, array, and object values of the optional
//! `type` field).

use schc_core::{
    Cda, Decompressor, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Position,
    RuleContext, SchcError, SidRegistry,
};

fn ietf_schc_sid_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/core/ietf-schc@2026-05-07.sid"
    )
}

fn sid_value(registry: &SidRegistry, identifier: &str) -> ciborium::value::Value {
    int(i128::from(registry.sid(identifier).unwrap()))
}

/// Loads the IETF SCHC SID file shape and asserts that the registry
/// returns both identifier-to-SID and SID-to-identifier mappings for every
/// supported compression-core identity family: field identity, direction
/// indicator, matching operator, CDA, field length function, and rule nature.
#[test]
fn loads_ietf_schc_sid_file_shape() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();

    for identifier in [
        "fid-ipv6-version",
        "di-bidirectional",
        "mo-equal",
        "cda-not-sent",
        "fl-token-length",
        "nature-compression",
        "nature-fragmentation",
        "cda-appiid",
        "fid-icmpv6-identifier",
    ] {
        let sid = registry.sid(identifier).unwrap();
        assert_eq!(registry.identifier(sid).unwrap(), identifier);
    }
}

/// A JSON rule that uses the IETF SCHC `ICMPv6` identifier field loads into the
/// corresponding typed compression-core field.
#[test]
fn json_rule_loads_ietf_schc_sid_icmpv6_identifier() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-icmpv6-identifier", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#;

    let context = RuleContext::from_json_str(json, registry).unwrap();
    let field = &context.rules().rules()[0].fields()[0];
    assert_eq!(field.field, FieldRef::Icmpv6("fid-icmpv6-identifier"));
    assert_eq!(field.length, FieldLength::FixedBits(16));
    assert_eq!(field.action, Cda::ValueSent);
}

/// A CORECONF CBOR rule that uses the IETF SCHC `ICMPv6` identifier field loads
/// into the corresponding typed compression-core field.
#[test]
fn cbor_rule_loads_ietf_schc_sid_icmpv6_identifier() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    // The canonical field SID resolves to `fid-icmpv6-identifier`.
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(1)),
                (
                    int(23),
                    array(vec![map(vec![
                        (int(1), int(0)),
                        (int(2), sid_value(&registry, "fid-icmpv6-identifier")),
                        (int(5), int(16)),
                        (int(7), sid_value(&registry, "di-bidirectional")),
                        (int(8), int(1)),
                        (int(9), target_list(vec![bytes(&[])])),
                        (int(12), sid_value(&registry, "mo-ignore")),
                        (int(16), sid_value(&registry, "cda-value-sent")),
                    ])]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let context = RuleContext::from_cbor_slice(&cbor, registry).unwrap();
    let field = &context.rules().rules()[0].fields()[0];
    assert_eq!(field.field, FieldRef::Icmpv6("fid-icmpv6-identifier"));
    assert_eq!(field.length, FieldLength::FixedBits(16));
    assert_eq!(field.action, Cda::ValueSent);
}

/// A CORECONF CBOR rule that applies `cda-appiid` to the wrong field must fail
/// with a precise invalid-field diagnostic.
#[test]
fn cbor_rule_rejects_ietf_schc_sid_cda_on_wrong_field() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    // The canonical `cda-appiid` SID is valid only for
    // `fid-ipv6-appiid`, not the IPv6 Version field used by this probe.
    let root = map(vec![(
        int(2574),
        map(vec![(
            int(23),
            array(vec![map(vec![
                (int(1), int(4)),
                (int(2), int(1)),
                (
                    int(23),
                    array(vec![map(vec![
                        (int(1), int(0)),
                        (int(2), sid_value(&registry, "fid-ipv6-version")),
                        (int(5), int(4)),
                        (int(7), sid_value(&registry, "di-bidirectional")),
                        (int(8), int(1)),
                        (int(9), target_list(vec![bytes(&[0x06])])),
                        (int(12), sid_value(&registry, "mo-equal")),
                        (int(16), sid_value(&registry, "cda-appiid")),
                    ])]),
                ),
            ])]),
        )]),
    )]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&root, &mut cbor).unwrap();

    let error = RuleContext::from_cbor_slice(&cbor, registry).unwrap_err();
    let reason = error_reason(&error);
    assert!(
        matches!(&error, SchcError::InvalidRuleField { .. }),
        "wrong CDA/field pairing must be an invalid-field error, got: {error}"
    );
    assert_eq!(
        reason, "cda-appiid is only valid for fid-ipv6-appiid",
        "error must identify the invalid CDA/field pairing"
    );
}

/// Sanity check that the IETF SCHC SID file shape works end-to-end through a JSON
/// rule using only supported identities.
#[test]
fn json_rule_loads_with_ietf_schc_sid_file_supported_identities() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    let json = r#"
    {
      "rules": [{
        "rule_id": 3,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }
        ]
      }]
    }
    "#;

    let context = RuleContext::from_json_str(json, registry).unwrap();
    let rule = &context.rules().rules()[0];
    assert_eq!(rule.fields().len(), 2);
    assert_eq!(rule.fields()[0].field, FieldRef::Ipv6("fid-ipv6-version"));
    assert_eq!(rule.fields()[0].action, Cda::NotSent);
    assert_eq!(rule.fields()[0].matching, MatchingOperator::Equal);
    assert_eq!(rule.fields()[1].field, FieldRef::Udp("fid-udp-length"));
    assert_eq!(rule.fields()[1].length, FieldLength::FixedBits(16));
    assert_eq!(rule.fields()[1].action, Cda::Compute);
    assert_eq!(rule.fields()[1].matching, MatchingOperator::Ignore);
    assert_eq!(rule.fields()[1].direction, DirectionSelector::Bidirectional);
}

/// Asserts that decompressing a rule whose field length references an
/// unsupported field-length function SID produces an error that names the
/// SID and identifies the field-length operation.
#[test]
fn decompress_rejects_unsupported_field_length_function_sid() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    // SID 9999 is not present in the IETF SCHC SID file, so the field-length
    // function is preserved as an unresolved `FunctionSid` at load time and
    // must produce an explicit error at decompression time.
    let json = r#"
    {
      "rules": [{
        "rule_id": 1,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length": { "type": "function-sid", "sid": 9999 }, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" }
        ]
      }]
    }
    "#;
    let context = RuleContext::from_json_str(json, registry).unwrap();
    let decompressor = Decompressor::new(context).unwrap();

    // 0001 = rule ID 1, then zero padding. The not-sent field with a
    // function-sid length triggers length resolution, which must fail.
    let message = decompressor
        .decompress(Position::Core, &[0x10])
        .unwrap_err()
        .to_string();

    assert!(
        message.contains("field-length function"),
        "error must identify the field-length operation, got: {message}"
    );
    assert!(
        message.contains("9999"),
        "error must name the unsupported SID, got: {message}"
    );
}

fn error_reason(error: &SchcError) -> String {
    match error {
        SchcError::InvalidRuleField { reason, .. } | SchcError::InvalidRule { reason, .. } => {
            reason.clone()
        }
        other => other.to_string(),
    }
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

fn int(value: i128) -> ciborium::value::Value {
    ciborium::value::Value::Integer(value.try_into().unwrap())
}
