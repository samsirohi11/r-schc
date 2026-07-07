//! Compatibility tests for the CORECONF SID file shape.
//!
//! These tests verify that the SID registry can deterministically load the
//! standard CORECONF SID file shape defined for SCHC CORECONF, and
//! that compression-core identities present in that file but not supported by
//! the Rust compression core produce explicit, identifiable errors when used in
//! a rule.
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
        "/../../fixtures/sid/ietf-schc.sid.json"
    )
}

/// Loads the IETF SCHC SID file shape and asserts that the registry
/// returns both identifier-to-SID and SID-to-identifier mappings for every
/// supported compression-core identity family: field identity, direction
/// indicator, matching operator, CDA, field length function, and rule nature.
#[test]
fn loads_ietf_schc_sid_file_shape() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();

    // Field identity.
    assert_eq!(registry.sid("fid-ipv6-version").unwrap(), 2860);
    assert_eq!(registry.identifier(2860).unwrap(), "fid-ipv6-version");

    // Direction indicator.
    assert_eq!(registry.sid("di-bidirectional").unwrap(), 2880);
    assert_eq!(registry.identifier(2880).unwrap(), "di-bidirectional");

    // Matching operator.
    assert_eq!(registry.sid("mo-equal").unwrap(), 2900);
    assert_eq!(registry.identifier(2900).unwrap(), "mo-equal");

    // CDA.
    assert_eq!(registry.sid("cda-not-sent").unwrap(), 2920);
    assert_eq!(registry.identifier(2920).unwrap(), "cda-not-sent");

    // Field length function.
    assert_eq!(registry.sid("fl-token-length").unwrap(), 2892);
    assert_eq!(registry.identifier(2892).unwrap(), "fl-token-length");

    // Rule nature (compression).
    assert_eq!(registry.sid("nature-compression").unwrap(), 2940);
    assert_eq!(registry.identifier(2940).unwrap(), "nature-compression");

    // Fragmentation identities are loadable as names in the registry even
    // though fragmentation behavior is intentionally not implemented by the
    // core.
    assert_eq!(registry.sid("nature-fragmentation").unwrap(), 2941);
    assert_eq!(registry.identifier(2941).unwrap(), "nature-fragmentation");

    // Unsupported identities are still present as registry entries so callers
    // can report them precisely when they appear in rules.
    assert_eq!(registry.sid("cda-appiid").unwrap(), 2926);
    assert_eq!(registry.sid("fid-icmpv6-identifier").unwrap(), 2813);
}

/// A JSON rule that uses a field identity present in the IETF SCHC SID file but
/// not mapped by the Rust compression core must fail with an explicit error
/// naming the unsupported field identity and its SID.
#[test]
fn json_rule_rejects_unsupported_ietf_schc_sid_field_identity() {
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

    let error = RuleContext::from_json_str(json, registry).unwrap_err();
    let reason = error_reason(&error);
    assert!(
        reason.contains("fid-icmpv6-identifier"),
        "error must name the unsupported field identifier, got: {reason}"
    );
    assert!(
        reason.contains("2813"),
        "error must name the unsupported field SID, got: {reason}"
    );
}

/// A CORECONF CBOR rule that uses a field-id SID present in the IETF SCHC SID
/// file but not mapped by the Rust compression core must fail with an explicit
/// error naming the unsupported field identity and its SID.
#[test]
fn cbor_rule_rejects_unsupported_ietf_schc_sid_field_identity() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    // Field SID 2813 resolves to `fid-icmpv6-identifier`, which is registered
    // by the IETF SCHC SID file but is not supported by the compression core.
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
                        (int(2), int(2813)),
                        (int(5), int(16)),
                        (int(7), int(2880)),
                        (int(8), int(1)),
                        (int(9), target_list(vec![bytes(&[])])),
                        (int(12), int(2901)),
                        (int(16), int(2921)),
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
        reason.contains("fid-icmpv6-identifier"),
        "error must name the unsupported field identifier, got: {reason}"
    );
    assert!(
        reason.contains("2813"),
        "error must name the unsupported field SID, got: {reason}"
    );
}

/// A CORECONF CBOR rule that uses an unsupported CDA identity from the IETF
/// SCHC SID file must fail with an explicit error naming the unsupported CDA.
/// This asserts that capability reporting for unsupported CDAs remains explicit
/// when the IETF SCHC SID file is used as the registry source.
#[test]
fn cbor_rule_rejects_unsupported_ietf_schc_sid_cda() {
    let registry = SidRegistry::load_path(ietf_schc_sid_fixture()).unwrap();
    // CDA SID 2926 resolves to `cda-appiid`, which is registered by the IETF
    // SCHC SID file but is not supported by the compression core.
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
                        (int(2), int(2860)),
                        (int(5), int(4)),
                        (int(7), int(2880)),
                        (int(8), int(1)),
                        (int(9), target_list(vec![bytes(&[0x06])])),
                        (int(12), int(2900)),
                        (int(16), int(2926)),
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
        reason.contains("cda-appiid"),
        "error must name the unsupported CDA identifier, got: {reason}"
    );
    assert!(
        reason.contains("2926"),
        "error must name the unsupported CDA SID, got: {reason}"
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