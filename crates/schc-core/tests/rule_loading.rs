use schc_core::{RuleContext, SchcError, SidRegistry};

#[test]
fn sid_registry_loads_standard_sid_file_shape() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    );
    let registry = SidRegistry::load_path(fixture).unwrap();

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
    let sid_fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    );
    let rule_fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/udp_coap.json"
    );
    let registry = SidRegistry::load_path(sid_fixture).unwrap();
    let json = std::fs::read_to_string(rule_fixture).unwrap();

    let context = RuleContext::from_json_str(&json, registry).unwrap();

    assert_eq!(context.rules().rules().len(), 1);
    assert_eq!(context.rules().rules()[0].id().value(), 3);
    assert_eq!(context.rules().rules()[0].id().bit_len(), 4);
    assert_eq!(context.rules().rules()[0].fields().len(), 15);
}
