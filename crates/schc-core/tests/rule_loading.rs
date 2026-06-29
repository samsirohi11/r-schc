use schc_core::{SchcError, SidRegistry};

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
