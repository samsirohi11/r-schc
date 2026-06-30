use schc_core::tree::DecisionTree;
use schc_core::{RuleContext, SchcError, SidRegistry};

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
    assert_eq!(context.rules().rules()[0].fields().len(), 15);
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
