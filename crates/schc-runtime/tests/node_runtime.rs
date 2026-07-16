use schc_core::{RuleContext, RuleId, SidRegistry};
use schc_runtime::{DeviceId, DeviceProfile, Node, NodeRole, Runtime};

fn sid_registry() -> SidRegistry {
    SidRegistry::load_path(format!(
        "{}/../../fixtures/core/ietf-schc@2026-05-07.sid",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn context() -> RuleContext {
    let fields = r#"
      {"field":"fid-ipv6-version","length_bits":4,"field_position":1,"direction":"bi","target":"06","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-trafficclass","length_bits":8,"field_position":1,"direction":"bi","target":"00","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-flowlabel","length_bits":20,"field_position":1,"direction":"bi","target":"000000","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-payload-length","length_bits":16,"field_position":1,"direction":"bi","target":null,"mo":"ignore","cda":"compute"},
      {"field":"fid-ipv6-nextheader","length_bits":8,"field_position":1,"direction":"bi","target":"11","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-hoplimit","length_bits":8,"field_position":1,"direction":"bi","target":"3f","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-devprefix","length_bits":64,"field_position":1,"direction":"bi","target":"20010db800000000","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-deviid","length_bits":64,"field_position":1,"direction":"bi","target":"0000000000000001","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-appprefix","length_bits":64,"field_position":1,"direction":"bi","target":"20010db800000000","mo":"equal","cda":"not-sent"},
      {"field":"fid-ipv6-appiid","length_bits":64,"field_position":1,"direction":"bi","target":"0000000000000002","mo":"equal","cda":"not-sent"},
      {"field":"fid-udp-dev-port","length_bits":16,"field_position":1,"direction":"bi","target":"1633","mo":"equal","cda":"not-sent"},
      {"field":"fid-udp-app-port","length_bits":16,"field_position":1,"direction":"bi","target":"1633","mo":"equal","cda":"not-sent"},
      {"field":"fid-udp-length","length_bits":16,"field_position":1,"direction":"bi","target":null,"mo":"ignore","cda":"compute"},
      {"field":"fid-udp-checksum","length_bits":16,"field_position":1,"direction":"bi","target":null,"mo":"ignore","cda":"compute"}
    "#;
    let management_fields = fields.replace("\"direction\":\"bi\"", "\"direction\":\"up\"");
    let ordinary_fields = fields
        .replace("\"3f\"", "\"40\"")
        .replace("\"direction\":\"bi\"", "\"direction\":\"down\"");
    let json = format!(
        r#"{{"rules":[
          {{"rule_id":1,"rule_id_length":4,"nature":"management","fields":[{management_fields}]}},
          {{"rule_id":2,"rule_id_length":4,"nature":"compression","fields":[{ordinary_fields}]}}
        ]}}"#
    );
    RuleContext::from_json_str(&json, sid_registry()).unwrap()
}

fn packet() -> Vec<u8> {
    hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap()
}

fn downlink_packet() -> Vec<u8> {
    let mut packet = packet();
    let source = packet[8..24].to_vec();
    let destination = packet[24..40].to_vec();
    packet[8..24].copy_from_slice(&destination);
    packet[24..40].copy_from_slice(&source);
    packet
}

fn node(role: NodeRole, context: RuleContext) -> Node {
    let id = DeviceId::new("local-device").unwrap();
    Node::new(
        Runtime::new(id, context, DeviceProfile::default()).unwrap(),
        role,
    )
}

#[test]
fn node_roles_have_only_their_valid_link_paths() {
    assert_eq!(
        NodeRole::Device.outbound(),
        (
            schc_runtime::Endpoint::Device,
            schc_runtime::PacketFlow::Uplink
        )
    );
    assert_eq!(
        NodeRole::Device.inbound(),
        (
            schc_runtime::Endpoint::Device,
            schc_runtime::PacketFlow::Downlink
        )
    );
    assert_eq!(
        NodeRole::Core.outbound(),
        (
            schc_runtime::Endpoint::Core,
            schc_runtime::PacketFlow::Downlink
        )
    );
    assert_eq!(
        NodeRole::Core.inbound(),
        (
            schc_runtime::Endpoint::Core,
            schc_runtime::PacketFlow::Uplink
        )
    );
}

#[test]
fn two_nodes_route_management_uplink_and_ordinary_downlink_by_rule_id() {
    let context = context();
    let device = node(NodeRole::Device, context.clone());
    let core = node(NodeRole::Core, context);

    let mut management = packet();
    management[7] = 0x3f;
    let management_frame = device.outbound(&management).unwrap();
    assert_eq!(management_frame.rule_id(), RuleId::new(1, 4));
    assert_eq!(management_frame.frame().bit_len() % 8, 4);
    let management_bytes = management_frame.frame().bytes().to_vec();
    let management_result = core.inbound(&management_bytes).unwrap();
    assert_eq!(management_result.rule_id(), RuleId::new(1, 4));
    assert_eq!(management_result.packet(), management.as_slice());

    let ordinary = downlink_packet();
    let ordinary_frame = core.outbound(&ordinary).unwrap();
    assert_eq!(ordinary_frame.rule_id(), RuleId::new(2, 4));
    let ordinary_bytes = ordinary_frame.frame().bytes().to_vec();
    let ordinary_result = device.inbound(&ordinary_bytes).unwrap();
    assert_eq!(ordinary_result.rule_id(), RuleId::new(2, 4));
    assert_eq!(ordinary_result.packet(), ordinary.as_slice());
}

#[test]
fn node_propagates_detailed_core_errors() {
    let core = node(NodeRole::Core, context());
    let error = core.inbound(&[0xff]).unwrap_err();
    assert!(matches!(
        error,
        schc_runtime::RuntimeError::Core(schc_core::SchcError::NoMatchingRule)
    ));
}

#[test]
fn runtime_detailed_results_and_compatibility_wrappers_agree() {
    let id = DeviceId::new("local-device").unwrap();
    let runtime = Runtime::new(id.clone(), context(), DeviceProfile::default()).unwrap();
    let mut management = packet();
    management[7] = 0x3f;
    let detailed = runtime
        .encode_detailed(
            &id,
            schc_runtime::Endpoint::Device,
            schc_runtime::PacketFlow::Uplink,
            &management,
        )
        .unwrap();
    let frame = runtime
        .encode(
            &id,
            schc_runtime::Endpoint::Device,
            schc_runtime::PacketFlow::Uplink,
            &management,
        )
        .unwrap();
    assert_eq!(detailed.rule_id(), RuleId::new(1, 4));
    assert_eq!(detailed.frame(), &frame);
    assert_eq!(
        runtime
            .decode_padded_detailed(
                &id,
                schc_runtime::Endpoint::Core,
                schc_runtime::PacketFlow::Uplink,
                frame.bytes(),
            )
            .unwrap()
            .packet(),
        management.as_slice()
    );
}
