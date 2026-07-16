use schc_core::{RuleContext, SidRegistry};
use schc_runtime::{DeviceId, DeviceProfile, Node, NodeRole, Runtime};

pub fn sid_registry() -> SidRegistry {
    SidRegistry::load_path(format!(
        "{}/../../fixtures/core/ietf-schc@2026-05-07.sid",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

pub fn context() -> RuleContext {
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

pub fn packet() -> Vec<u8> {
    hex::decode(
        "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f",
    )
    .unwrap()
}

pub fn management_packet() -> Vec<u8> {
    let mut packet = packet();
    packet[7] = 0x3f;
    packet
}

pub fn downlink_packet() -> Vec<u8> {
    let mut packet = packet();
    let source = packet[8..24].to_vec();
    let destination = packet[24..40].to_vec();
    packet[8..24].copy_from_slice(&destination);
    packet[24..40].copy_from_slice(&source);
    packet
}

pub fn node(role: NodeRole, context: RuleContext) -> Node {
    let id = DeviceId::new("local-device").unwrap();
    Node::new(
        Runtime::new(id, context, DeviceProfile::default()).unwrap(),
        role,
    )
}
