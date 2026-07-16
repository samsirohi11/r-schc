mod support;

use schc_core::RuleId;
use schc_runtime::{DeviceId, DeviceProfile, NodeRole, Runtime};
use support::{context, downlink_packet, management_packet, node};

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

    let management = management_packet();
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
    let management = management_packet();
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
