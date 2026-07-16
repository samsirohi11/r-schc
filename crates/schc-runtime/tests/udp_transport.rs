mod support;

use schc_core::RuleId;
use schc_runtime::udp::{UdpError, UdpOperation, UdpReport, UdpTransport, UdpTransportConfig};
use schc_runtime::NodeRole;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;
use support::{context, downlink_packet, management_packet, node};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

fn bound_socket() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    (socket, address)
}

fn output_socket() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    (socket, address)
}

fn config(
    link_bind: SocketAddr,
    link_peer: SocketAddr,
    packet_ingress_bind: SocketAddr,
    packet_output_peer: SocketAddr,
) -> UdpTransportConfig {
    UdpTransportConfig {
        link_bind,
        link_peer,
        packet_ingress_bind,
        packet_output_peer,
    }
}

fn assert_outbound_report(report: UdpReport, rule_id: RuleId, packet_len: usize, link_len: usize) {
    assert_eq!(report.operation, UdpOperation::Outbound);
    assert_eq!(report.rule_id, rule_id);
    assert_eq!(report.received_bytes, packet_len);
    assert_eq!(report.sent_bytes, link_len);
}

fn assert_inbound_report(report: UdpReport, rule_id: RuleId, link_len: usize, packet_len: usize) {
    assert_eq!(report.operation, UdpOperation::Inbound);
    assert_eq!(report.rule_id, rule_id);
    assert_eq!(report.received_bytes, link_len);
    assert_eq!(report.sent_bytes, packet_len);
}

#[test]
fn device_ingress_to_core_output_uses_one_raw_management_schc_datagram() {
    let (device_link_socket, device_link) = bound_socket();
    let (core_link_socket, core_link) = bound_socket();
    let (device_ingress_socket, device_ingress) = bound_socket();
    let (core_ingress_socket, core_ingress) = bound_socket();
    let (core_output, core_output_addr) = output_socket();
    let (_device_output, device_output_addr) = output_socket();

    let device = UdpTransport::from_sockets(
        node(NodeRole::Device, context()),
        device_link_socket,
        device_ingress_socket,
        config(device_link, core_link, device_ingress, device_output_addr),
    )
    .unwrap();
    let core = UdpTransport::from_sockets(
        node(NodeRole::Core, context()),
        core_link_socket,
        core_ingress_socket,
        config(core_link, device_link, core_ingress, core_output_addr),
    )
    .unwrap();
    device.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    core.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    let management = management_packet();
    let expected = node(NodeRole::Device, context())
        .outbound(&management)
        .unwrap();
    assert_eq!(expected.frame().bit_len() % 8, 4);

    let core_thread = thread::spawn(move || core.inbound_once());
    let ingress_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    ingress_sender
        .send_to(&management, device.packet_ingress_local_addr().unwrap())
        .unwrap();
    let device_report = device.outbound_once().unwrap();
    let core_report = core_thread.join().unwrap().unwrap();

    let mut output = vec![0_u8; 65_535];
    let (output_len, _) = core_output.recv_from(&mut output).unwrap();
    assert_eq!(&output[..output_len], management.as_slice());
    assert_outbound_report(
        device_report,
        RuleId::new(1, 4),
        management.len(),
        expected.frame().bytes().len(),
    );
    assert_inbound_report(
        core_report,
        RuleId::new(1, 4),
        expected.frame().bytes().len(),
        management.len(),
    );
}

#[test]
fn core_ingress_to_device_output_uses_one_raw_ordinary_schc_datagram() {
    let (device_link_socket, device_link) = bound_socket();
    let (core_link_socket, core_link) = bound_socket();
    let (device_ingress_socket, device_ingress) = bound_socket();
    let (core_ingress_socket, core_ingress) = bound_socket();
    let (core_output, core_output_addr) = output_socket();
    let (device_output, device_output_addr) = output_socket();

    let core = UdpTransport::from_sockets(
        node(NodeRole::Core, context()),
        core_link_socket,
        core_ingress_socket,
        config(core_link, device_link, core_ingress, core_output_addr),
    )
    .unwrap();
    let device = UdpTransport::from_sockets(
        node(NodeRole::Device, context()),
        device_link_socket,
        device_ingress_socket,
        config(device_link, core_link, device_ingress, device_output_addr),
    )
    .unwrap();
    core.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    device.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    let packet = downlink_packet();
    let expected = node(NodeRole::Core, context()).outbound(&packet).unwrap();
    let device_thread = thread::spawn(move || device.inbound_once());
    let ingress_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    ingress_sender
        .send_to(&packet, core.packet_ingress_local_addr().unwrap())
        .unwrap();
    let core_report = core.outbound_once().unwrap();
    let device_report = device_thread.join().unwrap().unwrap();

    let mut output = vec![0_u8; 65_535];
    let (output_len, _) = device_output.recv_from(&mut output).unwrap();
    assert_eq!(&output[..output_len], packet.as_slice());
    assert_outbound_report(
        core_report,
        RuleId::new(2, 4),
        packet.len(),
        expected.frame().bytes().len(),
    );
    assert_inbound_report(
        device_report,
        RuleId::new(2, 4),
        expected.frame().bytes().len(),
        packet.len(),
    );
    drop(core_output);
}

#[test]
fn outbound_link_datagram_matches_node_bytes_without_metadata() {
    let (link_socket, link_addr) = bound_socket();
    let (link_capture, link_capture_addr) = bound_socket();
    let (packet_ingress, packet_ingress_addr) = bound_socket();
    let (_packet_output, packet_output_addr) = output_socket();
    let transport = UdpTransport::from_sockets(
        node(NodeRole::Device, context()),
        link_socket,
        packet_ingress,
        config(
            link_addr,
            link_capture_addr,
            packet_ingress_addr,
            packet_output_addr,
        ),
    )
    .unwrap();
    transport.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    let packet = management_packet();
    let expected = node(NodeRole::Device, context()).outbound(&packet).unwrap();
    assert_eq!(expected.frame().bit_len() % 8, 4);
    let ingress_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    ingress_sender
        .send_to(&packet, packet_ingress_addr)
        .unwrap();

    let report = transport.outbound_once().unwrap();
    let mut captured = vec![0_u8; 65_535];
    let (captured_len, source) = link_capture.recv_from(&mut captured).unwrap();
    assert_eq!(source, link_addr);
    assert_eq!(&captured[..captured_len], expected.frame().bytes());
    assert_outbound_report(
        report,
        RuleId::new(1, 4),
        packet.len(),
        expected.frame().bytes().len(),
    );
}

#[test]
fn link_datagrams_from_unexpected_peers_are_rejected_before_decompression() {
    let (_expected_peer_socket, expected_peer) = bound_socket();
    let (core_link_socket, core_link) = bound_socket();
    let (core_ingress_socket, core_ingress) = bound_socket();
    let (packet_output, packet_output_addr) = output_socket();
    let core = UdpTransport::from_sockets(
        node(NodeRole::Core, context()),
        core_link_socket,
        core_ingress_socket,
        config(core_link, expected_peer, core_ingress, packet_output_addr),
    )
    .unwrap();
    core.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    attacker
        .send_to(&[0_u8], core.link_local_addr().unwrap())
        .unwrap();
    let error = core.inbound_once().unwrap_err();
    assert!(matches!(error, UdpError::UnexpectedLinkPeer { .. }));
    packet_output
        .recv_from(&mut [0_u8; 64])
        .expect_err("unexpected peer must not produce packet output");
}
