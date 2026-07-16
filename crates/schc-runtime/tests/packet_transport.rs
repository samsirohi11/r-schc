mod support;

use schc_core::RuleId;
use schc_runtime::packet::{
    PacketDevice, PacketDeviceError, PacketOperation, PacketReport, PacketTransport,
    PacketTransportConfig, PacketTransportError,
};
use schc_runtime::NodeRole;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use support::{context, downlink_packet, management_packet, node};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

type SharedPackets = Arc<Mutex<Vec<Vec<u8>>>>;

struct MemoryPacketDevice {
    incoming: VecDeque<Result<Vec<u8>, PacketDeviceError>>,
    written: SharedPackets,
    write_count: Option<usize>,
}

impl MemoryPacketDevice {
    fn with_packet(packet: Vec<u8>) -> (Self, SharedPackets) {
        let written = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                incoming: VecDeque::from([Ok(packet)]),
                written: Arc::clone(&written),
                write_count: None,
            },
            written,
        )
    }

    fn with_read_result(result: Result<Vec<u8>, PacketDeviceError>) -> Self {
        Self {
            incoming: VecDeque::from([result]),
            written: Arc::new(Mutex::new(Vec::new())),
            write_count: None,
        }
    }

    fn with_short_write(packet: &[u8]) -> Self {
        Self {
            incoming: VecDeque::new(),
            written: Arc::new(Mutex::new(Vec::new())),
            write_count: Some(packet.len().saturating_sub(1)),
        }
    }
}

impl PacketDevice for MemoryPacketDevice {
    fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError> {
        self.incoming.pop_front().unwrap_or_else(|| {
            Err(PacketDeviceError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no packet queued",
            )))
        })
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PacketDeviceError> {
        let count = self.write_count.unwrap_or(packet.len());
        if count == packet.len() {
            self.written
                .lock()
                .expect("memory packet device lock")
                .push(packet.to_vec());
        }
        Ok(count)
    }
}

fn bound_socket() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    (socket, address)
}

fn transport<D: PacketDevice>(
    role: NodeRole,
    device: D,
    link_socket: UdpSocket,
    link_bind: SocketAddr,
    link_peer: SocketAddr,
) -> PacketTransport<D> {
    let transport = PacketTransport::from_socket(
        node(role, context()),
        device,
        link_socket,
        PacketTransportConfig {
            link_bind,
            link_peer,
        },
    )
    .unwrap();
    transport.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    transport
}

fn assert_report(
    report: PacketReport,
    operation: PacketOperation,
    rule_id: RuleId,
    received_bytes: usize,
    sent_bytes: usize,
) {
    assert_eq!(
        report,
        PacketReport {
            operation,
            rule_id,
            received_bytes,
            sent_bytes,
        }
    );
}

#[test]
fn device_to_core_management_uplink_preserves_packet_boundary_and_rule_id() {
    let (device_link_socket, device_link) = bound_socket();
    let (core_link_socket, core_link) = bound_socket();
    let management = management_packet();
    let expected = node(NodeRole::Device, context())
        .outbound(&management)
        .unwrap();
    assert_eq!(expected.frame().bit_len() % 8, 4);

    let (device_device, _device_written) = MemoryPacketDevice::with_packet(management.clone());
    let (core_device, core_written) = MemoryPacketDevice::with_packet(Vec::new());
    let mut device = transport(
        NodeRole::Device,
        device_device,
        device_link_socket,
        device_link,
        core_link,
    );
    let mut core = transport(
        NodeRole::Core,
        core_device,
        core_link_socket,
        core_link,
        device_link,
    );

    let core_thread = thread::spawn(move || core.inbound_once());
    let device_report = device.outbound_once().unwrap();
    let core_report = core_thread.join().unwrap().unwrap();

    assert_report(
        device_report,
        PacketOperation::Outbound,
        RuleId::new(1, 4),
        management.len(),
        expected.frame().bytes().len(),
    );
    assert_report(
        core_report,
        PacketOperation::Inbound,
        RuleId::new(1, 4),
        expected.frame().bytes().len(),
        management.len(),
    );
    assert_eq!(
        core_written.lock().unwrap().as_slice(),
        [management].as_slice()
    );
}

#[test]
fn core_to_device_ordinary_downlink_preserves_packet_boundary_and_rule_id() {
    let (device_link_socket, device_link) = bound_socket();
    let (core_link_socket, core_link) = bound_socket();
    let packet = downlink_packet();
    let expected = node(NodeRole::Core, context()).outbound(&packet).unwrap();

    let (core_device, _core_written) = MemoryPacketDevice::with_packet(packet.clone());
    let (device_device, device_written) = MemoryPacketDevice::with_packet(Vec::new());
    let mut core = transport(
        NodeRole::Core,
        core_device,
        core_link_socket,
        core_link,
        device_link,
    );
    let mut device = transport(
        NodeRole::Device,
        device_device,
        device_link_socket,
        device_link,
        core_link,
    );

    let device_thread = thread::spawn(move || device.inbound_once());
    let core_report = core.outbound_once().unwrap();
    let device_report = device_thread.join().unwrap().unwrap();

    assert_report(
        core_report,
        PacketOperation::Outbound,
        RuleId::new(2, 4),
        packet.len(),
        expected.frame().bytes().len(),
    );
    assert_report(
        device_report,
        PacketOperation::Inbound,
        RuleId::new(2, 4),
        expected.frame().bytes().len(),
        packet.len(),
    );
    assert_eq!(
        device_written.lock().unwrap().as_slice(),
        [packet].as_slice()
    );
}

#[test]
fn outbound_link_datagram_is_exact_raw_padded_frame() {
    let (link_socket, link_bind) = bound_socket();
    let (capture, link_peer) = bound_socket();
    let packet = management_packet();
    let expected = node(NodeRole::Device, context()).outbound(&packet).unwrap();
    assert_eq!(expected.frame().bit_len() % 8, 4);
    let (device, _written) = MemoryPacketDevice::with_packet(packet.clone());
    let mut transport = transport(NodeRole::Device, device, link_socket, link_bind, link_peer);

    let report = transport.outbound_once().unwrap();
    let mut received = vec![0_u8; 65_535];
    let (received_bytes, source) = capture.recv_from(&mut received).unwrap();
    assert_eq!(source, link_bind);
    assert_eq!(&received[..received_bytes], expected.frame().bytes());
    assert_report(
        report,
        PacketOperation::Outbound,
        RuleId::new(1, 4),
        packet.len(),
        expected.frame().bytes().len(),
    );
}

#[test]
fn unexpected_link_peer_is_rejected_before_decompression() {
    let (link_socket, link_bind) = bound_socket();
    let (_expected_socket, expected_peer) = bound_socket();
    let (attacker, _) = bound_socket();
    let (device, written) = MemoryPacketDevice::with_packet(Vec::new());
    let mut transport = transport(
        NodeRole::Core,
        device,
        link_socket,
        link_bind,
        expected_peer,
    );

    attacker.send_to(&[0_u8], link_bind).unwrap();
    let error = transport.inbound_once().unwrap_err();
    assert!(matches!(
        error,
        PacketTransportError::UnexpectedLinkPeer { .. }
    ));
    assert!(written.lock().unwrap().is_empty());
}

fn assert_invalid_ipv6_ingress(packet: Vec<u8>) {
    let (link_socket, _link_bind) = bound_socket();
    let (_peer_socket, link_peer) = bound_socket();
    let link_bind = link_socket.local_addr().unwrap();
    let device = MemoryPacketDevice::with_read_result(Ok(packet));
    let mut transport = transport(NodeRole::Device, device, link_socket, link_bind, link_peer);

    let error = transport.outbound_once().unwrap_err();
    assert!(matches!(error, PacketTransportError::InvalidIpv6(_)));
}

#[test]
fn truncated_declared_ipv6_payload_is_rejected_at_packet_device_boundary() {
    let mut packet = support::packet();
    packet.truncate(packet.len() - 1);
    assert_invalid_ipv6_ingress(packet);
}

#[test]
fn trailing_ipv6_bytes_are_rejected_at_packet_device_boundary() {
    let mut packet = support::packet();
    packet.push(0xaa);
    assert_invalid_ipv6_ingress(packet);
}

#[test]
fn short_packet_device_write_is_reported_without_claiming_success() {
    let (link_socket, link_bind) = bound_socket();
    let (peer_socket, link_peer) = bound_socket();
    let packet = downlink_packet();
    let expected = node(NodeRole::Core, context()).outbound(&packet).unwrap();
    let device = MemoryPacketDevice::with_short_write(&packet);
    let mut transport = transport(NodeRole::Device, device, link_socket, link_bind, link_peer);

    peer_socket
        .send_to(expected.frame().bytes(), link_bind)
        .unwrap();
    let error = transport.inbound_once().unwrap_err();
    assert!(matches!(
        error,
        PacketTransportError::ShortWrite { expected: actual_expected, actual }
            if actual_expected == packet.len() && actual + 1 == actual_expected
    ));
}

#[test]
fn packet_device_short_read_error_is_preserved() {
    let (link_socket, link_bind) = bound_socket();
    let (_peer_socket, link_peer) = bound_socket();
    let device = MemoryPacketDevice::with_read_result(Err(PacketDeviceError::ShortRead {
        expected: 40,
        actual: 1,
    }));
    let mut transport = transport(NodeRole::Device, device, link_socket, link_bind, link_peer);

    let error = transport.outbound_once().unwrap_err();
    assert!(matches!(
        error,
        PacketTransportError::Device(PacketDeviceError::ShortRead {
            expected: 40,
            actual: 1
        })
    ));
}
