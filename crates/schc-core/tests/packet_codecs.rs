use schc_core::packet::{CoapMessage, Icmpv6Message, Ipv6Packet, UdpDatagram};

#[test]
fn ipv6_udp_coap_packet_round_trips() {
    let packet = hex::decode(
        "60000000000c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000c37d0\
         4001002a",
    )
    .unwrap();

    let ipv6 = Ipv6Packet::parse(&packet).unwrap();
    assert_eq!(ipv6.next_header(), 17);

    let udp = UdpDatagram::parse(ipv6.payload()).unwrap();
    assert_eq!(udp.source_port(), 5683);
    assert_eq!(udp.destination_port(), 5683);

    let coap = CoapMessage::parse(udp.payload()).unwrap();
    assert_eq!(coap.version(), 1);
    assert_eq!(coap.code(), 1);
    assert_eq!(coap.message_id(), 42);

    assert_eq!(ipv6.to_vec(), packet);
}

#[test]
fn ipv6_rejects_truncated_headers_wrong_version_and_short_payloads() {
    assert!(Ipv6Packet::parse(&[0; 39]).is_err());

    let mut wrong_version = [0; 40];
    wrong_version[0] = 0x40;
    assert!(Ipv6Packet::parse(&wrong_version).is_err());

    let mut short_payload = [0; 40];
    short_payload[0] = 0x60;
    short_payload[5] = 1;
    assert!(Ipv6Packet::parse(&short_payload).is_err());
}

#[test]
fn udp_rejects_truncated_and_invalid_lengths() {
    assert!(UdpDatagram::parse(&[0; 7]).is_err());

    let too_small = [0, 0, 0, 0, 0, 7, 0, 0];
    assert!(UdpDatagram::parse(&too_small).is_err());

    let too_large = [0, 0, 0, 0, 0, 9, 0, 0];
    assert!(UdpDatagram::parse(&too_large).is_err());
}

#[test]
fn coap_parses_extended_option_forms_and_round_trips() {
    let mut message = vec![0x40, 0x01, 0x00, 0x2a, 0xdd, 0x00, 0x00];
    message.extend_from_slice(b"hello, world!");

    let coap = CoapMessage::parse(&message).unwrap();

    assert_eq!(coap.options()[0].number(), 13);
    assert_eq!(coap.options()[0].value(), b"hello, world!");
    assert_eq!(coap.to_vec(), message);
}

#[test]
fn coap_rejects_reserved_option_nibbles_and_empty_payload_marker() {
    assert!(CoapMessage::parse(&[0x40, 0x01, 0x00, 0x2a, 0xf0]).is_err());
    assert!(CoapMessage::parse(&[0x40, 0x01, 0x00, 0x2a, 0x0f]).is_err());
    assert!(CoapMessage::parse(&[0x40, 0x01, 0x00, 0x2a, 0xff]).is_err());
}

#[test]
fn icmpv6_rejects_truncated_messages_and_preserves_bytes() {
    assert!(Icmpv6Message::parse(&[128, 0, 0]).is_err());

    let message = [128, 0, 0x12, 0x34, 0xab, 0xcd];
    let icmp = Icmpv6Message::parse(&message).unwrap();

    assert_eq!(icmp.message_type(), 128);
    assert_eq!(icmp.code(), 0);
    assert_eq!(icmp.checksum(), 0x1234);
    assert_eq!(icmp.payload(), &[0xab, 0xcd]);
    assert_eq!(icmp.to_vec(), message);
}
