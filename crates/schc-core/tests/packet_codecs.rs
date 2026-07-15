use schc_core::packet::{CoapMessage, CoapOption, Icmpv6Message, Ipv6Packet, UdpDatagram};

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

    assert!(Icmpv6Message::parse(&[128, 0, 0x12, 0x34, 0xab, 0xcd]).is_err());

    let message = [128, 0, 0x12, 0x34, 0xab, 0xcd, 0, 1, b'o', b'k'];
    let icmp = Icmpv6Message::parse(&message).unwrap();

    assert_eq!(icmp.message_type(), 128);
    assert_eq!(icmp.code(), 0);
    assert_eq!(icmp.checksum(), 0x1234);
    assert_eq!(icmp.payload(), b"ok");
    assert_eq!(icmp.to_vec(), message);
}

#[test]
fn icmpv6_message_builds_echo_payload() {
    let icmp = Icmpv6Message::from_parts(128, 0, 0x333e, b"\x12\x34\x00\x01ping".to_vec()).unwrap();

    assert_eq!(icmp.message_type(), 128);
    assert_eq!(icmp.code(), 0);
    assert_eq!(icmp.checksum(), 0x333e);
    assert_eq!(icmp.payload(), b"ping");
    assert_eq!(
        icmp.to_vec(),
        hex::decode("8000333e1234000170696e67").unwrap()
    );
}

#[test]
fn coap_message_builds_token_options_and_payload() {
    let message = CoapMessage::from_parts(
        1,
        0,
        2,
        0x1234,
        b"\xaa\xbb".to_vec(),
        vec![CoapOption::new(11, b"temp".to_vec()).unwrap()],
        b"21.5".to_vec(),
    )
    .unwrap();

    assert_eq!(
        message.to_vec(),
        hex::decode("42021234aabbb474656d70ff32312e35").unwrap()
    );
}

#[test]
fn coap_repeated_options_same_absolute_number_round_trip() {
    // Two Uri-Path options (CoAP option number 11) with the same absolute
    // option number must parse and rebuild exactly. The second option has a
    // zero delta so it keeps the same absolute number.
    let bytes = hex::decode("4001002ab474656d70026373").unwrap();

    let coap = CoapMessage::parse(&bytes).unwrap();
    assert_eq!(coap.options().len(), 2);
    assert_eq!(coap.options()[0].number(), 11);
    assert_eq!(coap.options()[0].value(), b"temp");
    assert_eq!(coap.options()[1].number(), 11);
    assert_eq!(coap.options()[1].value(), b"cs");
    assert!(coap.payload().is_empty());
    assert_eq!(coap.to_vec(), bytes);

    // The builder must also accept repeated options with the same number,
    // since from_parts only requires nondecreasing order.
    let rebuilt = CoapMessage::from_parts(
        1,
        0,
        1,
        0x002a,
        Vec::new(),
        vec![
            CoapOption::new(11, b"temp".to_vec()).unwrap(),
            CoapOption::new(11, b"cs".to_vec()).unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(rebuilt.to_vec(), bytes);
}

#[test]
fn coap_extended_option_delta_boundaries_round_trip() {
    // Delta 268 is the maximum 8-bit extended delta (nibble 13, extension 255).
    let max_8bit = hex::decode("4001002ad0ff").unwrap();
    let coap = CoapMessage::parse(&max_8bit).unwrap();
    assert_eq!(coap.options().len(), 1);
    assert_eq!(coap.options()[0].number(), 268);
    assert_eq!(coap.options()[0].value(), &[] as &[u8]);
    assert_eq!(coap.to_vec(), max_8bit);

    // Delta 269 is the minimum 16-bit extended delta (nibble 14, extension 0).
    let min_16bit = hex::decode("4001002ae00000").unwrap();
    let coap = CoapMessage::parse(&min_16bit).unwrap();
    assert_eq!(coap.options().len(), 1);
    assert_eq!(coap.options()[0].number(), 269);
    assert_eq!(coap.options()[0].value(), &[] as &[u8]);
    assert_eq!(coap.to_vec(), min_16bit);
}

#[test]
fn coap_extended_option_length_boundaries_round_trip() {
    // Length 268 is the maximum 8-bit extended length (nibble 13, extension 255).
    let value_268 = vec![0xaau8; 268];
    let built = CoapMessage::from_parts(
        1,
        0,
        1,
        0x002a,
        Vec::new(),
        vec![CoapOption::new(11, value_268.clone()).unwrap()],
        Vec::new(),
    )
    .unwrap();
    let serialized = built.to_vec();
    // Header: delta 11 (0xb), length nibble 13 (0xd) -> 0xbd, then 0xff extension.
    assert_eq!(&serialized[..5], &[0x40, 0x01, 0x00, 0x2a, 0xbd]);
    assert_eq!(serialized[5], 0xff);
    assert_eq!(serialized.len(), 4 + 2 + 268);

    let reparsed = CoapMessage::parse(&serialized).unwrap();
    assert_eq!(reparsed.options()[0].number(), 11);
    assert_eq!(reparsed.options()[0].value(), &value_268[..]);
    assert_eq!(reparsed.to_vec(), serialized);

    // Length 269 is the minimum 16-bit extended length (nibble 14, extension 0).
    let value_269 = vec![0xbbu8; 269];
    let built = CoapMessage::from_parts(
        1,
        0,
        1,
        0x002a,
        Vec::new(),
        vec![CoapOption::new(11, value_269.clone()).unwrap()],
        Vec::new(),
    )
    .unwrap();
    let serialized = built.to_vec();
    // Header: delta 11 (0xb), length nibble 14 (0xe) -> 0xbe, then 0x0000 extension.
    assert_eq!(&serialized[..5], &[0x40, 0x01, 0x00, 0x2a, 0xbe]);
    assert_eq!(&serialized[5..7], &[0x00, 0x00]);
    assert_eq!(serialized.len(), 4 + 3 + 269);

    let reparsed = CoapMessage::parse(&serialized).unwrap();
    assert_eq!(reparsed.options()[0].number(), 11);
    assert_eq!(reparsed.options()[0].value(), &value_269[..]);
    assert_eq!(reparsed.to_vec(), serialized);
}

#[test]
fn coap_empty_payload_omits_marker_and_round_trips() {
    // A message with options but no payload must not emit the 0xff payload
    // marker, and must round-trip through parse and to_vec.
    let message = CoapMessage::from_parts(
        1,
        0,
        1,
        0x002a,
        Vec::new(),
        vec![CoapOption::new(11, b"temp".to_vec()).unwrap()],
        Vec::new(),
    )
    .unwrap();

    let serialized = message.to_vec();
    assert!(!serialized.contains(&0xff));

    let reparsed = CoapMessage::parse(&serialized).unwrap();
    assert!(reparsed.payload().is_empty());
    assert_eq!(reparsed.to_vec(), serialized);
}
