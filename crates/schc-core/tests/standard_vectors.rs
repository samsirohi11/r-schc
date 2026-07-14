// Bit-exact SCHC compression and decompression vectors.
//
// Each vector asserts the exact compressed byte sequence and exact bit length
// produced by compressing a known IPv6/UDP/CoAP or IPv6/ICMPv6 packet against
// a SCHC rule, and the exact reconstructed packet bytes produced by
// decompressing that exact compressed datagram.
//
// Vectors are derived from the executable SCHC compression behavior over the
// committed packet and rule fixtures in `fixtures/`. The compressed datagrams
// and bit lengths recorded here are the stable, bit-exact outputs of that
// behavior and act as regression coverage for supported SCHC core paths:
//
// - UDP/CoAP uplink compression and decompression.
// - CoAP options and payload marker behavior.
// - UDP payload explicit residue behavior.
// - ICMPv6 echo compression and decompression.
// - ICMPv6 error embedded-packet direction reversal.

use schc_core::{Compressor, Decompressor, Direction, Position, RuleContext, SidRegistry};

fn sid_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sid/minimal.sid.json"
    )
}

fn rule_fixture(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/rules/");
    std::fs::read_to_string(format!("{path}{name}")).unwrap()
}

fn context_from_rule(name: &str) -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    RuleContext::from_json_str(&rule_fixture(name), registry).unwrap()
}

fn context_from_str(json: &str) -> RuleContext {
    let registry = SidRegistry::load_path(sid_fixture()).unwrap();
    RuleContext::from_json_str(json, registry).unwrap()
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// UDP/CoAP GET uplink vector (IETF SCHC UDP and CoAP compression).
//
// Rule: `udp_coap.json` (rule id 3, 4-bit rule id).
// Packet: IPv6/UDP/CoAP GET with message id 0x002a, no token, no options,
// no payload.
// Compressed datagram: rule id `0x3`, hop limit `0x40`, CoAP type `0x0`,
// CoAP message id `0x002a`, zero padding to byte boundary.
mod udp_coap_get {
    use super::*;

    const RULE: &str = "udp_coap.json";
    const PACKET_HEX: &str = "60000000000c114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000c37d0\
         4001002a";
    const COMPRESSED_HEX: &str = "3400000a80";
    const COMPRESSED_BIT_LEN: usize = 34;

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_rule(RULE)
    }

    #[test]
    fn compress_udp_coap_get_uplink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_udp_coap_get_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// UDP/CoAP POST uplink vector with a dynamic-length CoAP token.
//
// Rule: inline rule id 4, 4-bit rule id, `fid-coap-tkl` ignored with
// `value-sent` and `fid-coap-token` length `token-length`.
// Packet: IPv6/UDP/CoAP POST carrying a 2-byte token `0xaabb` and message id
// `0x1234`.
// Compressed datagram: rule id `0x4`, hop limit `0x40`, CoAP type `0x0`,
// CoAP TKL `0x2`, CoAP message id `0x1234`, token `0xaabb`, zero padding.
mod udp_coap_token {
    use super::*;

    const PACKET_HEX: &str = "60000000000e114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000e7905\
         42021234aabb";
    const COMPRESSED_HEX: &str = "4400848d2aaec0";
    const COMPRESSED_BIT_LEN: usize = 50;

    fn rule_json() -> &'static str {
        r#"
    {
      "rules": [{
        "rule_id": 4,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "direction": "bi", "target": "11", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "40", "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-dev-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-app-port", "length_bits": 16, "direction": "up", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-coap-version", "length_bits": 2, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-coap-type", "length_bits": 2, "direction": "bi", "target": "00", "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-tkl", "length_bits": 4, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-code", "length_bits": 8, "direction": "bi", "target": "02", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-coap-mid", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" },
          { "field": "fid-coap-token", "length": { "type": "token-length" }, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }
        ]
      }]
    }
    "#
    }

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_str(rule_json())
    }

    #[test]
    fn compress_udp_coap_token_uplink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_udp_coap_token_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// UDP explicit payload residue vector.
//
// Rule: `udp_payload.json` (rule id 8, 4-bit rule id) with a variable-length
// `fid-udp-payload` field sent by value.
// Packet: IPv6/UDP carrying the payload `hello`.
// Compressed datagram: rule id `0x8`, hop limit `0x40`, payload length
// `0x05`, payload `hello`.
mod udp_payload_residue {
    use super::*;

    const RULE: &str = "udp_payload.json";
    const PACKET_HEX: &str = "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f";
    const COMPRESSED_HEX: &str = "840568656c6c6f";
    const COMPRESSED_BIT_LEN: usize = 56;

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_rule(RULE)
    }

    #[test]
    fn compress_udp_payload_uplink_produces_exact_residue() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_udp_payload_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// UDP/CoAP uplink vector with a variable-length CoAP Uri-Path option and a
// CoAP payload separated by the payload marker `0xff`.
//
// Rule: `dynamic_coap.json` (rule id 4, 4-bit rule id) with a fixed
// `fid-coap-option-uri-path` target `temp` and a variable-length
// `fid-coap-payload` sent by value.
// Packet: IPv6/UDP/CoAP POST with token `0xaabb`, Uri-Path option `temp`,
// payload marker, and payload `21.5`.
// Compressed datagram: rule id `0x4`, hop limit `0x40`, CoAP type `0x0`,
// CoAP TKL `0x2`, CoAP message id `0x1234`, token `0xaabb`, payload `21.5`.
mod coap_path_payload {
    use super::*;

    const RULE: &str = "dynamic_coap.json";
    const PACKET_HEX: &str = "600000000018114020010db8000000000000000000000001\
         20010db80000000000000000000000021633163300188da9\
         42021234aabbb474656d70ff32312e35";
    const COMPRESSED_HEX: &str = "4400848d2aaed0c8c4b8d4";
    const COMPRESSED_BIT_LEN: usize = 86;

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_rule(RULE)
    }

    #[test]
    fn compress_coap_path_payload_uplink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_coap_path_payload_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// UDP/CoAP uplink vector using CoAP options addressed by option number with
// `match-mapping` matching operators and a payload marker.
//
// Rule: `coap_option_by_number.json` (rule id 6, 4-bit rule id). The
// `coap-option(11)` and `coap-option(12)` fields use `match-mapping` with
// `mapping-sent`, so the compressed datagram carries the mapping index bits.
// Packet: IPv6/UDP/CoAP GET with token `0xaabb`, option 11 value `cs`,
// option 12 value `8e`, payload marker, and payload `21.5`.
// Compressed datagram: rule id `0x6`, hop limit `0x40`, CoAP type `0x0`,
// CoAP TKL `0x2`, CoAP message id `0x1234`, token `0xaabb`, two 1-bit
// mapping indices, payload `21.5`.
mod coap_option_by_number {
    use super::*;

    const RULE: &str = "coap_option_by_number.json";
    const PACKET_HEX: &str = "600000000017114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633001750a1\
         42011234aabbb163118eff32312e35";
    const COMPRESSED_HEX: &str = "6400848d2aaed432312e35";
    const COMPRESSED_BIT_LEN: usize = 88;

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_rule(RULE)
    }

    #[test]
    fn compress_coap_option_by_number_uplink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_coap_option_by_number_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// ICMPv6 echo request uplink vector.
//
// Rule: `icmpv6_echo.json` (rule id 9, 4-bit rule id) with a variable-length
// `fid-icmpv6-payload` field sent by value.
// Packet: IPv6/ICMPv6 echo request with checksum `0x333e`, identifier and
// sequence `0x12340001`, and payload `ping`.
// Compressed datagram: rule id `0x9`, hop limit `0x40`, identifier and
// sequence `0x12340001`, payload `ping`.
mod icmpv6_echo {
    use super::*;

    const RULE: &str = "icmpv6_echo.json";
    const PACKET_HEX: &str = "60000000000c3a4020010db8000000000000000000000001\
         20010db80000000000000000000000028000333e12340001\
         70696e67";
    const COMPRESSED_HEX: &str = "94081234000170696e67";
    const COMPRESSED_BIT_LEN: usize = 80;

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_rule(RULE)
    }

    #[test]
    fn compress_icmpv6_echo_uplink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_icmpv6_echo_uplink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// ICMPv6 error message with an embedded IPv6/UDP packet, downlink direction.
//
// The SCHC rule covers the outer ICMPv6 error header and the inner embedded
// IPv6/UDP header at `field_position` 2. The outer hop limit and inner hop
// limit are both fixed (`not-sent`), so the compressed datagram carries only
// the rule id.
// Rule: inline rule id 5, 4-bit rule id.
// Packet: IPv6/ICMPv6 destination-unreachable embedding an IPv6/UDP header.
// Compressed datagram: rule id `0x5`.
mod icmpv6_error_embedded {
    use super::*;

    const PACKET_HEX: &str = "6000000000383aff20010db8000000000000000000000002\
         20010db80000000000000000000000010104312600000000\
         60000000000811ff20010db8000000000000000000000001\
         20010db80000000000000000000000021633163300087803";
    const COMPRESSED_HEX: &str = "50";
    const COMPRESSED_BIT_LEN: usize = 4;

    fn rule_json() -> &'static str {
        r#"
    {
      "rules": [{
        "rule_id": 5,
        "rule_id_length": 4,
        "fields": [
          { "field": "fid-ipv6-version", "length_bits": 4, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "direction": "bi", "target": "3a", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "direction": "bi", "target": "ff", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-type", "length_bits": 8, "direction": "bi", "target": "01", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-code", "length_bits": 8, "direction": "bi", "target": "04", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-icmpv6-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-unused", "length_bits": 32, "direction": "bi", "target": "00000000", "mo": "equal", "cda": "not-sent" },

          { "field": "fid-ipv6-version", "length_bits": 4, "field_position": 2, "direction": "bi", "target": "06", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-trafficclass", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "00", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-flowlabel", "length_bits": 20, "field_position": 2, "direction": "bi", "target": "000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-payload-length", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-ipv6-nextheader", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "11", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-hoplimit", "length_bits": 8, "field_position": 2, "direction": "bi", "target": "ff", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-devprefix", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-deviid", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "0000000000000001", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appprefix", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "20010db800000000", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-ipv6-appiid", "length_bits": 64, "field_position": 2, "direction": "bi", "target": "0000000000000002", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-dev-port", "length_bits": 16, "field_position": 2, "direction": "bi", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-app-port", "length_bits": 16, "field_position": 2, "direction": "bi", "target": "1633", "mo": "equal", "cda": "not-sent" },
          { "field": "fid-udp-length", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" },
          { "field": "fid-udp-checksum", "length_bits": 16, "field_position": 2, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }
        ]
      }]
    }
    "#
    }

    fn packet() -> Vec<u8> {
        hex_decode(PACKET_HEX)
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_str(rule_json())
    }

    #[test]
    fn compress_icmpv6_error_downlink_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Down, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_icmpv6_error_downlink_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Device, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}

// UDP payload residue vector with the UDP checksum sent by value.
//
// Rule: `udp_payload.json` with the `fid-udp-checksum` field changed from
// `compute` to `value-sent`, so the compressed datagram carries the checksum
// inline before the payload residue.
// Packet: IPv6/UDP carrying payload `hello` with checksum `0x1234`.
// Compressed datagram: rule id `0x8`, hop limit `0x40`, UDP checksum
// `0x1234`, payload length `0x05`, payload `hello`.
mod udp_payload_sent_checksum {
    use super::*;

    const RULE: &str = "udp_payload.json";
    const PACKET_HEX: &str = "60000000000d114020010db8000000000000000000000001\
         20010db800000000000000000000000216331633000d3427\
         68656c6c6f";
    const COMPRESSED_HEX: &str = "8401234568656c6c6f";
    const COMPRESSED_BIT_LEN: usize = 72;

    fn rule_json() -> String {
        let json = rule_fixture(RULE);
        let checksum_compute = r#"{ "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "compute" }"#;
        assert_eq!(
            json.matches(checksum_compute).count(),
            1,
            "UDP checksum rule entry should appear exactly once in fixture"
        );
        json.replace(
            checksum_compute,
            r#"{ "field": "fid-udp-checksum", "length_bits": 16, "direction": "bi", "target": null, "mo": "ignore", "cda": "value-sent" }"#,
        )
    }

    fn packet() -> Vec<u8> {
        let mut p = hex_decode(PACKET_HEX);
        // Override the UDP checksum bytes with the value carried in the
        // compressed datagram.
        p[46] = 0x12;
        p[47] = 0x34;
        p
    }
    fn compressed() -> Vec<u8> {
        hex_decode(COMPRESSED_HEX)
    }
    fn context() -> RuleContext {
        context_from_str(&rule_json())
    }

    #[test]
    fn compress_udp_payload_sent_checksum_produces_exact_datagram() {
        let out = Compressor::new(context())
            .unwrap()
            .compress(Direction::Up, &packet())
            .unwrap();
        assert_eq!(out.bit_len(), COMPRESSED_BIT_LEN);
        assert_eq!(out.bytes(), compressed());
    }

    #[test]
    fn decompress_udp_payload_sent_checksum_reconstructs_exact_packet() {
        let out = Decompressor::new(context())
            .unwrap()
            .decompress(Position::Core, &compressed())
            .unwrap();
        assert_eq!(out, packet());
    }
}
