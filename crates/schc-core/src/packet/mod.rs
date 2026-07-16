//! Packet parsing and serialization.

pub(crate) mod builder;
pub(crate) mod checksum;
pub(crate) mod field;
pub(crate) mod length;

mod coap;
mod icmpv6;
mod ipv6;
mod udp;

pub(crate) mod traversal;

pub use coap::{CoapMessage, CoapOption};
pub use icmpv6::Icmpv6Message;
pub use ipv6::Ipv6Packet;
pub use udp::UdpDatagram;

/// Validates lengths declared by an IPv6 packet and its UDP payload when
/// present.
///
/// Non-IPv6 payloads remain valid for no-compression rules, which may carry
/// arbitrary bytes. IPv6 payloads and UDP datagrams must consume the complete
/// supplied byte slice.
///
/// # Errors
///
/// Returns a packet parsing error when a declared length is inconsistent with
/// the supplied bytes.
pub(crate) fn validate_packet_lengths(packet: &[u8]) -> crate::error::Result<()> {
    if packet.len() >= 40 && packet.first().is_some_and(|byte| byte >> 4 == 6) {
        let ipv6 = Ipv6Packet::parse(packet)?;
        if ipv6.next_header() == 17 {
            UdpDatagram::parse(ipv6.payload())?;
        }
    }
    Ok(())
}
