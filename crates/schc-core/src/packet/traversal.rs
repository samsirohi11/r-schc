//! Shared packet nesting traversal helpers.

use crate::error::{Result, SchcError};
use crate::packet::{field::PacketScope, Icmpv6Message, Ipv6Packet};

/// Returns true when an `ICMPv6` message type carries an invoking packet.
#[must_use]
pub(crate) const fn is_icmpv6_error_type(message_type: u8) -> bool {
    matches!(message_type, 1..=4)
}

/// Returns true when an `ICMPv6` error carries a 32-bit unused field.
#[must_use]
pub(crate) const fn has_icmpv6_unused_field(message_type: u8) -> bool {
    matches!(message_type, 1 | 3)
}

/// Returns the packet bytes for a traversal scope.
///
/// Both outer and embedded packet access use the same IPv6 and `ICMPv6` error
/// validation path. Embedded bytes are limited by their own IPv6 payload
/// length.
pub(crate) fn packet_for_scope(packet: &[u8], scope: PacketScope) -> Result<Vec<u8>> {
    match scope {
        PacketScope::Outer => Ok(Ipv6Packet::parse(packet)?.to_vec()),
        PacketScope::Embedded => embedded_ipv6_packet(packet),
    }
}

/// Extracts the IPv6 packet embedded in an `ICMPv6` error message.
///
/// The returned bytes are limited to the embedded IPv6 packet declared by its
/// own IPv6 payload length. This keeps all nested extraction callers on the same
/// packet traversal and truncation rules.
pub(crate) fn embedded_ipv6_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let ipv6 = Ipv6Packet::parse(packet)?;
    if ipv6.next_header() != 58 {
        return Err(packet_error(
            "ICMPv6",
            "embedded packet requires an ICMPv6 next header",
        ));
    }
    let icmp = Icmpv6Message::parse(ipv6.payload())?;
    if !is_icmpv6_error_type(icmp.message_type()) {
        return Err(packet_error(
            "ICMPv6",
            "embedded packet requires an ICMPv6 error type",
        ));
    }
    if icmp.payload().len() < 4 {
        return Err(packet_error(
            "ICMPv6",
            "error header is shorter than 8 bytes",
        ));
    }
    let embedded = icmp.payload();
    Ok(Ipv6Packet::parse(embedded)?.to_vec())
}

fn packet_error(protocol: &'static str, reason: impl Into<String>) -> SchcError {
    SchcError::Packet {
        protocol,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{has_icmpv6_unused_field, is_icmpv6_error_type};

    #[test]
    fn classifies_icmpv6_error_words() {
        assert!(has_icmpv6_unused_field(1));
        assert!(has_icmpv6_unused_field(3));
        assert!(!has_icmpv6_unused_field(2));
        assert!(!has_icmpv6_unused_field(4));
        assert!((1..=4).all(is_icmpv6_error_type));
    }
}
