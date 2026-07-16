use crate::error::{Result, SchcError};

/// Parsed IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    bytes: Vec<u8>,
    payload_offset: usize,
    payload_len: usize,
}

impl Ipv6Packet {
    /// Parses an IPv6 packet from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the input is shorter than the fixed
    /// IPv6 header, has a non-IPv6 version, or declares a payload length that
    /// does not exactly match the available bytes.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < 40 {
            return Err(packet_error("IPv6", "packet shorter than 40-byte header"));
        }

        if input[0] >> 4 != 6 {
            return Err(packet_error("IPv6", "version is not 6"));
        }

        let payload_len = usize::from(u16::from_be_bytes([input[4], input[5]]));
        let total_len = 40usize
            .checked_add(payload_len)
            .ok_or_else(|| packet_error("IPv6", "payload length overflows packet length"))?;

        if total_len != input.len() {
            let reason = if total_len > input.len() {
                "payload length exceeds available bytes"
            } else {
                "payload length is smaller than available bytes"
            };
            return Err(packet_error("IPv6", reason));
        }

        Ok(Self {
            bytes: input.to_vec(),
            payload_offset: 40,
            payload_len,
        })
    }

    /// Returns the IPv6 next header value.
    #[must_use]
    pub fn next_header(&self) -> u8 {
        self.bytes[6]
    }

    /// Returns the IPv6 payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..self.payload_offset + self.payload_len]
    }

    /// Serializes this packet to bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

fn packet_error(protocol: &'static str, reason: impl Into<String>) -> SchcError {
    SchcError::Packet {
        protocol,
        reason: reason.into(),
    }
}
