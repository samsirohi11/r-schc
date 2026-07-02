use crate::error::{Result, SchcError};

/// Parsed `ICMPv6` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Message {
    bytes: Vec<u8>,
    payload_offset: usize,
}

impl Icmpv6Message {
    /// Parses an `ICMPv6` message from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the input is shorter than the fixed
    /// `ICMPv6` header.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(packet_error("ICMPv6", "message shorter than 4-byte header"));
        }

        Ok(Self {
            bytes: input.to_vec(),
            payload_offset: 4,
        })
    }

    /// Returns the `ICMPv6` message type.
    #[must_use]
    pub fn message_type(&self) -> u8 {
        self.bytes[0]
    }

    /// Returns the `ICMPv6` code.
    #[must_use]
    pub fn code(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the `ICMPv6` checksum.
    #[must_use]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// Returns the `ICMPv6` payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }

    /// Serializes this message to bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Builds an `ICMPv6` message from header fields and payload.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the constructed bytes do not parse
    /// back into a valid message, which can only happen if the payload
    /// overflows the available capacity.
    pub fn from_parts(message_type: u8, code: u8, checksum: u16, payload: Vec<u8>) -> Result<Self> {
        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.push(message_type);
        bytes.push(code);
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend(payload);
        Self::parse(&bytes)
    }
}

fn packet_error(protocol: &'static str, reason: impl Into<String>) -> SchcError {
    SchcError::Packet {
        protocol,
        reason: reason.into(),
    }
}
