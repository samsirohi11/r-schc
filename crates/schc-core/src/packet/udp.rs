use crate::error::{Result, SchcError};

/// Parsed UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    bytes: Vec<u8>,
    payload_offset: usize,
}

impl UdpDatagram {
    /// Parses a UDP datagram from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the input is shorter than the UDP
    /// header, declares a length smaller than the header, or declares a length
    /// larger than the available bytes.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < 8 {
            return Err(packet_error("UDP", "datagram shorter than 8-byte header"));
        }

        let length = usize::from(u16::from_be_bytes([input[4], input[5]]));
        if length < 8 {
            return Err(packet_error("UDP", "length is smaller than 8 bytes"));
        }

        if length > input.len() {
            return Err(packet_error("UDP", "length exceeds available bytes"));
        }

        Ok(Self {
            bytes: input[..length].to_vec(),
            payload_offset: 8,
        })
    }

    /// Returns the UDP source port.
    #[must_use]
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// Returns the UDP destination port.
    #[must_use]
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// Returns the UDP payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }

    /// Serializes this datagram to bytes.
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
