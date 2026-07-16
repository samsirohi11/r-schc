//! Blocking packet-device transport for one-node SCHC links.
//!
//! The [`PacketDevice`] contract is packet-oriented: each read returns one
//! complete packet and each write accepts one complete packet. It deliberately
//! does not expose stream reads, stream writes, or packet-harness sockets.

use crate::{EncodedResult, Node, RuntimeError};
use schc_core::{packet::Ipv6Packet, RuleId, SchcError};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use thiserror::Error;

const RECEIVE_BUFFER_BYTES: usize = 65_535;

/// A packet-oriented device boundary.
///
/// Implementations must preserve packet boundaries. [`Self::read_packet`]
/// returns exactly one complete packet, while [`Self::write_packet`] consumes
/// exactly one complete packet. A device that cannot return a complete packet
/// must report [`PacketDeviceError::ShortRead`] rather than returning a
/// fragment.
pub trait PacketDevice {
    /// Reads one complete packet from the device.
    ///
    /// # Errors
    ///
    /// Returns a device I/O or packet-boundary error.
    fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError>;

    /// Writes one complete packet and returns the number of bytes consumed.
    ///
    /// A count smaller than `packet.len()` is classified by
    /// [`PacketTransport`] as [`PacketTransportError::ShortWrite`].
    ///
    /// # Errors
    ///
    /// Returns a device I/O error.
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PacketDeviceError>;
}

/// Errors at a [`PacketDevice`] boundary.
#[derive(Debug, Error)]
pub enum PacketDeviceError {
    /// The device implementation reported an I/O failure.
    #[error("packet-device I/O operation failed: {0}")]
    Io(#[source] io::Error),
    /// The device could not return one complete packet.
    #[error("short packet-device read: expected {expected} bytes, received {actual}")]
    ShortRead {
        /// Number of bytes needed for the complete packet.
        expected: usize,
        /// Number of bytes received before the device reported a short read.
        actual: usize,
    },
}

impl From<io::Error> for PacketDeviceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Explicit addresses for a packet-device SCHC link.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PacketTransportConfig {
    /// Local address for the SCHC link socket.
    pub link_bind: SocketAddr,
    /// Expected peer address for SCHC link datagrams and destination for sends.
    pub link_peer: SocketAddr,
}

/// Whether a report describes packet compression or decompression.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PacketOperation {
    /// A packet-device packet was compressed and sent on the SCHC link.
    Outbound,
    /// A SCHC link datagram was decompressed and written to the packet device.
    Inbound,
}

/// Byte counts and `RuleID` for one packet-device operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PacketReport {
    /// Operation represented by this report.
    pub operation: PacketOperation,
    /// `RuleID` selected or matched by SCHC processing.
    pub rule_id: RuleId,
    /// Number of bytes received at the operation's input boundary.
    pub received_bytes: usize,
    /// Number of bytes sent at the operation's output boundary.
    pub sent_bytes: usize,
}

/// Errors returned by the packet-device SCHC transport.
#[derive(Debug, Error)]
pub enum PacketTransportError {
    /// A SCHC link socket operation failed.
    #[error("SCHC link UDP socket operation failed: {0}")]
    Io(#[source] io::Error),
    /// A packet-device operation failed.
    #[error("packet-device operation failed: {0}")]
    Device(#[source] PacketDeviceError),
    /// The packet-device input was not exactly one complete IPv6 packet.
    #[error("packet-device input is not one complete IPv6 packet: {0}")]
    InvalidIpv6(#[source] SchcError),
    /// The SCHC runtime rejected the packet.
    #[error("SCHC runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
    /// A link datagram arrived from a source other than the configured peer.
    #[error("unexpected SCHC link peer: expected {expected}, received {actual}")]
    UnexpectedLinkPeer {
        /// Configured link peer.
        expected: SocketAddr,
        /// Datagram source address.
        actual: SocketAddr,
    },
    /// A supplied socket is not bound to its configured local address.
    #[error("UDP socket local address {actual} does not match configured address {configured}")]
    SocketAddressMismatch {
        /// Address configured for the socket.
        configured: SocketAddr,
        /// Address reported by the supplied socket.
        actual: SocketAddr,
    },
    /// The operating system reported a short SCHC link send.
    #[error("short SCHC link datagram send: expected {expected} bytes, sent {actual}")]
    ShortSend {
        /// Number of bytes in the supplied datagram.
        expected: usize,
        /// Number of bytes accepted by the socket.
        actual: usize,
    },
    /// The packet device consumed fewer bytes than the reconstructed packet.
    #[error("short packet-device write: expected {expected} bytes, wrote {actual}")]
    ShortWrite {
        /// Number of bytes in the reconstructed packet.
        expected: usize,
        /// Number of bytes consumed by the device.
        actual: usize,
    },
}

impl From<PacketDeviceError> for PacketTransportError {
    fn from(error: PacketDeviceError) -> Self {
        Self::Device(error)
    }
}

/// A blocking packet-device transport around one public [`Node`].
#[derive(Debug)]
pub struct PacketTransport<D> {
    node: Node,
    device: D,
    link_socket: UdpSocket,
    config: PacketTransportConfig,
}

impl<D: PacketDevice> PacketTransport<D> {
    /// Binds the SCHC link socket for one packet-device transport.
    ///
    /// # Errors
    ///
    /// Returns a link socket error when the address cannot be bound.
    pub fn bind(
        node: Node,
        device: D,
        config: PacketTransportConfig,
    ) -> Result<Self, PacketTransportError> {
        let link_socket =
            UdpSocket::bind(config.link_bind).map_err(PacketTransportError::link_io)?;
        let config = PacketTransportConfig {
            link_bind: link_socket
                .local_addr()
                .map_err(PacketTransportError::link_io)?,
            ..config
        };
        Self::from_socket(node, device, link_socket, config)
    }

    /// Creates a transport from an already-bound SCHC link socket.
    ///
    /// The configured local address must equal the socket's actual local
    /// address. This allows tests and callers to reserve port-zero sockets
    /// before constructing a transport without a close-and-rebind race.
    ///
    /// # Errors
    ///
    /// Returns an address mismatch or socket query error.
    pub fn from_socket(
        node: Node,
        device: D,
        link_socket: UdpSocket,
        config: PacketTransportConfig,
    ) -> Result<Self, PacketTransportError> {
        let actual = link_socket
            .local_addr()
            .map_err(PacketTransportError::link_io)?;
        if actual != config.link_bind {
            return Err(PacketTransportError::SocketAddressMismatch {
                configured: config.link_bind,
                actual,
            });
        }
        Ok(Self {
            node,
            device,
            link_socket,
            config,
        })
    }

    /// Returns the address currently bound to the SCHC link socket.
    ///
    /// # Errors
    ///
    /// Returns a socket query error when the address cannot be read.
    pub fn link_local_addr(&self) -> Result<SocketAddr, PacketTransportError> {
        self.link_socket
            .local_addr()
            .map_err(PacketTransportError::link_io)
    }

    /// Returns the configured SCHC link peer.
    #[must_use]
    pub const fn link_peer(&self) -> SocketAddr {
        self.config.link_peer
    }

    /// Returns mutable access to the packet device.
    #[must_use]
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Configures a read timeout on the SCHC link socket.
    ///
    /// Packet-device read timeout behavior remains the responsibility of the
    /// supplied [`PacketDevice`] implementation.
    ///
    /// # Errors
    ///
    /// Returns a socket configuration error.
    pub fn set_read_timeout(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> Result<(), PacketTransportError> {
        self.link_socket
            .set_read_timeout(timeout)
            .map_err(PacketTransportError::link_io)
    }

    /// Reads one packet from the device, compresses it, and sends one raw
    /// padded SCHC Packet to the configured link peer.
    ///
    /// # Errors
    ///
    /// Returns a typed device, IPv6, runtime, or link-send error.
    pub fn outbound_once(&mut self) -> Result<PacketReport, PacketTransportError> {
        let packet = self.device.read_packet()?;
        let received_bytes = packet.len();
        Ipv6Packet::parse(&packet).map_err(PacketTransportError::invalid_ipv6)?;

        let encoded: EncodedResult = self.node.outbound(&packet)?;
        let frame = encoded.frame().bytes();
        let sent_bytes = self
            .link_socket
            .send_to(frame, self.config.link_peer)
            .map_err(PacketTransportError::link_io)?;
        if sent_bytes != frame.len() {
            return Err(PacketTransportError::ShortSend {
                expected: frame.len(),
                actual: sent_bytes,
            });
        }
        Ok(PacketReport {
            operation: PacketOperation::Outbound,
            rule_id: encoded.rule_id(),
            received_bytes,
            sent_bytes,
        })
    }

    /// Receives one raw padded SCHC Packet, reconstructs one IPv6 packet, and
    /// writes it to the packet device.
    ///
    /// A datagram from an unexpected peer is rejected before decompression.
    ///
    /// # Errors
    ///
    /// Returns a typed link, peer, runtime, IPv6, or device-write error.
    pub fn inbound_once(&mut self) -> Result<PacketReport, PacketTransportError> {
        let mut compressed = vec![0_u8; RECEIVE_BUFFER_BYTES];
        let (received_bytes, source) = self
            .link_socket
            .recv_from(&mut compressed)
            .map_err(PacketTransportError::link_io)?;
        if source != self.config.link_peer {
            return Err(PacketTransportError::UnexpectedLinkPeer {
                expected: self.config.link_peer,
                actual: source,
            });
        }

        let decoded = self.node.inbound(&compressed[..received_bytes])?;
        Ipv6Packet::parse(decoded.packet()).map_err(PacketTransportError::invalid_ipv6)?;
        let expected = decoded.packet().len();
        let sent_bytes = self.device.write_packet(decoded.packet())?;
        if sent_bytes != expected {
            return Err(PacketTransportError::ShortWrite {
                expected,
                actual: sent_bytes,
            });
        }
        Ok(PacketReport {
            operation: PacketOperation::Inbound,
            rule_id: decoded.rule_id(),
            received_bytes,
            sent_bytes,
        })
    }
}

impl PacketTransportError {
    fn link_io(error: io::Error) -> Self {
        Self::Io(error)
    }

    fn invalid_ipv6(error: SchcError) -> Self {
        Self::InvalidIpv6(error)
    }
}
