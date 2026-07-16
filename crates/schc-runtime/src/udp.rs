//! Blocking UDP transport for one-node SCHC packet harnesses.

use crate::{EncodedResult, Node, RuntimeError};
use schc_core::{packet::Ipv6Packet, RuleId, SchcError};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use thiserror::Error;

const RECEIVE_BUFFER_BYTES: usize = 65_535;

/// Explicit socket addresses for the two UDP boundaries.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpTransportConfig {
    /// Local address for the SCHC link socket.
    pub link_bind: SocketAddr,
    /// Expected peer address for SCHC link datagrams and destination for sends.
    pub link_peer: SocketAddr,
    /// Local address receiving complete IPv6 packet datagrams.
    pub packet_ingress_bind: SocketAddr,
    /// Destination receiving reconstructed complete IPv6 packet datagrams.
    pub packet_output_peer: SocketAddr,
}

/// Whether a report describes application packet compression or decompression.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UdpOperation {
    /// Packet ingress was compressed and sent on the SCHC link.
    Outbound,
    /// A SCHC link datagram was decompressed and sent to packet output.
    Inbound,
}

/// Byte counts and `RuleID` for one blocking UDP operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpReport {
    /// Operation represented by this report.
    pub operation: UdpOperation,
    /// `RuleID` selected or matched by SCHC processing.
    pub rule_id: RuleId,
    /// Number of bytes received at the operation's input boundary.
    pub received_bytes: usize,
    /// Number of bytes sent at the operation's output boundary.
    pub sent_bytes: usize,
}

/// Errors returned by the blocking UDP transport.
#[derive(Debug, Error)]
pub enum UdpError {
    /// A socket operation failed.
    #[error("UDP socket operation failed: {0}")]
    Io(#[from] io::Error),
    /// The packet harness input was not exactly one complete IPv6 packet.
    #[error("packet harness datagram is not one complete IPv6 packet: {0}")]
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
    /// The operating system reported a short UDP send.
    #[error("short UDP datagram send: expected {expected} bytes, sent {actual}")]
    ShortSend {
        /// Number of bytes in the supplied datagram.
        expected: usize,
        /// Number of bytes accepted by the socket.
        actual: usize,
    },
}

/// A blocking two-boundary UDP transport around one public [`Node`].
#[derive(Debug)]
pub struct UdpTransport {
    node: Node,
    link_socket: UdpSocket,
    packet_ingress: UdpSocket,
    config: UdpTransportConfig,
}

impl UdpTransport {
    /// Binds the link and packet-ingress sockets for one node.
    ///
    /// The link socket remains unconnected so [`Self::inbound_once`] can report
    /// an unexpected source address explicitly. The configured peer is still
    /// used for every link send and checked for every link receive.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when either socket cannot be bound.
    pub fn bind(node: Node, config: UdpTransportConfig) -> Result<Self, UdpError> {
        let link_socket = UdpSocket::bind(config.link_bind)?;
        let packet_ingress = UdpSocket::bind(config.packet_ingress_bind)?;
        let config = UdpTransportConfig {
            link_bind: link_socket.local_addr()?,
            packet_ingress_bind: packet_ingress.local_addr()?,
            ..config
        };
        Self::from_sockets(node, link_socket, packet_ingress, config)
    }

    /// Creates a transport from sockets that the caller already bound.
    ///
    /// This constructor lets callers reserve port-zero sockets before building
    /// a connected test topology, avoiding close-and-rebind address races.
    /// The configured local addresses must match the supplied sockets.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::SocketAddressMismatch`] when a supplied socket does
    /// not match its configured local address.
    pub fn from_sockets(
        node: Node,
        link_socket: UdpSocket,
        packet_ingress: UdpSocket,
        config: UdpTransportConfig,
    ) -> Result<Self, UdpError> {
        let actual_link = link_socket.local_addr()?;
        if actual_link != config.link_bind {
            return Err(UdpError::SocketAddressMismatch {
                configured: config.link_bind,
                actual: actual_link,
            });
        }
        let actual_ingress = packet_ingress.local_addr()?;
        if actual_ingress != config.packet_ingress_bind {
            return Err(UdpError::SocketAddressMismatch {
                configured: config.packet_ingress_bind,
                actual: actual_ingress,
            });
        }
        Ok(Self {
            node,
            link_socket,
            packet_ingress,
            config,
        })
    }

    /// Returns the address currently bound to the SCHC link socket.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket address cannot be queried.
    pub fn link_local_addr(&self) -> Result<SocketAddr, UdpError> {
        Ok(self.link_socket.local_addr()?)
    }

    /// Returns the address currently bound to the packet-ingress socket.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket address cannot be queried.
    pub fn packet_ingress_local_addr(&self) -> Result<SocketAddr, UdpError> {
        Ok(self.packet_ingress.local_addr()?)
    }

    /// Returns the configured link peer.
    #[must_use]
    pub const fn link_peer(&self) -> SocketAddr {
        self.config.link_peer
    }

    /// Returns the configured packet-output peer.
    #[must_use]
    pub const fn packet_output_peer(&self) -> SocketAddr {
        self.config.packet_output_peer
    }

    /// Configures a read timeout on both operation sockets.
    ///
    /// This is primarily useful for deterministic tests and callers that need
    /// a bounded blocking operation. A `None` timeout restores blocking mode.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when either timeout cannot be applied.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), UdpError> {
        self.link_socket.set_read_timeout(timeout)?;
        self.packet_ingress.set_read_timeout(timeout)?;
        Ok(())
    }

    /// Receives one complete IPv6 packet, compresses it, and sends one raw
    /// padded SCHC Packet to the configured link peer.
    ///
    /// The link datagram is exactly `EncodedResult::frame().bytes()`.
    ///
    /// # Errors
    ///
    /// Returns an error when ingress is malformed, SCHC processing fails, or
    /// the link send fails.
    pub fn outbound_once(&self) -> Result<UdpReport, UdpError> {
        let mut packet = vec![0_u8; RECEIVE_BUFFER_BYTES];
        let (received_bytes, _) = self.packet_ingress.recv_from(&mut packet)?;
        let packet = &packet[..received_bytes];
        Ipv6Packet::parse(packet).map_err(UdpError::InvalidIpv6)?;

        let encoded: EncodedResult = self.node.outbound(packet)?;
        let link_bytes = encoded.frame().bytes();
        let sent_bytes = self
            .link_socket
            .send_to(link_bytes, self.config.link_peer)?;
        if sent_bytes != link_bytes.len() {
            return Err(UdpError::ShortSend {
                expected: link_bytes.len(),
                actual: sent_bytes,
            });
        }
        Ok(UdpReport {
            operation: UdpOperation::Outbound,
            rule_id: encoded.rule_id(),
            received_bytes,
            sent_bytes,
        })
    }

    /// Receives one raw padded SCHC Packet from the configured link peer,
    /// reconstructs one IPv6 packet, and sends it to packet output.
    ///
    /// No direction or identity is inferred from packet addresses.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::UnexpectedLinkPeer`] before SCHC processing when the
    /// datagram source does not equal the configured link peer.
    pub fn inbound_once(&self) -> Result<UdpReport, UdpError> {
        let mut compressed = vec![0_u8; RECEIVE_BUFFER_BYTES];
        let (received_bytes, source) = self.link_socket.recv_from(&mut compressed)?;
        if source != self.config.link_peer {
            return Err(UdpError::UnexpectedLinkPeer {
                expected: self.config.link_peer,
                actual: source,
            });
        }

        let decoded = self.node.inbound(&compressed[..received_bytes])?;
        Ipv6Packet::parse(decoded.packet()).map_err(UdpError::InvalidIpv6)?;
        let sent_bytes = self
            .packet_ingress
            .send_to(decoded.packet(), self.config.packet_output_peer)?;
        if sent_bytes != decoded.packet().len() {
            return Err(UdpError::ShortSend {
                expected: decoded.packet().len(),
                actual: sent_bytes,
            });
        }
        Ok(UdpReport {
            operation: UdpOperation::Inbound,
            rule_id: decoded.rule_id(),
            received_bytes,
            sent_bytes,
        })
    }
}
