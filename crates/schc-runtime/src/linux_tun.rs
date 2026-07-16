//! Linux TUN packet-device integration.
//!
//! This module uses tappers' safe Linux API to create an exclusive, temporary
//! L3 interface. It does not configure addresses or routes.

use crate::packet::{PacketDevice, PacketDeviceError};
use std::fmt;
use std::io;
use tappers::linux::Tun;
use tappers::{DeviceState, Interface};
use thiserror::Error;

/// The minimum MTU that can carry an IPv6 packet without violating the IPv6
/// minimum-link-MTU requirement.
pub const MIN_IPV6_MTU: u16 = 1_280;

/// Maximum bytes in one IPv6 packet, including its 40-byte header.
pub const MAX_IPV6_PACKET_BYTES: usize = 40 + u16::MAX as usize;

/// Configuration for one Linux L3 TUN packet device.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinuxTunConfig {
    /// Explicit Linux interface name.
    pub name: String,
    /// Interface MTU. Must be at least [`MIN_IPV6_MTU`].
    pub mtu: u16,
}

impl LinuxTunConfig {
    /// Creates a TUN configuration with an explicit name and MTU.
    #[must_use]
    pub fn new(name: impl Into<String>, mtu: u16) -> Self {
        Self {
            name: name.into(),
            mtu,
        }
    }

    fn validate(&self) -> Result<(), LinuxTunError> {
        if self.name.is_empty() {
            return Err(LinuxTunError::InvalidName);
        }
        if self.mtu < MIN_IPV6_MTU {
            return Err(LinuxTunError::InvalidMtu { mtu: self.mtu });
        }
        Ok(())
    }
}

/// Errors creating or configuring a Linux TUN device.
#[derive(Debug, Error)]
pub enum LinuxTunError {
    /// The requested interface name was empty.
    #[error("Linux TUN interface name must not be empty")]
    InvalidName,
    /// The requested MTU cannot carry the IPv6 minimum packet.
    #[error("Linux TUN MTU {mtu} is below the IPv6 minimum of {MIN_IPV6_MTU}")]
    InvalidMtu {
        /// Requested interface MTU.
        mtu: u16,
    },
    /// The interface name could not be represented by tappers.
    #[error("Linux TUN interface name is invalid: {source}")]
    InterfaceName {
        /// Name-construction error reported by the platform API.
        #[source]
        source: io::Error,
    },
    /// A Linux TUN operation failed.
    #[error("Linux TUN {operation} failed: {source}")]
    Operation {
        /// Device operation being performed.
        operation: &'static str,
        /// Operating-system error reported by tappers.
        #[source]
        source: io::Error,
    },
}

/// One Linux L3 TUN interface implementing the packet-device contract.
pub struct LinuxTunDevice {
    device: Tun,
    interface_name: String,
    mtu: u16,
}

impl fmt::Debug for LinuxTunDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxTunDevice")
            .field("interface_name", &self.interface_name)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl LinuxTunDevice {
    /// Creates and brings up one exclusive, nonpersistent Linux L3 TUN
    /// interface.
    ///
    /// The Linux TUN API uses `IFF_NO_PI`, so packets contain no packet-info
    /// header. The device is made nonblocking so an idle read returns
    /// `WouldBlock`; the surrounding node loop uses the link socket timeout to
    /// remain bounded. No IPv6 addresses or routes are configured here.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, name, creation, or configuration error.
    pub fn create(config: LinuxTunConfig) -> Result<Self, LinuxTunError> {
        config.validate()?;
        let LinuxTunConfig { name, mtu } = config;
        let interface =
            Interface::new(&name).map_err(|source| LinuxTunError::InterfaceName { source })?;
        let device = Tun::create_named(interface)
            .map_err(|source| LinuxTunError::operation("create interface", source))?;
        device
            .set_mtu(usize::from(mtu))
            .map_err(|source| LinuxTunError::operation("set MTU", source))?;
        device
            .set_state(DeviceState::Up)
            .map_err(|source| LinuxTunError::operation("bring interface up", source))?;
        device
            .set_nonblocking(true)
            .map_err(|source| LinuxTunError::operation("set nonblocking", source))?;
        let actual_name = device
            .name()
            .map_err(|source| LinuxTunError::operation("query interface name", source))?
            .name()
            .to_string_lossy()
            .into_owned();

        Ok(Self {
            device,
            interface_name: actual_name,
            mtu,
        })
    }

    /// Returns the actual interface name reported by Linux.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Returns the configured interface MTU.
    #[must_use]
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl LinuxTunError {
    fn operation(operation: &'static str, source: io::Error) -> Self {
        Self::Operation { operation, source }
    }
}

impl PacketDevice for LinuxTunDevice {
    fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError> {
        let mut packet = vec![0_u8; MAX_IPV6_PACKET_BYTES];
        let received = self
            .device
            .recv(&mut packet)
            .map_err(PacketDeviceError::Io)?;
        packet.truncate(received);
        Ok(packet)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PacketDeviceError> {
        self.device.send(packet).map_err(PacketDeviceError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_interface_name_without_opening_tun() {
        let error = LinuxTunConfig::new("", MIN_IPV6_MTU)
            .validate()
            .unwrap_err();
        assert!(matches!(error, LinuxTunError::InvalidName));
    }

    #[test]
    fn rejects_mtu_below_ipv6_minimum_without_opening_tun() {
        let error = LinuxTunConfig::new("schc-test", MIN_IPV6_MTU - 1)
            .validate()
            .unwrap_err();
        assert!(matches!(error, LinuxTunError::InvalidMtu { mtu } if mtu == MIN_IPV6_MTU - 1));
    }

    #[test]
    fn packet_buffer_covers_maximum_ipv6_packet() {
        let buffer = vec![0_u8; MAX_IPV6_PACKET_BYTES];
        assert!(buffer.len() >= 65_575);
    }

    #[test]
    fn nonblocking_idle_error_keeps_would_block_classification() {
        let error: PacketDeviceError = io::Error::from(io::ErrorKind::WouldBlock).into();
        assert!(matches!(
            error,
            PacketDeviceError::Io(source) if source.kind() == io::ErrorKind::WouldBlock
        ));
    }
}
