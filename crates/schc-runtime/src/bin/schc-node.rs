#![forbid(unsafe_code)]

use clap::{ArgGroup, Parser, ValueEnum};
use schc_core::{RuleContext, SidRegistry};
#[cfg(target_os = "linux")]
use schc_runtime::linux_tun::{LinuxTunConfig, LinuxTunDevice};
#[cfg(target_os = "linux")]
use schc_runtime::packet::{
    PacketDeviceError, PacketReport, PacketTransport, PacketTransportConfig, PacketTransportError,
};
use schc_runtime::udp::{UdpError, UdpReport, UdpTransport, UdpTransportConfig};
use schc_runtime::{DeviceId, DeviceProfile, Node, NodeRole, Runtime};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum Role {
    Core,
    Device,
}

impl Role {
    const fn node_role(self) -> NodeRole {
        match self {
            Self::Core => NodeRole::Core,
            Self::Device => NodeRole::Device,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Device => "device",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "schc-node",
    about = "Run one standalone SCHC node over a raw UDP link",
    group(
        ArgGroup::new("packet-boundary")
            .required(true)
            .multiple(false)
            .args(["tun_name", "packet_ingress_bind"])
    )
)]
struct Cli {
    /// Local node role.
    #[arg(long, value_enum)]
    role: Role,
    /// Path to the explicit SID registry JSON document.
    #[arg(long, value_name = "PATH")]
    sid: PathBuf,
    /// Path to the explicit Set of Rules CBOR document.
    #[arg(long, value_name = "PATH")]
    sor: PathBuf,
    /// Local device identifier.
    #[arg(long, value_name = "ID")]
    device_id: String,
    /// Local SCHC link UDP address.
    #[arg(long, value_name = "ADDR")]
    link_bind: SocketAddr,
    /// Expected peer SCHC link UDP address.
    #[arg(long, value_name = "ADDR")]
    link_peer: SocketAddr,
    /// Local UDP address for complete IPv6 packet ingress.
    #[arg(
        long,
        value_name = "ADDR",
        requires = "packet_output_peer",
        conflicts_with = "tun_name",
        group = "packet-boundary"
    )]
    packet_ingress_bind: Option<SocketAddr>,
    /// UDP destination for reconstructed complete IPv6 packets.
    #[arg(
        long,
        value_name = "ADDR",
        requires = "packet_ingress_bind",
        conflicts_with = "tun_name"
    )]
    packet_output_peer: Option<SocketAddr>,
    /// Explicit Linux TUN interface name, selecting packet-device mode.
    #[arg(
        long,
        value_name = "NAME",
        conflicts_with_all = ["packet_ingress_bind", "packet_output_peer"],
        group = "packet-boundary"
    )]
    tun_name: Option<String>,
    /// Linux TUN MTU. Defaults to 1280 in TUN mode.
    #[arg(
        long,
        value_name = "MTU",
        value_parser = parse_tun_mtu,
        conflicts_with_all = ["packet_ingress_bind", "packet_output_peer"]
    )]
    tun_mtu: Option<u16>,
    /// Optional exact eight-byte Device IID, encoded as 16 hexadecimal digits.
    #[arg(long, value_name = "HEX", value_parser = parse_iid::parse)]
    device_iid: Option<parse_iid::Iid>,
    /// Optional exact eight-byte Application IID, encoded as 16 hexadecimal digits.
    #[arg(long, value_name = "HEX", value_parser = parse_iid::parse)]
    application_iid: Option<parse_iid::Iid>,
    /// Exit after this many successful compress or decompress operations.
    #[arg(long, value_name = "COUNT")]
    operation_limit: Option<usize>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum PacketMode {
    Udp {
        packet_ingress_bind: SocketAddr,
        packet_output_peer: SocketAddr,
    },
    Tun {
        name: String,
        mtu: u16,
    },
}

impl Cli {
    fn packet_mode(&self) -> Result<PacketMode, String> {
        match (
            &self.tun_name,
            self.packet_ingress_bind,
            self.packet_output_peer,
        ) {
            (Some(name), None, None) => Ok(PacketMode::Tun {
                name: name.clone(),
                mtu: self.tun_mtu.unwrap_or(1_280),
            }),
            (None, Some(packet_ingress_bind), Some(packet_output_peer))
                if self.tun_mtu.is_none() =>
            {
                Ok(PacketMode::Udp {
                    packet_ingress_bind,
                    packet_output_peer,
                })
            }
            _ => Err(
                "choose either --tun-name or both --packet-ingress-bind and --packet-output-peer"
                    .to_owned(),
            ),
        }
    }
}

fn parse_tun_mtu(value: &str) -> Result<u16, String> {
    let mtu = value
        .parse::<u16>()
        .map_err(|error| format!("TUN MTU must be an unsigned 16-bit integer: {error}"))?;
    if mtu < 1_280 {
        return Err("TUN MTU must be at least 1280 for IPv6".to_owned());
    }
    Ok(mtu)
}

mod parse_iid {
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct Iid(pub [u8; 8]);

    pub fn parse(value: &str) -> Result<Iid, String> {
        if value.len() != 16 {
            return Err(format!(
                "IID must contain exactly 16 hexadecimal digits (8 bytes), got {}",
                value.len()
            ));
        }
        let bytes = value.as_bytes();
        let mut output = [0_u8; 8];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = digit(pair[0])
                .ok_or_else(|| format!("IID contains non-hexadecimal character at byte {index}"))?;
            let low = digit(pair[1]).ok_or_else(|| {
                format!(
                    "IID contains non-hexadecimal character at byte {}",
                    index + 1
                )
            })?;
            output[index] = (high << 4) | low;
        }
        Ok(Iid(output))
    }

    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-node: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let packet_mode = cli.packet_mode()?;
    let role = cli.role;
    let device_id = DeviceId::new(cli.device_id)?;
    let sid = SidRegistry::load_path(cli.sid)?;
    let sor = std::fs::read(cli.sor)?;
    let context = RuleContext::from_cbor_slice(&sor, sid)?;
    let profile = DeviceProfile::new(
        cli.device_iid.map(|iid| iid.0),
        cli.application_iid.map(|iid| iid.0),
    );
    let runtime = Runtime::new(device_id, context, profile)?;
    let node = Node::new(runtime, role.node_role());
    match packet_mode {
        PacketMode::Udp {
            packet_ingress_bind,
            packet_output_peer,
        } => run_udp_mode(
            node,
            role,
            cli.link_bind,
            cli.link_peer,
            packet_ingress_bind,
            packet_output_peer,
            cli.operation_limit,
        ),
        PacketMode::Tun { name, mtu } => run_tun_mode(
            node,
            role,
            cli.link_bind,
            cli.link_peer,
            name,
            mtu,
            cli.operation_limit,
        ),
    }
}

fn run_udp_mode(
    node: Node,
    role: Role,
    link_bind: SocketAddr,
    link_peer: SocketAddr,
    packet_ingress_bind: SocketAddr,
    packet_output_peer: SocketAddr,
    operation_limit: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    let config = UdpTransportConfig {
        link_bind,
        link_peer,
        packet_ingress_bind,
        packet_output_peer,
    };
    let transport = UdpTransport::bind(node, config)?;
    transport.set_read_timeout(Some(READ_TIMEOUT))?;

    println!(
        "READY role={} link_bind={} packet_ingress_bind={} link_peer={} packet_output_peer={}",
        role.name(),
        transport.link_local_addr()?,
        transport.packet_ingress_local_addr()?,
        transport.link_peer(),
        transport.packet_output_peer(),
    );
    io::Write::flush(&mut io::stdout())?;
    run_udp_loop(&transport, operation_limit)
}

fn run_udp_loop(
    transport: &UdpTransport,
    operation_limit: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    let mut successful_operations = 0_usize;
    if operation_limit == Some(0) {
        return Ok(());
    }

    loop {
        successful_operations =
            run_udp_one("outbound", transport.outbound_once(), successful_operations)?;
        if reached_limit(successful_operations, operation_limit) {
            return Ok(());
        }

        successful_operations =
            run_udp_one("inbound", transport.inbound_once(), successful_operations)?;
        if reached_limit(successful_operations, operation_limit) {
            return Ok(());
        }
    }
}

fn run_udp_one(
    label: &str,
    result: Result<UdpReport, UdpError>,
    successful_operations: usize,
) -> Result<usize, Box<dyn Error>> {
    match result {
        Ok(report) => {
            print_report(
                label,
                report.rule_id,
                report.received_bytes,
                report.sent_bytes,
            );
            Ok(successful_operations + 1)
        }
        Err(error) if is_timeout(&error) => Ok(successful_operations),
        Err(error) if is_recoverable(&error) => {
            eprintln!("drop operation={label}: {error}");
            Ok(successful_operations)
        }
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(target_os = "linux")]
fn run_tun_mode(
    node: Node,
    role: Role,
    link_bind: SocketAddr,
    link_peer: SocketAddr,
    name: String,
    mtu: u16,
    operation_limit: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    let device = LinuxTunDevice::create(LinuxTunConfig::new(name, mtu))?;
    let actual_name = device.interface_name().to_owned();
    let config = PacketTransportConfig {
        link_bind,
        link_peer,
    };
    let mut transport = PacketTransport::bind(node, device, config)?;
    transport.set_read_timeout(Some(READ_TIMEOUT))?;

    println!(
        "READY role={} tun_name={} mtu={} link_bind={} link_peer={}",
        role.name(),
        actual_name,
        mtu,
        transport.link_local_addr()?,
        transport.link_peer(),
    );
    io::Write::flush(&mut io::stdout())?;
    run_tun_loop(&mut transport, operation_limit)
}

#[cfg(not(target_os = "linux"))]
fn run_tun_mode(
    _node: Node,
    _role: Role,
    _link_bind: SocketAddr,
    _link_peer: SocketAddr,
    _name: String,
    _mtu: u16,
    _operation_limit: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    Err("TUN packet-device mode is only supported on Linux".into())
}

#[cfg(target_os = "linux")]
fn run_tun_loop(
    transport: &mut PacketTransport<LinuxTunDevice>,
    operation_limit: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    let mut successful_operations = 0_usize;
    if operation_limit == Some(0) {
        return Ok(());
    }

    loop {
        successful_operations =
            run_tun_one("outbound", transport.outbound_once(), successful_operations)?;
        if reached_limit(successful_operations, operation_limit) {
            return Ok(());
        }

        successful_operations =
            run_tun_one("inbound", transport.inbound_once(), successful_operations)?;
        if reached_limit(successful_operations, operation_limit) {
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
fn run_tun_one(
    label: &str,
    result: Result<PacketReport, PacketTransportError>,
    successful_operations: usize,
) -> Result<usize, Box<dyn Error>> {
    match result {
        Ok(report) => {
            print_report(
                label,
                report.rule_id,
                report.received_bytes,
                report.sent_bytes,
            );
            Ok(successful_operations + 1)
        }
        Err(error) if is_packet_timeout(label, &error) => Ok(successful_operations),
        Err(error) if is_packet_recoverable(&error) => {
            eprintln!("drop operation={label}: {error}");
            Ok(successful_operations)
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn print_report(label: &str, rule_id: schc_core::RuleId, received_bytes: usize, sent_bytes: usize) {
    eprintln!("operation={label} rule_id={rule_id:?} received={received_bytes} sent={sent_bytes}");
}

fn reached_limit(successful_operations: usize, operation_limit: Option<usize>) -> bool {
    operation_limit.is_some_and(|limit| successful_operations >= limit)
}

fn is_timeout(error: &UdpError) -> bool {
    matches!(
        error,
        UdpError::Io(source)
            if matches!(source.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
    )
}

fn is_recoverable(error: &UdpError) -> bool {
    matches!(
        error,
        UdpError::InvalidIpv6(_) | UdpError::Runtime(_) | UdpError::UnexpectedLinkPeer { .. }
    )
}

#[cfg(target_os = "linux")]
fn is_packet_timeout(operation: &str, error: &PacketTransportError) -> bool {
    let kind = match error {
        PacketTransportError::Io(source) => source.kind(),
        PacketTransportError::Device(PacketDeviceError::Io(source)) if operation == "outbound" => {
            source.kind()
        }
        _ => return false,
    };
    matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

#[cfg(target_os = "linux")]
fn is_packet_recoverable(error: &PacketTransportError) -> bool {
    matches!(
        error,
        PacketTransportError::InvalidIpv6(_)
            | PacketTransportError::Runtime(_)
            | PacketTransportError::UnexpectedLinkPeer { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn valid_args() -> Vec<&'static str> {
        vec![
            "schc-node",
            "--role",
            "device",
            "--sid",
            "sid.json",
            "--sor",
            "rules.sor",
            "--device-id",
            "local-device",
            "--link-bind",
            "127.0.0.1:10000",
            "--link-peer",
            "127.0.0.1:10001",
            "--packet-ingress-bind",
            "127.0.0.1:10002",
            "--packet-output-peer",
            "127.0.0.1:10003",
        ]
    }

    fn valid_tun_args() -> Vec<&'static str> {
        vec![
            "schc-node",
            "--role",
            "device",
            "--sid",
            "sid.json",
            "--sor",
            "rules.sor",
            "--device-id",
            "local-device",
            "--link-bind",
            "127.0.0.1:10000",
            "--link-peer",
            "127.0.0.1:10001",
            "--tun-name",
            "schc-test0",
        ]
    }

    #[test]
    fn parses_role_and_all_explicit_addresses() {
        let cli = Cli::try_parse_from(valid_args()).unwrap();
        assert_eq!(cli.role, Role::Device);
        assert_eq!(cli.link_bind, "127.0.0.1:10000".parse().unwrap());
        assert_eq!(cli.link_peer, "127.0.0.1:10001".parse().unwrap());
        assert_eq!(
            cli.packet_ingress_bind,
            Some("127.0.0.1:10002".parse().unwrap())
        );
        assert_eq!(
            cli.packet_output_peer,
            Some("127.0.0.1:10003".parse().unwrap())
        );
        assert_eq!(cli.tun_name, None);
        assert_eq!(cli.tun_mtu, None);
        assert_eq!(cli.operation_limit, None);
        assert!(matches!(cli.packet_mode(), Ok(PacketMode::Udp { .. })));
    }

    #[test]
    fn parses_tun_mode_with_default_ipv6_mtu() {
        let cli = Cli::try_parse_from(valid_tun_args()).unwrap();
        assert_eq!(cli.packet_ingress_bind, None);
        assert_eq!(cli.packet_output_peer, None);
        assert_eq!(
            cli.packet_mode(),
            Ok(PacketMode::Tun {
                name: "schc-test0".to_owned(),
                mtu: 1_280,
            })
        );
    }

    #[test]
    fn requires_role_paths_identity_and_addresses() {
        assert!(Cli::try_parse_from(["schc-node"]).is_err());
    }

    #[test]
    fn rejects_mixed_packet_boundary_modes() {
        let mut args = valid_tun_args();
        args.extend([
            "--packet-ingress-bind",
            "127.0.0.1:10002",
            "--packet-output-peer",
            "127.0.0.1:10003",
        ]);
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn rejects_partial_udp_packet_boundary_mode() {
        let mut args = valid_args();
        args.truncate(args.len() - 2);
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn rejects_tun_mtu_outside_tun_mode() {
        let mut args = valid_args();
        args.extend(["--tun-mtu", "1280"]);
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn rejects_non_ipv6_tun_mtu() {
        let mut args = valid_tun_args();
        args.extend(["--tun-mtu", "1279"]);
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifies_packet_device_timeout_as_idle() {
        let timeout = PacketTransportError::Device(PacketDeviceError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "idle",
        )));
        let failure = PacketTransportError::Device(PacketDeviceError::Io(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "closed",
        )));
        assert!(is_packet_timeout("outbound", &timeout));
        assert!(!is_packet_timeout("inbound", &timeout));
        assert!(!is_packet_timeout("outbound", &failure));
    }

    #[test]
    fn parses_exact_iids_and_operation_limit() {
        let mut args = valid_args();
        args[2] = "core";
        args.extend([
            "--device-iid",
            "0000000000000001",
            "--application-iid",
            "AABBCCDDEEFF0011",
            "--operation-limit",
            "7",
        ]);
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.role, Role::Core);
        assert_eq!(cli.device_iid.unwrap().0, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            cli.application_iid.unwrap().0,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0x11]
        );
        assert_eq!(cli.operation_limit, Some(7));
    }

    #[test]
    fn rejects_malformed_iids_and_operation_limit() {
        let mut short = valid_args();
        short.extend(["--device-iid", "0011"]);
        assert!(Cli::try_parse_from(short).is_err());

        let mut invalid_hex = valid_args();
        invalid_hex.extend(["--application-iid", "00000000000000xz"]);
        assert!(Cli::try_parse_from(invalid_hex).is_err());

        let mut invalid_limit = valid_args();
        invalid_limit.extend(["--operation-limit", "not-a-number"]);
        assert!(Cli::try_parse_from(invalid_limit).is_err());
    }

    #[test]
    fn iid_parser_rejects_non_ascii_without_panicking() {
        let error = parse_iid::parse("00000000000000é").unwrap_err();
        assert!(error.contains("non-hexadecimal"));
    }
}
