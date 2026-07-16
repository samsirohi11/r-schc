use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const STARTUP_ATTEMPTS: usize = 8;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_TIMEOUT: Duration = Duration::from_secs(5);

struct Topology {
    device_link: Option<UdpSocket>,
    core_link: Option<UdpSocket>,
    device_ingress: Option<UdpSocket>,
    core_ingress: Option<UdpSocket>,
    device_link_addr: SocketAddr,
    core_link_addr: SocketAddr,
    device_ingress_addr: SocketAddr,
    core_ingress_addr: SocketAddr,
    device_output: UdpSocket,
    core_output: UdpSocket,
    device_output_addr: SocketAddr,
    core_output_addr: SocketAddr,
}

fn reserve_topology() -> io::Result<Topology> {
    let (device_link, device_link_addr) = reserve_socket()?;
    let (core_link, core_link_addr) = reserve_socket()?;
    let (device_ingress, device_ingress_addr) = reserve_socket()?;
    let (core_ingress, core_ingress_addr) = reserve_socket()?;
    let (device_output, device_output_addr) = reserve_output_socket()?;
    let (core_output, core_output_addr) = reserve_output_socket()?;
    Ok(Topology {
        device_link: Some(device_link),
        core_link: Some(core_link),
        device_ingress: Some(device_ingress),
        core_ingress: Some(core_ingress),
        device_link_addr,
        core_link_addr,
        device_ingress_addr,
        core_ingress_addr,
        device_output,
        core_output,
        device_output_addr,
        core_output_addr,
    })
}

fn reserve_socket() -> io::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    Ok((socket, address))
}

fn reserve_output_socket() -> io::Result<(UdpSocket, SocketAddr)> {
    let (socket, address) = reserve_socket()?;
    socket.set_read_timeout(Some(OUTPUT_TIMEOUT))?;
    Ok((socket, address))
}

struct ChildReport {
    status: ExitStatus,
    stderr: String,
}

struct ChildPair {
    device: Option<Child>,
    core: Option<Child>,
}

impl ChildPair {
    fn new() -> Self {
        Self {
            device: None,
            core: None,
        }
    }

    fn set_device(&mut self, child: Child) {
        debug_assert!(self.device.is_none());
        self.device = Some(child);
    }

    fn set_core(&mut self, child: Child) {
        debug_assert!(self.core.is_none());
        self.core = Some(child);
    }

    fn device_mut(&mut self) -> Option<&mut Child> {
        self.device.as_mut()
    }

    fn core_mut(&mut self) -> Option<&mut Child> {
        self.core.as_mut()
    }

    fn wait_all(&mut self) -> io::Result<(ChildReport, ChildReport)> {
        let device = wait_child(self.device.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "device child was not started")
        })?)?;
        let core = wait_child(self.core.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "core child was not started")
        })?)?;

        if device.status.success() && core.status.success() {
            self.device.take();
            self.core.take();
        }
        Ok((device, core))
    }
}

impl Drop for ChildPair {
    fn drop(&mut self) {
        for child in [&mut self.device, &mut self.core] {
            let Some(child) = child.as_mut() else {
                continue;
            };
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn start_pair() -> Result<(Topology, ChildPair, String, String), String> {
    let mut last_error = String::new();
    for attempt in 1..=STARTUP_ATTEMPTS {
        let Ok(mut topology) = reserve_topology() else {
            last_error = format!("attempt {attempt}: could not reserve UDP topology");
            continue;
        };
        let mut children = ChildPair::new();

        // The CLI intentionally reports actual addresses but cannot receive
        // inherited descriptors. Keep the peer and output sockets reserved,
        // release each child's two local sockets immediately before spawning,
        // and retry the complete startup a bounded number of times if another
        // process wins the tiny close/rebind window.
        drop(topology.device_link.take());
        drop(topology.device_ingress.take());
        let device = match spawn_node("device", &topology, 2) {
            Ok(child) => child,
            Err(error) => {
                last_error = format!("attempt {attempt}: device spawn failed: {error}");
                continue;
            }
        };
        children.set_device(device);
        let device_ready = match children.device_mut() {
            Some(child) => wait_ready(child),
            None => Err("device child was not stored".to_owned()),
        };
        let device_ready = match device_ready {
            Ok(line) => line,
            Err(error) => {
                last_error = format!("attempt {attempt}: device readiness failed: {error}");
                continue;
            }
        };

        drop(topology.core_link.take());
        drop(topology.core_ingress.take());
        let core = match spawn_node("core", &topology, 2) {
            Ok(child) => child,
            Err(error) => {
                last_error = format!("attempt {attempt}: core spawn failed: {error}");
                continue;
            }
        };
        children.set_core(core);
        let core_ready = match children.core_mut() {
            Some(child) => wait_ready(child),
            None => Err("core child was not stored".to_owned()),
        };
        let core_ready = match core_ready {
            Ok(line) => line,
            Err(error) => {
                last_error = format!("attempt {attempt}: core readiness failed: {error}");
                continue;
            }
        };
        return Ok((topology, children, device_ready, core_ready));
    }
    Err(format!(
        "no two-process topology became ready after {STARTUP_ATTEMPTS} attempts: {last_error}"
    ))
}

fn spawn_node(role: &str, topology: &Topology, operation_limit: usize) -> io::Result<Child> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sid = manifest.join("../../fixtures/core/ietf-schc@2026-05-07.sid");
    let sor = manifest.join("../../fixtures/core/core.sor");
    let (link_bind, link_peer, packet_ingress_bind, packet_output_peer) = match role {
        "device" => (
            topology.device_link_addr,
            topology.core_link_addr,
            topology.device_ingress_addr,
            topology.device_output_addr,
        ),
        "core" => (
            topology.core_link_addr,
            topology.device_link_addr,
            topology.core_ingress_addr,
            topology.core_output_addr,
        ),
        _ => unreachable!("test supplied an invalid role"),
    };
    Command::new(env!("CARGO_BIN_EXE_schc-node"))
        .args([
            "--role",
            role,
            "--sid",
            sid.to_str().expect("fixture path is UTF-8"),
            "--sor",
            sor.to_str().expect("fixture path is UTF-8"),
            "--device-id",
            "process-test-device",
            "--link-bind",
            &link_bind.to_string(),
            "--link-peer",
            &link_peer.to_string(),
            "--packet-ingress-bind",
            &packet_ingress_bind.to_string(),
            "--packet-output-peer",
            &packet_output_peer.to_string(),
            "--device-iid",
            "0000000000000001",
            "--application-iid",
            "0000000000000002",
            "--operation-limit",
            &operation_limit.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

fn wait_ready(child: &mut Child) -> Result<String, String> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout was not piped".to_owned())?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout)
            .read_line(&mut line)
            .map(|bytes| (bytes, line))
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(STARTUP_TIMEOUT) {
        Ok(Ok((bytes, line))) if bytes > 0 && line.starts_with("READY ") => Ok(line),
        Ok(Ok((_bytes, line))) => Err(format!("unexpected readiness output: {line:?}")),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(format!("timed out waiting for readiness: {error}")),
    }
}

fn wait_child(child: &mut Child) -> io::Result<ChildReport> {
    let status = child.wait()?;
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        use std::io::Read;
        stream.read_to_string(&mut stderr)?;
    }
    Ok(ChildReport { status, stderr })
}

fn packet(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("canonical packet hex is valid")
}

#[test]
fn two_processes_exchange_exact_ipv6_packets_in_both_directions() {
    let (topology, mut children, device_ready, core_ready) =
        start_pair().expect("two-process SCHC topology should start");
    assert!(device_ready.contains(&format!(
        "link_bind={} packet_ingress_bind={}",
        topology.device_link_addr, topology.device_ingress_addr
    )));
    assert!(core_ready.contains(&format!(
        "link_bind={} packet_ingress_bind={}",
        topology.core_link_addr, topology.core_ingress_addr
    )));

    let uplink = packet(
        "600000000015114020010db8000000000000000000000001\
         20010db80000000000000000000000021633163300156bb742011234aabbb163118dff4f4b",
    );
    let downlink = packet(
        "6000000000383a2020010db8000000000000000000000002\
         20010db8000000000000000000000001010431260000000060000000000811ff\
         20010db800000000000000000000000120010db80000000000000000000000021633163300087803",
    );
    let ingress_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let malformed = [0_u8];
    ingress_sender
        .send_to(&malformed, topology.device_ingress_addr)
        .unwrap();
    ingress_sender
        .send_to(&malformed, topology.core_ingress_addr)
        .unwrap();
    ingress_sender
        .send_to(&uplink, topology.device_ingress_addr)
        .unwrap();
    ingress_sender
        .send_to(&downlink, topology.core_ingress_addr)
        .unwrap();

    let mut received = vec![0_u8; 65_535];
    let (uplink_len, _) = topology.core_output.recv_from(&mut received).unwrap();
    assert_eq!(&received[..uplink_len], uplink.as_slice());
    let (downlink_len, _) = topology.device_output.recv_from(&mut received).unwrap();
    assert_eq!(&received[..downlink_len], downlink.as_slice());

    let (device, core) = children.wait_all().expect("children should be reapable");
    assert_eq!(
        device.status.code(),
        Some(0),
        "device stderr: {}",
        device.stderr
    );
    assert_eq!(core.status.code(), Some(0), "core stderr: {}", core.stderr);
    assert!(device.stderr.contains("drop operation=outbound"));
    assert!(core.stderr.contains("drop operation=outbound"));
}
