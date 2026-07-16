#![cfg(target_os = "linux")]

use schc_runtime::linux_tun::{LinuxTunConfig, LinuxTunDevice, MIN_IPV6_MTU};

/// Creates a real TUN interface only when explicitly opted in by the caller.
///
/// Default CI skips this privilege-dependent check and therefore does not
/// claim Linux TUN creation coverage.
#[test]
fn linux_tun_creation_smoke_when_opted_in() {
    if std::env::var_os("R_SCHC_RUN_TUN_SMOKE").is_none() {
        eprintln!("skipping privileged Linux TUN smoke; set R_SCHC_RUN_TUN_SMOKE=1");
        return;
    }

    let name = std::env::var("R_SCHC_TUN_NAME")
        .unwrap_or_else(|_| format!("rsc{:x}", std::process::id() & 0xffff));
    let device = LinuxTunDevice::create(LinuxTunConfig::new(name, MIN_IPV6_MTU))
        .expect("opted-in Linux TUN smoke requires interface creation privileges");
    assert!(!device.interface_name().is_empty());
    assert_eq!(device.mtu(), MIN_IPV6_MTU);
}
