// ./nhip/nhipd/src/main.rs

// external
use anyhow::{Context, Result};
use aya::{Ebpf, include_bytes_aligned};

use std::sync::Arc;
use tokio::time::{sleep, Duration};

// local crates
use nhip_cfg::*;
use crate::ctl::ctl_listener;
use crate::daemon::NhipDaemon;

// modules
mod daemon;
mod ctl;
mod nharp_ctl;
mod socket;
mod forward;

///
/// Main function of Daemon
/// 
/// # Behavior
/// * Inits `env_logger`
/// * Loads eBPF object
/// * Creates `NhipDaemon` object
/// * Starts background tasks
/// * Handles SIGINT (Interruption Signal, CTRL+C)
#[cfg_attr(
    feature = "single_thread", 
    tokio::main(flavor = "current_thread")
)]
#[cfg_attr(
    not(feature = "single_thread"), 
    tokio::main(flavor = "multi_thread")
)]
async fn main() -> Result<()> {
    //  -----------
    //  Init logger
    //  -----------
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    #[cfg(feature = "single_thread")]
    log::info!("Starting NHIP Daemon in single-thread mode");
    #[cfg(not(feature = "single_thread"))]
    log::info!("Starting NHIP Daemon in multi-thread mode");

    //  ------------------
    //  Load eBPF bytecode
    //  ------------------
    let bpf = Ebpf::load(include_bytes_aligned!(
        "/home/user/code/nhipd-ebpf/target/bpfel-unknown-none/release/nhipd-ebpf"
    )).context("Failed to load eBPF bytecode")?;

    //  -----------
    //  Init daemon
    //  -----------
    let ifaces = get_ifaces()?;
    let daemon = Arc::new(NhipDaemon::new(ifaces, bpf).await?);
    log::info!("NHIP Daemon started");
    
    //  ----------------
    //  Background tasks
    //  ----------------

    // Receiver
    let daemon_receiver: Arc<NhipDaemon> = daemon.clone();
    tokio::spawn(async move {
        if let Err(e) = daemon_receiver.recv_handler().await {
            log::error!("Failed to start receiver: {e}");
        }
    });

    // MAC-updater
    let daemon_mac_updater = daemon.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;
            if let Err(e) = daemon_mac_updater.update_iface_mac_maps().await {
                log::warn!("IFACE_MAC update failed: {e}");
            }
            
        }
    });

    // CTL-listener
    let daemon_ctl_listener: Arc<NhipDaemon> = daemon.clone();
    tokio::spawn(async move {
        if let Err(e) = ctl_listener(daemon_ctl_listener).await {
            log::error!("CTL Listener error: {e}");
        }
    });

    // Connected-routes listener
    let daemon_connected_routes_listener: Arc<NhipDaemon> = daemon.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(10)).await;
            if let Err(e) = daemon_connected_routes_listener.check_connected().await {
                log::error!("Connected-Routes Listener error: {e}");
            }
        }
    });

    //  -----------------
    //  SIGINT processing
    //  -----------------
    tokio::signal::ctrl_c().await?;
    log::info!("Received SIGINT, NHIP Daemon shutting down.");

    Ok(())
}
