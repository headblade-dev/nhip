use std::sync::Arc;
use crate::NhipDaemon;
use anyhow::Result;
use tokio::net::UnixListener;
use tokio::io::AsyncWriteExt;

pub async fn ctl_listener(daemon: Arc<NhipDaemon>) -> Result<()>{
    let socket_path = "/var/run/nhipd.sock";
    let _ = std::fs::remove_file(socket_path);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => { anyhow::bail!("Failed to bind UnixListener to {}: {}", socket_path, e) }
    };
    log::info!("CTL Listener started on {}", socket_path);

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                anyhow::bail!("Failed to connect to UnixStream: {}", e);
            }
        };

        let daemon_second = daemon.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                if let Ok(()) = stream.readable().await {
                    match stream.try_read(&mut buf) {
                        Ok(0) => {
                            log::debug!("UnixStream client disconnected");
                            break;
                        }
                        Ok(n) => {
                            let cmd = String::from_utf8_lossy(&buf[..n]);

                            #[allow(unused)]
                            // TODO using this
                            let cmd_str: &str = &cmd;

                            // if cmd_str.starts_with("RESOLVE") {
                            //     log::debug!("CTL Command: '{}'", cmd.trim());
                            //     let parts: Vec<&str> = cmd.split_whitespace().collect();
                            //     if parts.len() == 3 {
                            //         let remote_node_id: u32 = match parts[1].trim().parse() {
                            //             Ok(v) => v,
                            //             Err(e) => {
                            //                 log::warn!("CTL Listener: invalid node_id '{}': {}", parts[1], e);
                            //                 return;
                            //             }
                            //         };
                            //         let ifindex: Result<u32, ParseIntError> = parts[2].trim().parse();
                            //         if let Err(e) = &ifindex {
                            //             log::warn!("CTL Listener: invalid ifindex '{}': {}", parts[2], e);
                            //         };
                            //         let ifindex = ifindex.unwrap_or(0);

                            //         if let Err(e) = daemon_second.nharp_send_request(ifindex, remote_node_id).await {
                            //             log::error!("Failed to send NHARP request: {}", e);
                            //         };
                            //     } else {
                            //         log::warn!("CTL Command 'RESOLVE': parts.len() != 3, skipping")
                            //     }
                            // }

                            if cmd.starts_with("PING") {
                                let parts: Vec<&str> = cmd.split_whitespace().collect();
                                if parts.len() == 5 {
                                    let dst_addr = parts[1];
                                    let src_addr = parts[2];
                                    let ifindex: u32 = match parts[3].trim().parse() {
                                        Ok(idx) => idx,
                                        Err(_) => { 
                                            log::warn!("CTL Ping error: Bad ifindex");
                                            0
                                        } 
                                    };
                                    log::debug!("CTL Command: 'PING: dst={}, src={}, ifindex={}'", dst_addr, src_addr, ifindex);
                                    let payload = match hex::decode(parts[4]) {
                                        Ok(p) => p,
                                        Err(_) => {
                                            log::error!("CTL Ping error: failed to decode payload");
                                            vec![0xee]
                                        }
                                    };
                                    let payload = payload.as_slice();

                                    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
                                    *daemon_second.pong_sender.lock().await = Some(tx);

                                    if let Err(e) = daemon_second.pingpong(src_addr, dst_addr, ifindex, payload, 1).await {
                                        log::error!("Failed to send ping: {}", e);
                                        *daemon_second.pong_sender.lock().await = None;
                                    }

                                    match tokio::time::timeout(tokio::time::Duration::from_secs(2), rx).await {
                                        Ok(Ok(cmd)) => {
                                            let _ = stream.write_all(cmd.as_bytes()).await;
                                        }
                                        _ => {
                                            log::warn!("Reached timeout when waiting ping answer");
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        });
    }
}