# NHIP - Nested Hierarchical Internet Protocol (pet)

#### WARN! WORKS ON _LINUX_ ONLY!

## Installation
0. (I'll add installation script later...)
1. Download binaries from Releases
2. Make them executable: ```chmod +x nhip*```
3. Move them to ```/usr/local/bin``` folder: ```mv nhip* /usr/local/bin```
4. Create simple systemd-unit
5. Enable nhipd: ```systemctl enable --now nhipd```

## Build
1. Clone this repository
2. Go to the eBPF program folder: ```cd nhipd-ebpf```
3. Build eBPF program with _release_ profile: ```cargo build --release```
4. Go to main workspace: ```cd ../nhip```
5. Build userspace-programs: ```cargo build --release```
6. Now you have 3 binaries (nhipd, nhipctl and nhipping) in ```nhip/target/release``` folder
