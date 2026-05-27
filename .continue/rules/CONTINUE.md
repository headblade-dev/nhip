# Project Guide for nhip

## 1. Project Overview
**Purpose**
This repository implements **nhip**, a high‑performance networking stack built with eBPF. It provides a userspace control plane (`nhipctl`) and a daemon (`nhipd`) that load and manage eBPF programs for packet processing.

**Key Technologies**
- **Rust** (2024 edition) – core language for all components
- **eBPF** via the **aya** crate – kernel‑space packet handling
- **Cargo workspace** – multi‑crate organization (`nharp`, `nhip-cfg`, `nhip-core`, `nhipctl`, `nhipd`, `nhipping`)
- **Clap** – CLI argument parsing for `nhipctl`
- **Log** – structured logging

**High‑Level Architecture**
```
+-------------------+        +-------------------+
|   nhipctl (CLI)   | ---->  |   nhipd (daemon) |
+-------------------+        +-------------------+
         |                         |
         v                         v
   nhip-cfg (config)      nhip-core (core lib)
         |                         |
         v                         v
   eBPF programs (aya)   <--->   Kernel via aya
```
- `nhipctl`: user‑space command line interface to configure and control the stack.
- `nhipd`: daemon that loads eBPF bytecode, manages maps, and runs the data‑plane.
- `nhip-core`: shared library containing packet‑processing abstractions, data structures, and utilities.
- `nhip-cfg`: configuration handling (likely TOML/YAML).
- `nharp` & `nhipping`: ancillary crates (e.g., ARP handling, IP forwarding).

---

## 2. Getting Started
### Prerequisites
| Requirement | Version / Notes |
|-------------|-----------------|
| **Rust toolchain** | `rustc 1.81+` (use `rustup`) |
| **Cargo** | Comes with Rust |
| **Clang / LLVM** | Required by `aya` to compile eBPF objects |
| **Linux kernel** | 5.10+ with `CONFIG_BPF` enabled |
| **sudo / root** | Loading eBPF programs needs elevated privileges |
| **libelf / libbpf-dev** | For building eBPF objects (`apt install libelf-dev libbpf-dev`) |

### Installation
```bash
# Clone the repo
git clone <repo‑url>
cd nhip

# Install Rust toolchain if not present
rustup install stable
rustup default stable

# Install required system packages (Debian/Ubuntu example)
sudo apt-get update
sudo apt-get install clang llvm libelf-dev libbpf-dev make

# Build all workspace crates
cargo build --release
```

### Basic Usage
```bash
# Run the daemon (requires sudo)
sudo ./target/release/nhipd --config ./config/nhipd.toml

# Use the CLI to add an interface
sudo ./target/release/nhipctl iface add eth0 --address 10.0.0.1/24

# Show current configuration
./target/release/nhipctl show
```

### Running Tests
```bash
# Run unit tests for all crates
cargo test

# Run integration/eBPF tests (requires root)
sudo cargo test --manifest-path nhipd/Cargo.toml -- --test-threads=1
```

---

## 3. Project Structure
```
nhip/
├─ Cargo.toml                # Workspace definition
├─ Cargo.lock
├─ nharp/                    # ARP handling implementation
├─ nhip-cfg/                # Configuration parsing & structs
├─ nhip-core/               # Core library (packet structs, utilities)
│   ├─ Cargo.toml
│   └─ src/
│       ├─ lib.rs
│       ├─ addr.rs
│       ├─ header.rs
│       └─ label.rs
├─ nhipctl/                 # CLI control tool
│   ├─ Cargo.toml
│   └─ src/
├─ nhipd/                   # Daemon that loads eBPF
│   ├─ Cargo.toml
│   └─ src/
├─ nhipping/                # IP forwarding / routing logic
└─ target/                  # Build artefacts (generated)
```

**Key Files**
- `nhip-core/src/lib.rs` – public API re‑exports for other crates.
- `nhipctl/src/main.rs` – entry point for the CLI, uses `clap`.
- `nhipd/src/main.rs` – daemon startup, loads eBPF objects via `aya`.
- `nhip-cfg/src/` – defines configuration structs (likely using `serde`).

---

## 4. Development Workflow
| Step | Description |
|------|-------------|
| **Branching** | Follow GitFlow or simple feature‑branch model (`git checkout -b feature/<name>`). |
| **Coding Standards** | - `rustfmt` for formatting (`cargo fmt`). <br> - `clippy` linting (`cargo clippy -- -D warnings`). |
| **Testing** | Write unit tests in each crate’s `tests/` module. Use `#[cfg(test)]`. Integration tests for eBPF reside under `nhipd/tests/`. |
| **Building** | `cargo build` for dev, `cargo build --release` for production. |
| **eBPF Compilation** | The `aya` build script automatically compiles eBPF C/Rust code; ensure `clang` is in `$PATH`. |
| **Commit Messages** | Use conventional commits (`feat:`, `fix:`, `docs:` etc.). |
| **Pull Requests** | PR must pass CI (formatting, clippy, tests) before merge. |

**Deployment**
- Build a release binary (`cargo build --release`).
- Copy binaries & config files to target host.
- Load via systemd service (`nhipd.service`) or manual start with `sudo`.

---

## 5. Key Concepts
| Concept | Explanation |
|---------|-------------|
| **eBPF Program** | Kernel‑space code compiled to BPF bytecode; loaded via `aya`. |
| **Maps** | Shared data structures between user‑space and eBPF (e.g., routing tables). |
| **CLI (`nhipctl`)** | Provides commands: `iface add/remove`, `route add`, `show`, etc. |
| **Configuration (`nhip-cfg`)** | Central TOML/YAML file used by daemon and CLI. |
| **Workspace** | Cargo workspace groups related crates, sharing `Cargo.lock`. |
| **Safety** | All Rust code runs in userspace; eBPF code is verified by the kernel. |

---

## 6. Common Tasks
### Adding a New Interface
```bash
sudo ./target/release/nhipctl iface add <dev> --address <IP>/<prefix>
```
### Updating Routing Table
```bash
sudo ./target/release/nhipctl route add 192.168.1.0/24 via 10.0.0.254 dev eth0
```
### Reloading eBPF Programs
```bash
# Stop daemon
sudo systemctl stop nhipd

# Re‑build (if changes were made)
cargo build --release -p nhipd

# Restart daemon
sudo systemctl start nhipd
```
### Debugging eBPF Maps
```bash
sudo bpftool map dump pinned /sys/fs/bpf/<map_name>
```

---

## 7. Troubleshooting
| Issue | Likely Cause | Fix |
|-------|--------------|-----|
| **Permission denied loading eBPF** | Not running as root or missing CAP_SYS_ADMIN | Run `sudo` or grant capabilities (`setcap cap_sys_admin+ep <binary>`). |
| **`clang` not found** | Build dependencies missing | Install `clang` (`sudo apt-get install clang`). |
| **Kernel rejects eBPF program** | Incompatible kernel version or invalid verifier log | Verify kernel >= 5.10; check `dmesg` for verifier output. |
| **CLI crashes on unknown subcommand** | Out‑of‑date binary vs. config schema | Rebuild all crates (`cargo clean && cargo build --release`). |
| **Maps appear empty** | Daemon not running or failed to load maps | Check daemon logs (`journalctl -u nhipd`); ensure correct config path. |

**Debugging Tips**
- Enable verbose logging (`RUST_LOG=debug ./target/release/nhipd`).
- Use `bpftool prog list` and `bpftool map list` to inspect loaded objects.
- Run unit tests with `cargo test -- --nocapture` to see printed diagnostic output.

---

## 8. References
- **Aya crate documentation** – https://docs.rs/aya/latest/aya/
- **eBPF tutorials** – https://ebpf.io/what-is-ebpf/
- **Clap CLI guide** – https://docs.rs/clap/latest/clap/
- **Rust Coding Guidelines** – https://github.com/rust-lang/rustfmt
- **Cargo Workspace Docs** – https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html

*If any of the above sections lack concrete information (e.g., exact config file format, systemd unit files), please verify against the repository and update the guide accordingly.*
