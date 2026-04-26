# Sentinal

A defense-in-depth container threat detection system that combines **static image analysis** with **runtime syscall monitoring** to detect malicious containers before and during execution.

Sentinal wraps Docker/Podman as a transparent CLI shim. Every `run` or `pull` command triggers a two-phase security pipeline:

1. **Pre-run** — Container image layers are extracted, encoded into grayscale PPM images (linear + Hilbert curve), and classified by a CNN via ONNX Runtime. Malicious images are blocked before they ever start.
2. **Runtime** — An eBPF program traces 14 syscall categories in real time, building a process-syscall behavior graph. Logs stream to Loki and graphs are exported as JSON for GNN-based anomaly detection.

```
              ┌─────────────────────────────────────────────────────┐
              │                  sentinal run alpine                │
              │                                                     │
              │   PRE-RUN                    RUNTIME                │
              │   ┌──────────────────┐       ┌──────────────────┐   │
              │   │ tarball → PPM    │       │ eBPF tracing     │   │
              │   │ linear + hilbert │       │ 14 syscall types │   │
              │   │       ↓          │       │       ↓          │   │
              │   │ CNN (ONNX)       │       │ syscall graph    │   │
              │   │       ↓          │       │       ↓          │   │
              │   │ verdict: clean/  │       │ GNN inference    │   │
              │   │ suspicious/      │       │       ↓          │   │
              │   │ malicious        │       │ normal/anomalous │   │
              │   └──────────────────┘       └──────────────────┘   │
              └─────────────────────────────────────────────────────┘
```

---

## Architecture

```
sentinal/
├── cli.cpp                    # main entry point — CLI shim
├── encoder/
│   ├── linear.cpp / .hpp      # linear byte-to-pixel encoder (1024×512)
│   ├── filling.cpp / .hpp     # hilbert curve encoder (1024×1024)
│   └── image.cpp / .hpp       # PPM image writer
├── utils/
│   ├── bpf_runner.cpp / .hpp  # eBPF program loader (libbcc)
│   ├── syscall_graph.cpp/.hpp # process-syscall graph builder + JSON export
│   ├── onxx_model.cpp / .hpp  # ONNX Runtime inference wrapper
│   ├── loki.cpp / .hpp        # Grafana Loki log shipper
│   ├── http.cpp / .hpp        # libcurl HTTP client
│   ├── helpers.cpp / .hpp     # runtime detection (docker/podman)
│   └── parser.cpp / .hpp      # argument parser
├── bpf/
│   └── sys_call.c             # eBPF kprobe program (14 syscall hooks)
├── infra/
│   ├── loki-config.yaml       # Loki server configuration
│   └── grafana/               # Grafana provisioning (dashboards, datasources)
├── docker-compose.yml         # Loki + Grafana observability stack
├── Makefile                   # build targets
└── CMakeLists.txt             # CMake build configuration
```

---

## Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| **g++** | C++17 support | Compilation |
| **ONNX Runtime** | ≥ 1.17.0 | CNN model inference |
| **libbcc** | ≥ 0.28 | eBPF program compilation and loading |
| **libcurl** | ≥ 7.x | HTTP client for Loki log shipping |
| **libarchive** | ≥ 3.x | Tarball extraction for image encoding |
| **Docker** or **Podman** | any | Container runtime |
| **Linux kernel** | ≥ 5.4 | eBPF kprobe support |
| **root access** | — | Required for eBPF attachment |

---

## Build

```bash
make
```

This produces `cli.out`, the main Sentinal binary.

To set a custom ONNX Runtime path, edit `ONNX_DIR` in the Makefile:

```makefile
ONNX_DIR := /path/to/onnxruntime-linux-x64-1.17.0
```

---

## Usage

Sentinal acts as a drop-in wrapper around your container runtime. Prefix any Docker/Podman command with `sudo ./cli.out`:

```bash
sudo SENTINAL_BPF_PATH=./bpf/sys_call.c ./cli.out run --rm alpine sh -c "echo hello; sleep 2; ls /"
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SENTINAL_BPF_PATH` | `./bpf/sys_call.c` | Path to the eBPF kprobe source |
| `SENTINAL_MODEL_PATH` | `/etc/sentinal/model.onnx` | Path to the ONNX CNN model |
| `SENTINAL_LOKI_URL` | `http://localhost:3100` | Loki endpoint for log shipping |
| `SENTINAL_GRAPH_DIR` | `./out/graphs` | Output directory for syscall graph JSON files |

### Pipeline Walkthrough

```bash
[sentinal] image: alpine
[sentinal] saving tarball...
[sentinal] encoding (linear)...
[sentinal] encoding (hilbert)...
[sentinal] running model...
[sentinal] verdict: clean
[sentinal] pre-run log pushed
[sentinal] container pid=12345 — eBPF monitor active
hello
bin  dev  etc  home  lib  ...
root
[sentinal] graph saved: ./out/graphs/alpine_1777176610.json
```

If the CNN classifies an image as **malicious**, Sentinal blocks execution immediately:

```bash
[sentinal] verdict: malicious
[sentinal] BLOCKED: image flagged as malicious
```

---

## Encoders

### Linear Encoder

Maps container layer bytes sequentially to a **1024 × 512** grayscale PPM image. Each pixel represents one byte value (0–255). Preserves sequential byte ordering — effective for detecting packed sections, headers, and repetitive structures.

### Hilbert Curve Encoder

Maps container layer bytes via a Hilbert space-filling curve to a **1024 × 1024** grayscale PPM image. Nearby bytes in the binary remain nearby in 2D space, preserving locality. Better for detecting structural patterns and spatial relationships in binary data.

Both encoders extract layers from container tarballs via `libarchive` and write standard PPM files to the output directory.

---

## eBPF Syscall Monitor

The eBPF program (`bpf/sys_call.c`) attaches kprobes to 14 security-sensitive syscall families:

| Type ID | Syscall | What It Captures |
|---|---|---|
| 1 | `clone` | Process creation (fork/clone flags) |
| 2 | `execve` | Program execution |
| 3 | `exit` | Process termination (exit code) |
| 4 | `setuid` | UID changes |
| 5 | `setgid` | GID changes |
| 6 | `setns` | Namespace switching |
| 7 | `unshare` | Namespace creation |
| 8 | `ptrace` | Process tracing/debugging (request + target PID) |
| 9 | `kill` | Signal delivery (target PID + signal number) |
| 10 | `mount` | Filesystem mounting |
| 11 | `umount` | Filesystem unmounting |
| 12 | `chroot` | Root directory changes |
| 13 | `prctl` | Process control operations |
| 14 | `cap_capable` | Capability checks (capability ID) |

Each event captures: `pid`, `ppid`, `uid`, `gid`, `comm`, `type`, `arg1`, `arg2`.

---

## Syscall Graph

Events are assembled into a directed graph with two node types and three edge relations:

**Nodes:**
- `proc_<pid>` — Process nodes with attributes: `pid`, `ppid`, `uid`, `gid`, `comm`
- `ev_<id>` — Syscall event nodes with attributes: `type`, `name`, `arg1`, `arg2`, `pid`

**Edges:**
- `spawns` — Process → child process (parent created child via `clone`)
- `invokes` — Process → syscall event (process made the syscall)
- `sequences` — Event → event (temporal ordering within a process)

Graphs are exported as JSON matching this schema:

```json
{
  "graph": {
    "image": "alpine",
    "verdict": "clean",
    "runtime": "podman",
    "container_exit_code": 0,
    "total_events": 194,
    "total_processes": 12,
    "total_edges": 379
  },
  "nodes": [...],
  "links": [...]
}
```

---

## Observability Stack

Start the Loki + Grafana stack for log visualization:

```bash
docker compose up -d
```

| Service | URL | Credentials |
|---|---|---|
| **Grafana** | `http://localhost:3000` | `admin` / `sentinal` |
| **Loki** | `http://localhost:3100` | — |

Sentinal pushes structured logs to Loki in two phases:

- **Pre-run logs** — Image name, CNN verdict, model scores
- **Runtime logs** — Every syscall event with full context (pid, comm, syscall name, args)
- **Exit logs** — Container exit code, graph summary (node/edge counts, top syscalls)

---

## ML Models

Sentinal supports a dual-model architecture for defense-in-depth classification:

### Image CNN (Pre-run)

A dual-branch CNN that processes both linear and Hilbert encoded PPM images to classify container layers as `clean`, `suspicious`, or `malicious`. Loaded via ONNX Runtime at inference time.

### Syscall GNN (Runtime)

A Graph Attention Network (GATv2) that classifies entire process-syscall graphs as `normal` or `anomalous`. Trained on PyTorch Geometric, exported via ONNX or TorchScript.

### Verdict Decision Matrix

| CNN Verdict | GNN Verdict | Final |
|---|---|---|
| clean | normal | **clean** |
| clean | anomalous | **suspicious** |
| suspicious | normal | **suspicious** |
| suspicious | anomalous | **malicious** |
| malicious | * | **BLOCKED** |

---

## Make Targets

```bash
make              # build cli.out
make clean        # remove build artifacts
make test         # run alpine container with eBPF monitoring
make test-nginx   # run nginx:alpine with port mapping
make http         # build standalone HTTP client test
```

---

## License

MIT
