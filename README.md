# trml-daemon

The Go daemon that connects your Mac or Linux machine to the [trml](https://trml.app) iOS app via an end-to-end encrypted relay. No open ports required — the daemon dials outbound over WebSocket.

---

## How it works

```
iPhone (trml app)
      │
      │  wss://relay.trml.app
      │
  trml-daemon  ──► sh -c <command>  ──► stdout/stderr streamed back
```

- **Pairing**: scan a QR code once to bind your iPhone to this machine.
- **Encryption**: X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305. The relay never sees plaintext.
- **Reconnect**: exponential backoff (1 s → 60 s) with ±10 % jitter.

---

## Install

### Homebrew (macOS, Linux)

```bash
brew install craigderington/trml/trml-daemon
```

This auto-taps `craigderington/homebrew-trml` and installs the prebuilt binary for your OS/arch.

### From source

```bash
go build -o trml-daemon .
```

### First run

```bash
# Generates identity, prints pairing QR
trml-daemon pair

# Start in foreground
trml-daemon start

# Or install as a background service (launchd on macOS, systemd on Linux)
trml-daemon install
```

---

## Commands

| Command | Description |
|---|---|
| `trml-daemon pair` | Print the pairing QR code |
| `trml-daemon start` | Run the daemon in the foreground |
| `trml-daemon stop` | Send SIGTERM to the running daemon |
| `trml-daemon status` | Show connection state, uptime, paired device count |
| `trml-daemon install` | Install as launchd agent (macOS) or systemd user unit (Linux) |
| `trml-daemon uninstall` | Remove the service |

---

## Configuration

Config is stored at `~/.config/trml/config.yaml`. Override the directory with `TRML_CONFIG_DIR`.

```yaml
device_id: <uuid>
private_key: <base64 X25519>
relay_url: wss://relay.trml.app
log_level: info
paired_devices:
  - device_id: <ios-uuid>
    public_key: <base64 X25519>
    device_name: Alice's iPhone
```

Runtime state files:

| File | Purpose |
|---|---|
| `~/.config/trml/daemon.pid` | PID of running process |
| `~/.config/trml/status.json` | Connection state, uptime, paired count (updated every 10 s) |

---

## Directory structure

```
daemon/
├── main.go
├── go.mod
├── cmd/                        # Cobra CLI commands
│   ├── root.go
│   ├── start.go / stop.go / status.go / pair.go
│   └── install.go / uninstall.go
└── internal/
    ├── config/                 # Config struct, Load/Save, defaults
    ├── crypto/                 # X25519 keygen, ECDH+HKDF, ChaCha20-Poly1305
    ├── protocol/               # Wire types (Envelope, ExecPayload, OutputPayload, …)
    ├── pairing/                # Pairing manager, session cache, QR printer
    ├── relay/                  # WebSocket client, reconnect loop, message handler
    ├── exec/                   # sh -c runner, chunked streamer, process-group kill
    ├── parser/                 # Structured output: df, ps, git status/log, ls -l
    └── service/                # Run() wiring, PID file, status.json, launchd/systemd
```

---

## Encryption protocol

```
Pairing (once):
  daemon  →  QR: trml://pair?pub=<B64>&id=<UUID>&relay=relay.trml.app
  iOS     →  sends Envelope{ pair_pubkey=<ios_pub>, nonce, ciphertext }
              ciphertext = ChaCha20(HKDF(X25519(ios_priv, daemon_pub)), PairPayload)
  daemon  →  derives same key, decrypts, saves ios_pub, sends pair_ack

Ongoing:
  Envelope{ version, device_id, nonce, ciphertext }
  key = HKDF-SHA256( X25519(local_priv, remote_pub), info="trml-session-v1" )
  ciphertext = ChaCha20-Poly1305.Seal(key, random_nonce, inner_payload)
```

---

## Structured output parsers

When a command matches, the `done` message includes a `structured` JSON field alongside the raw text:

| Command | Structured type |
|---|---|
| `df [-h …]` | `[]DfEntry{filesystem, size, used, avail, use_pct, mounted_on}` |
| `ps [aux …]` | `[]PsEntry{user, pid, cpu_pct, mem_pct, command}` |
| `git status` | `GitStatusResult{branch, files[], clean}` |
| `git log` | `[]GitLogEntry{hash, author, date, message}` |
| `ls -l[a …]` | `[]LsEntry{permissions, owner, group, size, modified, name, is_dir}` |

---

## Testing

```bash
go test ./...                          # run all tests
go test ./... -race                    # with race detector
go test ./... -coverprofile=cover.out  # with coverage
go tool cover -func=cover.out          # per-function breakdown
```

### Coverage by package

| Package | Coverage |
|---|---|
| `protocol` | 100% |
| `parser` | 98.7% |
| `exec` | 94.4% |
| `relay` | 86.8% |
| `config` | 86.8% |
| `pairing` | 88.3% |
| `crypto` | 88.2% |
| `service` (logic) | `writeStatus` 80% — `Run()` and install funcs are integration-only |

#### What is and isn't unit-tested

- **Relay tests** use `net/http/httptest` with a gorilla WebSocket upgrader as a mock relay server.
- **Process-group kill**: the runner sets `cmd.SysProcAttr.Setpgid = true` and overrides `cmd.Cancel` to kill the entire process group. This prevents orphaned child processes (e.g. `sleep` spawned by `sh -c "echo x && sleep 10"`) from holding the stdout pipe open and blocking `cmd.Wait()`.
- **`sendPing` / ping ticker** (30 s interval) — exercised in integration, not unit tests.
- **`cmd/` CLI commands**, **`InstallLaunchd`**, **`InstallSystemd`** — require live OS services; excluded from unit tests.
- **`service.Run()`** — wires all components and blocks; requires a live relay; integration-only.

---

## Dependencies

| Module | Purpose |
|---|---|
| `golang.org/x/crypto` | X25519, ChaCha20-Poly1305, HKDF |
| `github.com/gorilla/websocket` | WebSocket client |
| `github.com/skip2/go-qrcode` | Terminal QR code |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/google/uuid` | Device ID generation |
| `gopkg.in/yaml.v3` | Config file |
| `go.uber.org/zap` | Structured logging |
