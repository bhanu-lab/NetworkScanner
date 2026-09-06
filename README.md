# Home Network Monitor

A self-hosted dashboard that discovers devices reachable on a selected local IPv4 network. It derives the actual CIDR from the interface, probes hosts concurrently, enriches results from the operating system's neighbour table, and can persist nicknames in Redis.

## Highlights

- Native Windows, Linux, and macOS support
- CIDR-aware, interface-specific scanning
- Offline manufacturer lookup from the IEEE MAC-prefix database
- Optional detailed identification using services and UPnP device metadata
- Confidence-labelled OS, model, and device-type inference
- Bounded concurrent discovery with a configurable safety limit
- Gateway detection and local-device identification
- Responsive dashboard served by Flask
- Installable `netscan` command-line client for the JSON API
- Optional Redis persistence; scanning works without Redis
- Offline-by-default vendor lookup
- Health API, structured errors, tests, Compose, and systemd examples

## Requirements

- Python 3.11 or newer
- The operating system's `ping` command
- Redis only if nickname persistence is needed

Network interfaces are discovered through `psutil`. Probing, gateway lookup, and neighbour-table enrichment use the appropriate native commands on each platform.

## Run on macOS or Linux

```bash
git clone https://github.com/bhanu-lab/NetworkScanner.git
cd NetworkScanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python main.py
```

## Run on Windows PowerShell

```powershell
git clone https://github.com/bhanu-lab/NetworkScanner.git
Set-Location NetworkScanner
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python main.py
```

Open <http://127.0.0.1:5000>. Select the active Wi-Fi or Ethernet interface and choose **Scan network**.

No administrator or root access is normally required. Make sure `ping` is allowed by endpoint security or firewall policy. Devices that reject ICMP echo requests may not appear.

## CLI client

Install the client from the repository in the same virtual environment:

```bash
python -m pip install -e .
```

The same commands work in PowerShell, Command Prompt, and macOS or Linux shells:

```bash
netscan health
netscan interfaces
netscan scan
netscan scan --details
netscan scan --interface "Wi-Fi@192.168.1.5"
netscan nicknames
netscan nickname aa:bb:cc:dd:ee:ff Kitchen TV
netscan scan --json
```

`netscan scan` automatically chooses the server's default interface. Add `--details` to probe common services and request local UPnP descriptions for make, model, probable OS, and device type. Use the exact interface ID reported by `netscan interfaces` when you need another one. The nickname command requires Redis to be configured on the server.

The default server is `http://127.0.0.1:5000`. To use a server on another computer:

```bash
netscan --server http://192.168.1.20:5000 scan
```

Alternatively, set `NETSCAN_SERVER_URL` once in the shell. The client triggers a scan **on the server's network**, not on the client computer's network.

For access from another device, start the server on a trusted LAN address. On macOS or Linux:

```bash
HOST=0.0.0.0 python main.py
```

On Windows PowerShell:

```powershell
$env:HOST = "0.0.0.0"
python main.py
```

Allow TCP port 5000 through the host firewall only for the trusted local network. The API currently has no authentication, so do not expose it to the internet.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | HTTP bind address |
| `PORT` | `5000` | HTTP port |
| `NETSCAN_WORKERS` | `64` | Concurrent ping workers, capped at 256 |
| `NETSCAN_TIMEOUT` | `0.8` | Per-host timeout in seconds |
| `NETSCAN_MAX_HOSTS` | `1024` | Refuse unexpectedly large scans |
| `REDIS_URL` | unset | Enable nickname persistence |
| `REDIS_HOST` | unset | Alternative Redis host configuration |
| `VENDOR_LOOKUP` | `false` | Allow an external vendor lookup only when the offline database has no match |
| `LOG_LEVEL` | `INFO` | Application log level |

Manufacturer lookup uses a bundled offline MAC-prefix database first. The external fallback is opt-in because it sends device MAC addresses to an external service. Modern phones and laptops commonly use private, locally administered Wi-Fi addresses; those are marked as randomized because their manufacturer cannot be reliably derived from the MAC prefix.

## Device identification

A detailed scan combines several signals rather than pretending every result is certain:

- MAC prefixes provide the network-adapter manufacturer, which is not always the device brand.
- SSDP/UPnP descriptions can provide a friendly name, manufacturer, model, and platform string for routers, TVs, speakers, printers, and streaming devices.
- A small set of TCP services helps classify devices and infer likely platforms.
- OS guesses include `high`, `medium`, or `low` confidence. An empty OS means there was not enough evidence.

This is a useful Fing-style inventory foundation, not a commercial fingerprint database. Firewalls, client isolation, randomized MAC addresses, sleeping devices, and disabled discovery protocols reduce what any local scanner can identify.

## API

- `GET /api/health`
- `GET /api/interfaces`
- `POST /api/scans` with `{"interface":"eth0","details":true}` (`details` defaults to `false`)
- `GET /api/nicknames`
- `PUT /api/devices/<mac>/nickname` with `{"nickname":"Kitchen TV"}`

Interface names differ by platform—for example, `eth0` on Linux, `en0` on macOS, and `Wi-Fi` on Windows. Always use a value returned by `GET /api/interfaces`.

## Containers and tests

Run tests on any supported platform:

```bash
pytest -q
```

GitHub Actions runs the suite on Windows, Ubuntu, and macOS with Python 3.11 and 3.13 for every push and pull request.

Docker deployment is intended for a **Linux host**:

```bash
docker compose up --build
```

The container uses host networking so it can inspect the physical LAN. Docker Desktop on Windows and macOS runs containers inside a VM, so run the Python application natively on those platforms for accurate LAN discovery.

Tests mock network operations. Verify a real scan on every target operating system because discovery depends on native networking behavior and local firewall rules.

## Security

The service exposes LAN device information. Keep the loopback bind or put it behind authenticated access; never expose it directly to the internet. The old MAC-changing endpoint was removed because it was unrelated to monitoring and required dangerous host privileges.
