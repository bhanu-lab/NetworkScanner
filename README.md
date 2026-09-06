# Home Network Monitor

A self-hosted dashboard that discovers devices reachable on a selected local IPv4 network. It derives the actual CIDR from the interface, probes hosts concurrently, enriches results from the OS neighbour table, and can persist nicknames in Redis.

## Highlights

- CIDR-aware, interface-specific scanning
- Bounded concurrent discovery with a configurable safety limit
- Gateway detection and local-device identification
- Responsive dashboard served by Flask
- Optional Redis persistence; scanning works without Redis
- Offline-by-default vendor lookup
- Health API, structured errors, tests, Compose, and systemd examples

## Requirements and local run

Python 3.11+, Linux `ip`, and `ping` are required. Redis is optional.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python main.py
```

Open <http://127.0.0.1:5000>.

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
| `VENDOR_LOOKUP` | `false` | Query `api.macvendors.com` for uncached MACs |
| `LOG_LEVEL` | `INFO` | Application log level |

Vendor lookup is opt-in because it sends device MAC addresses to an external service. Discovery remains local.

## API

- `GET /api/health`
- `GET /api/interfaces`
- `POST /api/scans` with `{"interface":"eth0"}`
- `GET /api/nicknames`
- `PUT /api/devices/<mac>/nickname` with `{"nickname":"Kitchen TV"}`

## Containers and tests

```bash
docker compose up --build
pytest -q
```

Host networking is required because a bridged container scans its Docker subnet rather than the physical LAN. Run Python directly on macOS, where Docker host networking differs.

Tests mock network operations. Verify a real scan on the target machine because discovery only sees the host's LAN.

## Security

The service exposes LAN device information. Keep the loopback bind or put it behind authenticated access; never expose it directly to the internet. The old MAC-changing endpoint was removed because it was unrelated to monitoring and required dangerous host privileges.
