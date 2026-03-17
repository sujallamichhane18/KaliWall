<div align="center">

# KW KaliWall

**Simple Linux Firewall Dashboard**  
Rules | Live Traffic | GeoIP | Threat Intel

</div>

---

KaliWall is a clean, FortiGate-style firewall manager built with Go.
It gives you a web dashboard and CLI to manage rules, inspect traffic, and monitor public threat sources in real time.

## Highlights

- Firewall rules: create, edit, enable/disable, delete
- Block lists: IP and website/domain blocking
- Live dashboard: bandwidth, events, traffic visibility
- GeoIP widget: live public-source traffic map/table (private IPs excluded)
- DPI controls: enable/disable from dashboard
- Threat intel: VirusTotal integration with cached verdicts
- Persistent storage: settings and rules saved in local JSON DB

## New Branding

- Sidebar includes a new KaliWall logo mark: `KW`
- Top-right dashboard controls include:
  - `Stop` (switch firewall backend to memory mode)
  - `Restart` (switch back to first available live backend)

## Quick Start

### 1) Setup

```bash
chmod +x setup.sh && ./setup.sh
```

### 2) Start (Default: Background)

```bash
chmod +x start.sh && ./start.sh
```

`start.sh` now starts KaliWall in daemon/background mode by default.

### 3) Open Dashboard

- http://localhost:8080

## Start Script Commands

```bash
./start.sh                 # start in background (default)
./start.sh --foreground    # run in foreground
./start.sh --daemon        # explicit background start
./start.sh --stop          # stop daemon
./start.sh --status        # show status
./start.sh --logs          # show recent logs
./start.sh --logs-follow   # tail logs live
```

## GeoIP Database Support

KaliWall supports both:

- `GeoLite2-City.mmdb`
- `IP2LOCATION-LITE-DB1.CSV`

Auto-detected paths include project root, `data/`, `configs/`, and `internal/database/`.

You can also force path:

```bash
./kaliwall --geo-db /path/to/database-file
```

Or env var:

```bash
KALIWALL_GEO_DB=/path/to/database-file ./start.sh
```

## Dashboard Firewall Controls

In the top-right of Dashboard:

- `Stop`: moves engine to `memory`
- `Restart`: moves engine to first available live backend (`nftables`, `iptables`, or `ufw`)

## Requirements

- Go 1.21+
- Linux
- Root/sudo for live firewall enforcement
- Optional: VirusTotal API key

## Project Layout

```text
main.go
start.sh
setup.sh
internal/
  api/
  firewall/
  geoip/
  dpi/
  database/
web/
  index.html
  css/style.css
  js/app.js
```

---

Built for fast local firewall operations with a simple UI and practical defaults.
