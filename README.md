<div align="center">

<br/>

<img src="kaliwall.png" alt="KaliWall Logo" width="680"/>

<br/><br/>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/License-MIT-1f6feb?style=for-the-badge&logo=opensourceinitiative&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Open%20Source-Yes-2ea043?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/iptables-supported-FF6B35?style=for-the-badge&logo=linux&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/nftables-supported-7B2FBE?style=for-the-badge&logo=linux&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/ufw-supported-0096FF?style=for-the-badge&logo=ubuntu&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/VirusTotal-integrated-394EFF?style=for-the-badge&logo=virustotal&logoColor=white&labelColor=0d1117"/>
</p>

<br/>

> **KaliWall** is a powerful open-source firewall platform for Linux.  
> It combines **live firewall control**, **traffic visibility**, **GeoIP telemetry**,  
> **threat intelligence**, and **DPI controls** through a sleek web dashboard and CLI.

<br/>

[🚀 Quick Start](#-quick-start) · [✨ Features](#-features) · [🔌 API](#-api-highlights) · [🌱 Open Source](#-open-source)

</div>

---

<br/>

## 🖥️ Dashboard Preview

<div align="center">
  <img src="dashboard.png" alt="KaliWall Dashboard" width="90%"/>
  <br/>
  <sub>KaliWall Web Dashboard — running at <code>http://localhost:8080</code></sub>
</div>

---

<br/>

## ✨ Features

<br/>

### 🔐 Core Firewall

| Capability | Details |
|---|---|
| **Rule Lifecycle** | Create · Update · Validate · Analyze · Toggle · Delete |
| **Backends** | `iptables` · `nftables` · `ufw` · Memory fallback |
| **Runtime Switch** | Hot-swap backend via API or dashboard |
| **Safe Defaults** | Automatic rule seeding on first run |

<br/>

### 🚫 Blocklists and Access Control

- 🔴 Block / unblock **IP addresses** with reasons and full history
- 🌐 Block / unblock **websites and domains**
- 💾 Persistent blocked entries via local database storage

<br/>

### 📡 Monitoring and Visibility

- 📊 **Live traffic logs** and streaming events via SSE
- 🔗 **Active connection** visibility and system health stats
- ⚡ Firewall **event stream** for near real-time UI updates
- 🌍 **DNS visibility** with cache stats, manual refresh, and cache clear endpoint

<br/>

### 🧠 Analytics and Intelligence

- 📈 Bandwidth and analytics metrics with **stream endpoint**
- 🦠 **VirusTotal** integration for IP reputation lookups
- 🗂️ Threat cache listing and API key management
- 🗺️ **GeoIP attack telemetry** with stream support

<br/>

### 🌍 GeoIP Support

```
✅  MaxMind .mmdb        →  GeoLite2-City.mmdb
✅  IP2Location CSV      →  IP2LOCATION-LITE-DB1.CSV
✅  Auto path resolution →  No manual config needed
```

<br/>

### 🔬 DPI (Lite Module)

- 🔁 Lightweight IDS/DPI module with **runtime on/off controls**
- ⚙️ Configurable interface, workers, BPF filter, promiscuous mode
- 📍 DPI status endpoint for **dashboard observability**
- 🧩 Stream-aware L7 extraction for HTTP, DNS, and TLS metadata
- 🌐 L3 telemetry: IPv4/IPv6, TCP/UDP/ICMP counters, unique IPs, and top talkers

#### DPI Validation

Start KaliWall with DPI enabled:

```bash
./kaliwall --dpi --dpi-lite --dpi-interface eth0
```

Run traffic generation tests:

```bash
curl -v http://example.com/test
curl -vk https://google.com
dig openai.com
```

Expected runtime verification logs include:

```text
[HTTP] GET /test Host: example.com
[TLS] SNI: google.com
[DNS] Query: openai.com
```

You can also confirm engine health via API:

```bash
curl -s http://localhost:8080/api/v1/dpi/status
```

### 🧪 Lightweight IDS/DPI Mode

KaliWall includes a lightweight IDS/DPI module for fast protocol telemetry (HTTP, DNS, TLS):

```bash
./kaliwall --dpi --dpi-lite --dpi-interface eth0
```

Environment-based start via script:

```bash
KALIWALL_DPI_LITE=1 ./start.sh --foreground
```

Detailed protocol counters and last-seen artifacts are available at:

```bash
curl -s http://localhost:8080/api/v1/dpi/stats
```

The response includes Layer 7 detections and Layer 3 telemetry such as:

- `http_detected`, `dns_detected`, `tls_detected`
- `ipv4_packets`, `ipv6_packets`, `tcp_packets`, `udp_packets`, `icmp_packets`
- `unique_src_ips`, `unique_dst_ips`, `top_src_ips`, `top_dst_ips`

<br/>

### 🖥️ UX and Tooling

- 🎨 **FortiGate-inspired** web UI in plain HTML/CSS/JS
- ⌨️ Full **CLI client** for rules, blocklists, status, logs, threats, and connections
- 🌑 Background **daemon** start via startup script

---

<br/>

## 🚀 Quick Start

<br/>

### 📋 Prerequisites

<p>
  <img src="https://img.shields.io/badge/OS-Ubuntu%20%2F%20Debian-E95420?style=flat-square&logo=ubuntu&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Privileges-Root%20Required-CC0000?style=flat-square&logo=linux&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Go-Toolchain%20Required-00ADD8?style=flat-square&logo=go&logoColor=white&labelColor=0d1117"/>
</p>

<br/>

### ⚡ Setup

```bash
git clone https://github.com/sujallamichhane18/KaliWall.git
cd KaliWall
chmod +x setup.sh && ./setup.sh
```

<br/>

### ▶️ Run

**Background mode** *(default)*:
```bash
chmod +x start.sh && ./start.sh
```

**Foreground mode**:
```bash
./start.sh --foreground
```

<br/>

<div align="center">
  <img src="https://img.shields.io/badge/Dashboard%20→-localhost%3A8080-00D9FF?style=for-the-badge&logo=googlechrome&logoColor=white&labelColor=0d1117"/>
</div>

---

<br/>

## 🔌 API Highlights

**Base URL:** `http://localhost:8080/api/v1`

| Category | Endpoints |
|---|---|
| 📜 **Rules** | `/rules` · `/rules/{id}` · `/rules/validate` · `/rules/analyze` |
| 🔥 **Firewall Engine** | `/firewall/engine` · `/firewall/logs` |
| 📡 **Traffic & Logs** | `/logs` · `/logs/stream` · `/events` · `/events/stream` · `/traffic/visibility` |
| 🌐 **Network / DNS** | `/connections` · `/dns/stats` · `/dns/refresh` · `/dns/cache` |
| 🦠 **Threat Intel** | `/threat/apikey` · `/threat/check/{ip}` · `/threat/cache` |
| 📊 **Analytics** | `/analytics` · `/analytics/stream` |
| 🗺️ **GeoIP** | `/geo/attacks` · `/geo/stream` |
| 🔬 **DPI** | `/dpi/status` · `/dpi/control` |
| 🚫 **Blocklists** | `/blocked` · `/blocked/{ip}` · `/websites` · `/websites/{domain}` |

---

<br/>

## ⚙️ Configuration

```
📁 GeoLite2-City.mmdb
📁 IP2LOCATION-LITE-DB1.CSV
```

```bash
./kaliwall --geo-db /path/to/GeoLite2-City.mmdb
./kaliwall --geo-db /path/to/IP2LOCATION-LITE-DB1.CSV
```

---

<br/>

## 🌱 Open Source

<div align="center">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Issues-Open-FF6B6B?style=for-the-badge&logo=github&logoColor=white&labelColor=0d1117"/>
  &nbsp;
  <img src="https://img.shields.io/badge/PRs-Welcome-4CAF50?style=for-the-badge&logo=git&logoColor=white&labelColor=0d1117"/>
</div>

<br/>

- 🐛 **Report bugs** in [GitHub Issues](https://github.com/sujallamichhane18/KaliWall/issues)
- 🔧 **Open pull requests** for fixes, docs, and enhancements
- 🎯 Keep changes **focused** and **well-tested**

---

<br/>

## 🛠️ Built With

<p align="center">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white"/>
  &nbsp;
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black"/>
  &nbsp;
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white"/>
  &nbsp;
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white"/>
  &nbsp;
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"/>
  &nbsp;
  <img src="https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white"/>
</p>

---

<br/>

<div align="center">

<a href="https://github.com/sujallamichhane18/KaliWall/stargazers">
  <img src="https://img.shields.io/github/stars/sujallamichhane18/KaliWall?style=social"/>
</a>
&nbsp;&nbsp;
<a href="https://github.com/sujallamichhane18/KaliWall/network/members">
  <img src="https://img.shields.io/github/forks/sujallamichhane18/KaliWall?style=social"/>
</a>
&nbsp;&nbsp;
<a href="https://github.com/sujallamichhane18/KaliWall/watchers">
  <img src="https://img.shields.io/github/watchers/sujallamichhane18/KaliWall?style=social"/>
</a>

<br/><br/>

<sub>If KaliWall helped you, consider giving it a ⭐ — it means the world!</sub>

<br/><br/>

---

<h3>Made with ❤️ by <a href="https://github.com/sujallamichhane18">Sujal Lamichhane</a></h3>

<br/>

</div>
