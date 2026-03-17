<div align="center">

#  KaliWall
### Next-Gen Linux Firewall Dashboard

[![Go Version](https://img.shields.io/github/go-mod/go-version/lamic/KaliWall?style=for-the-badge&logo=go&logoColor=white&color=00ADD8)](https://golang.org)
[![License](https://img.shields.io/github/license/lamic/KaliWall?style=for-the-badge&color=blue)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux&logoColor=white)](https://www.linux.org)
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)](https://github.com/lamic/KaliWall)

<br/>

<!-- Replace with actual GIF URL when available -->
<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3czamx6NDZ2YmV6YmR4aDV2a3ZnOGZ5d3JrdGdqaDIzbGZ5djJ6OSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3o7bu3XilJ5BOiSGic/giphy.gif" alt="KaliWall Dashboard Demo" width="100%" style="border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">

<br/>

**KaliWall** transforms your Linux server into a powerful firewall appliance with a FortiGate-inspired web interface.  
Manage iptables/nftables, visualize traffic, and block threats in real-time.

[Getting Started](#-quick-start) • [Features](#-key-features) • [Configuration](#-configuration)

</div>

---

## ⚡ Key Features

| Feature | Description |
| :--- | :--- |
| **Visual Dashboard** | FortiGate-style interface with real-time bandwidth and event monitoring. |
| **Firewall Management** | Create, edit, and toggle rules effortlessly from the web UI. |
| **GeoIP Intelligence** | Integrated world map visualizing public IP traffic sources. |
| **Threat Blocking** | Native integration with VirusTotal for IP and domain reputation checks. |
| **Live Traffic** | Real-time packet inspection and flow visualization using Netlink/PCAP. |
| **Persistent Storage** | Reliable disk-based JSON database ensures rules survive restarts. |

## 🚀 Quick Start

### Prerequisites

- **OS**: Linux (Ubuntu/Debian recommended)
- **Permissions**: Root privileges required for firewall manipulation.

### Installation

1.  **Clone & Setup**
    ```bash
    git clone https://github.com/sujallamichhane18/KaliWall.git
    cd KaliWall
    chmod +x setup.sh && ./setup.sh
    ```

2.  **Run Service**
    By default, the script runs in background mode (daemon).
    ```bash
    chmod +x start.sh && ./start.sh
    ```
    
    *To run in foreground for debugging:*
    ```bash
    ./start.sh --foreground
    ```

3.  **Access Dashboard**
    Open your browser and navigate to:
    > **http://localhost:8080**

## 🛠 Configuration

The system automatically detects GeoIP databases if placed in the root directory.

| File | Purpose |
| :--- | :--- |
| `GeoLite2-City.mmdb` | MaxMind City Database (Optional) |
| `IP2LOCATION-LITE-DB1.CSV` | IP2Location CSV Database (Optional) |
| `config.json` | Main configuration file (auto-generated) |

## 🏗 Architecture

KaliWall is built with performance and simplicity in mind:

- **Backend**: Golang (High performance, concurrent network handling)
- **Frontend**: Vanilla JS/CSS (Lightweight, no framework overhead)
- **Driver**: iptables/nftables (Native Linux kernel firewall)

---

<div align="center">
    <sub>Built with ❤️ for the Open Source Community</sub>
</div>
