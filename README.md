<p align="center">
  <h1 align="center">portmap</h1>
  <p align="center">Fast lightweight network scanner CLI — port scanning, host discovery, service detection.</p>
  <p align="center">
    <a href="https://pypi.org/project/portmap-cli/"><img src="https://img.shields.io/pypi/v/portmap-cli?color=blue" alt="PyPI"></a>
    <a href="https://pypi.org/project/portmap-cli/"><img src="https://img.shields.io/pypi/pyversions/portmap-cli" alt="Python"></a>
    <a href="https://github.com/shazeus/portmap/blob/main/LICENSE"><img src="https://img.shields.io/github/license/shazeus/portmap" alt="License"></a>
    <a href="https://github.com/shazeus/portmap/stargazers"><img src="https://img.shields.io/github/stars/shazeus/portmap" alt="Stars"></a>
  </p>
</p>

---

**portmap** is a fast, concurrent, pure-Python network scanner for the terminal. It handles TCP/UDP port scanning, live host discovery, service banner grabbing, reverse DNS resolution, and CIDR network math — all presented through a clean, colourful Rich interface. No root privileges required.

- **Multi-target scanning** — scan individual IPs, hostnames, or entire CIDR ranges in one command
- **Concurrent engine** — configurable thread pool (default 200 threads) for high-speed scans
- **Service detection** — maps ports to known service names, grabs banners from open sockets
- **Host discovery** — TCP-based ping sweep across CIDR ranges with optional rDNS
- **UDP scanning** — basic UDP probe mode for DNS, SNMP, NTP and other UDP services
- **Top-100 port preset** — curated list of the most commonly exposed ports for quick audits
- **Rich output** — coloured tables, progress bars, and summary panels; JSON export with `--json`
- **CIDR calculator** — network address, broadcast, usable host range, privacy classification

## Installation

```bash
pip install portmap-cli
```

## Usage

```bash
portmap [COMMAND] [OPTIONS] [TARGETS]
```

## Commands

| Command | Description |
|---------|-------------|
| `scan` | TCP/UDP port scan on one or more hosts or CIDRs |
| `discover` | Sweep a CIDR range and list live hosts |
| `services` | Scan and display all discovered services in one table |
| `quickscan` | Ultra-fast top-100 scan with banner grabbing on a single host |
| `ping` | TCP reachability check for one or more hosts |
| `resolve` | Forward/reverse DNS resolution |
| `portinfo` | Display well-known service info for port numbers |
| `cidrinfo` | Show network range, broadcast, usable hosts for a CIDR |

## Examples

```bash
# Quick scan of top 100 ports with service banners
portmap quickscan 192.168.1.1

# Scan specific ports on multiple hosts
portmap scan 192.168.1.1 192.168.1.2 -p 22,80,443,3306

# Full subnet port scan
portmap scan 192.168.1.0/24 -p 1-1024 --banners

# Discover live hosts in a subnet
portmap discover 10.0.0.0/24 --rdns

# Service table for a range
portmap services 192.168.1.0/24 -p top100

# UDP scan for DNS/SNMP services
portmap scan 8.8.8.8 -p 53,161 --udp

# Reachability check
portmap ping google.com 8.8.8.8 192.168.1.1

# DNS resolution
portmap resolve github.com cloudflare.com
portmap resolve --rdns 1.1.1.1 8.8.8.8

# Port information lookup
portmap portinfo 22 80 443 3306 5432

# Network CIDR info
portmap cidrinfo 192.168.1.0/24

# JSON output for scripting
portmap scan 192.168.1.0/24 -p top100 --json > results.json
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--ports` | `top100` | Ports: `22,80`, `1-1024`, `top100`, `1-65535` |
| `-t`, `--timeout` | `1.0` | TCP connection timeout in seconds |
| `-T`, `--threads` | `200` | Number of concurrent threads |
| `-b`, `--banners` | off | Grab service banners from open ports |
| `--udp` | off | Use UDP instead of TCP |
| `--json` | off | Output results as JSON |
| `-q`, `--quiet` | off | Only print alive hosts |

## License

MIT © [shazeus](https://github.com/shazeus)
