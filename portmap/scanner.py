"""Core scanning engine: port scanning, host discovery, service detection."""

import socket
import concurrent.futures
import ipaddress
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

# Well-known service names for common ports
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-trap", 179: "BGP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD", 587: "SMTP-submission", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Grafana/Node", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4369: "Erlang", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "PHP-FPM/SonarQube", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
    11211: "Memcached", 15672: "RabbitMQ-mgmt", 27017: "MongoDB",
    27018: "MongoDB-shard", 27019: "MongoDB-config",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161,
    179, 194, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375, 2376, 3000, 3306,
    3389, 3690, 4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443,
    7001, 8080, 8443, 8888, 9000, 9090, 9092, 9200, 9300, 11211,
    15672, 27017, 27018, 27019, 69, 137, 138, 162, 67, 68,
]


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    proto: str = "tcp"


@dataclass
class HostResult:
    host: str
    ip: str = ""
    hostname: str = ""
    alive: bool = False
    open_ports: list = field(default_factory=list)
    scan_time: float = 0.0
    os_hint: str = ""


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:120]
            except socket.timeout:
                # Try sending an HTTP GET for web ports
                if port in (80, 8080, 8888, 3000):
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    data = s.recv(1024)
                    line = data.decode("utf-8", errors="replace").split("\n")[0]
                    return line.strip()[:120]
    except Exception:
        pass
    return ""


def probe_tcp_port(ip: str, port: int, timeout: float, grab: bool) -> PortResult:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = COMMON_SERVICES.get(port, "")
            if not service:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
            banner = ""
            if grab:
                banner = grab_banner(ip, port, timeout)
            return PortResult(port=port, state="open", service=service, banner=banner)
    except (socket.timeout, ConnectionRefusedError):
        return PortResult(port=port, state="closed")
    except OSError:
        return PortResult(port=port, state="filtered")


def probe_udp_port(ip: str, port: int, timeout: float) -> PortResult:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (ip, port))
            try:
                s.recvfrom(1024)
                service = COMMON_SERVICES.get(port, "unknown")
                return PortResult(port=port, state="open", service=service, proto="udp")
            except socket.timeout:
                # No ICMP unreachable = likely open|filtered
                service = COMMON_SERVICES.get(port, "unknown")
                return PortResult(port=port, state="open|filtered", service=service, proto="udp")
    except Exception:
        return PortResult(port=port, state="filtered", proto="udp")


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """TCP-based host discovery (tries port 80, 443, 22)."""
    for port in (80, 443, 22, 8080):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            continue
    # Also try socket connect on port 0 trick — some stacks respond
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect_ex((ip, 7))
        sock.close()
    except Exception:
        pass
    return False


def scan_host(
    host: str,
    ports: list,
    timeout: float = 1.0,
    threads: int = 100,
    grab_banners: bool = False,
    udp: bool = False,
) -> HostResult:
    t0 = time.time()
    ip = resolve_host(host)
    if not ip:
        return HostResult(host=host, alive=False, scan_time=0.0)

    hostname = reverse_dns(ip) if ip != host else host
    result = HostResult(host=host, ip=ip, hostname=hostname)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        if udp:
            futures = {ex.submit(probe_udp_port, ip, p, timeout): p for p in ports}
        else:
            futures = {ex.submit(probe_tcp_port, ip, p, timeout, grab_banners): p for p in ports}

        for future in concurrent.futures.as_completed(futures):
            pr = future.result()
            if pr.state in ("open", "open|filtered"):
                result.open_ports.append(pr)
                result.alive = True

    result.open_ports.sort(key=lambda x: x.port)
    result.scan_time = time.time() - t0
    return result


def expand_cidr(cidr: str) -> list:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            hosts = [net.network_address]
        return [str(h) for h in hosts]
    except ValueError:
        return []


def parse_port_spec(spec: str) -> list:
    """Parse port spec like '22,80,443,8000-8100' into sorted list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part.lower() == "top100":
            ports.update(TOP_100_PORTS)
        elif part:
            ports.add(int(part))
    return sorted(ports)
