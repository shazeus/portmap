"""portmap CLI — port scanning, host discovery, service detection."""

import socket
import ipaddress
import concurrent.futures
import time
import sys

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

from portmap import __version__
from portmap.scanner import (
    scan_host, expand_cidr, parse_port_spec, resolve_host,
    ping_host, reverse_dns, COMMON_SERVICES, TOP_100_PORTS,
)
from portmap.output import (
    console, print_banner, render_host_result, render_summary,
    render_as_json, render_services_table,
)

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "-V", "--version", prog_name="portmap")
def cli():
    """portmap — fast lightweight network scanner CLI."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("-p", "--ports", default="top100", show_default=True,
              help="Ports: '22,80,443', '1-1024', 'top100', '1-65535'")
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float,
              help="Connection timeout in seconds")
@click.option("-T", "--threads", default=200, show_default=True, type=int,
              help="Number of concurrent threads")
@click.option("-b", "--banners", is_flag=True, help="Grab service banners")
@click.option("--udp", is_flag=True, help="UDP scan instead of TCP")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("-q", "--quiet", is_flag=True, help="Only show open ports")
def scan(targets, ports, timeout, threads, banners, udp, as_json, quiet):
    """Scan TCP (or UDP) ports on one or more hosts/CIDRs.

    \b
    Examples:
      portmap scan 192.168.1.1
      portmap scan 192.168.1.0/24 -p 22,80,443
      portmap scan example.com -p 1-1024 --banners
      portmap scan 10.0.0.1 -p top100 --udp
    """
    if not quiet:
        print_banner()

    port_list = parse_port_spec(ports)
    if not port_list:
        console.print("[red]No valid ports specified.[/]")
        sys.exit(1)

    all_hosts = []
    for t in targets:
        if "/" in t:
            all_hosts.extend(expand_cidr(t))
        else:
            all_hosts.append(t)

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
        disable=as_json,
    ) as progress:
        task = progress.add_task(f"Scanning {len(all_hosts)} host(s), {len(port_list)} port(s)…", total=len(all_hosts))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(all_hosts) + 1)) as ex:
            future_map = {
                ex.submit(scan_host, h, port_list, timeout, threads, banners, udp): h
                for h in all_hosts
            }
            for future in concurrent.futures.as_completed(future_map):
                r = future.result()
                results.append(r)
                progress.advance(task)

    results.sort(key=lambda x: x.host)

    if as_json:
        render_as_json(results)
        return

    for r in results:
        if quiet and not r.alive:
            continue
        render_host_result(r)
        console.print()

    render_summary(results)


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("cidr")
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float,
              help="Probe timeout per host")
@click.option("-T", "--threads", default=256, show_default=True, type=int,
              help="Concurrent threads")
@click.option("--rdns", is_flag=True, help="Resolve hostnames for live hosts")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def discover(cidr, timeout, threads, rdns, as_json):
    """Discover live hosts in a CIDR range via TCP probes.

    \b
    Examples:
      portmap discover 192.168.1.0/24
      portmap discover 10.0.0.0/16 --rdns
    """
    print_banner()
    hosts = expand_cidr(cidr)
    if not hosts:
        console.print(f"[red]Invalid CIDR: {cidr}[/]")
        sys.exit(1)

    console.print(f"[cyan]Discovering hosts in [bold]{cidr}[/] ({len(hosts)} addresses)…[/]\n")

    live = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
                  console=console, transient=True) as prog:
        task = prog.add_task("Probing…", total=len(hosts))

        def probe(ip):
            alive = ping_host(ip, timeout)
            prog.advance(task)
            return ip, alive

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for ip, alive in ex.map(probe, hosts):
                if alive:
                    live.append(ip)

    live.sort(key=lambda ip: tuple(int(o) for o in ip.split(".")))

    if as_json:
        import json
        data = []
        for ip in live:
            entry = {"ip": ip}
            if rdns:
                entry["hostname"] = reverse_dns(ip)
            data.append(entry)
        console.print_json(json.dumps(data))
        return

    tbl = Table(title=f"Live Hosts in {cidr}", box=box.ROUNDED, border_style="green")
    tbl.add_column("IP Address", style="cyan bold")
    if rdns:
        tbl.add_column("Hostname")
    tbl.add_column("Status", style="green")

    for ip in live:
        row = [ip]
        if rdns:
            row.append(reverse_dns(ip) or "—")
        row.append("● ALIVE")
        tbl.add_row(*row)

    console.print(tbl)
    console.print(f"\n[bold green]{len(live)}[/] of [bold]{len(hosts)}[/] hosts alive.")


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("-p", "--ports", default="top100", show_default=True,
              help="Ports to scan")
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float)
@click.option("-T", "--threads", default=200, show_default=True, type=int)
@click.option("-b", "--banners", is_flag=True, default=True, show_default=True,
              help="Grab service banners (default on)")
@click.option("--json", "as_json", is_flag=True)
def services(targets, ports, timeout, threads, banners, as_json):
    """Scan hosts and display discovered services in a unified table.

    \b
    Examples:
      portmap services 192.168.1.1 192.168.1.2
      portmap services 10.0.0.0/24 -p 22,80,443,3306,5432
    """
    print_banner()
    port_list = parse_port_spec(ports)
    all_hosts = []
    for t in targets:
        if "/" in t:
            all_hosts.extend(expand_cidr(t))
        else:
            all_hosts.append(t)

    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
                  console=console, transient=True) as prog:
        task = prog.add_task(f"Scanning services on {len(all_hosts)} host(s)…", total=len(all_hosts))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(all_hosts) + 1)) as ex:
            future_map = {ex.submit(scan_host, h, port_list, timeout, threads, banners, False): h for h in all_hosts}
            for f in concurrent.futures.as_completed(future_map):
                results.append(f.result())
                prog.advance(task)

    if as_json:
        render_as_json(results)
    else:
        render_services_table(results)


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------
@cli.command(name="ping")
@click.argument("hosts", nargs=-1, required=True)
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float)
def ping_cmd(hosts, timeout):
    """TCP-based reachability check for one or more hosts.

    \b
    Examples:
      portmap ping google.com 8.8.8.8 192.168.1.1
    """
    print_banner()
    tbl = Table(title="Host Reachability", box=box.ROUNDED, border_style="cyan")
    tbl.add_column("Host", style="bold")
    tbl.add_column("IP", style="cyan")
    tbl.add_column("Status")
    tbl.add_column("rDNS")

    for host in hosts:
        ip = resolve_host(host)
        if not ip:
            tbl.add_row(host, "—", "[red]UNRESOLVABLE[/]", "—")
            continue
        alive = ping_host(ip, timeout)
        rdns = reverse_dns(ip) if alive else "—"
        status = "[bold green]● ALIVE[/]" if alive else "[bold red]✗ DOWN[/]"
        tbl.add_row(host, ip, status, rdns or "—")

    console.print(tbl)


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("hosts", nargs=-1, required=True)
@click.option("--rdns", is_flag=True, help="Perform reverse DNS lookup on IPs")
def resolve(hosts, rdns):
    """Resolve hostnames to IPs (and optionally reverse-lookup IPs).

    \b
    Examples:
      portmap resolve google.com github.com
      portmap resolve --rdns 8.8.8.8 1.1.1.1
    """
    tbl = Table(title="DNS Resolution", box=box.ROUNDED)
    tbl.add_column("Input", style="bold cyan")
    tbl.add_column("Resolved", style="green")
    tbl.add_column("Type")

    for host in hosts:
        try:
            _ = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip and rdns:
            result = reverse_dns(host) or "—"
            tbl.add_row(host, result, "PTR")
        elif not is_ip:
            ip = resolve_host(host)
            tbl.add_row(host, ip or "[red]FAILED[/]", "A")
        else:
            tbl.add_row(host, host, "IP")

    console.print(tbl)


# ---------------------------------------------------------------------------
# portinfo
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("ports", nargs=-1, required=True, type=int)
def portinfo(ports):
    """Show well-known service information for port numbers.

    \b
    Examples:
      portmap portinfo 22 80 443 3306 5432
    """
    tbl = Table(title="Port Information", box=box.ROUNDED, border_style="magenta")
    tbl.add_column("Port", style="bold cyan", justify="right")
    tbl.add_column("Service", style="green")
    tbl.add_column("Description")

    DESCRIPTIONS = {
        21: "File Transfer Protocol (control)",
        22: "Secure Shell — encrypted remote login",
        23: "Telnet — unencrypted remote login (legacy)",
        25: "Simple Mail Transfer Protocol",
        53: "Domain Name System",
        80: "HyperText Transfer Protocol",
        110: "Post Office Protocol v3",
        143: "Internet Message Access Protocol",
        443: "HTTP over TLS/SSL",
        445: "SMB — Windows file sharing",
        3306: "MySQL database server",
        5432: "PostgreSQL database server",
        6379: "Redis in-memory data store",
        27017: "MongoDB document database",
        3389: "Remote Desktop Protocol (RDP)",
        8080: "HTTP alternate / proxy",
        9200: "Elasticsearch REST API",
    }

    for port in ports:
        svc = COMMON_SERVICES.get(port)
        if not svc:
            try:
                svc = socket.getservbyport(port)
            except OSError:
                svc = "unknown"
        desc = DESCRIPTIONS.get(port, "—")
        tbl.add_row(str(port), svc, desc)

    console.print(tbl)


# ---------------------------------------------------------------------------
# quickscan
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("-t", "--timeout", default=0.5, show_default=True, type=float,
              help="Timeout per port")
@click.option("-T", "--threads", default=500, show_default=True, type=int)
def quickscan(target, timeout, threads):
    """Ultra-fast scan of top 100 ports with banners on a single host.

    \b
    Examples:
      portmap quickscan 192.168.1.1
      portmap quickscan scanme.nmap.org
    """
    print_banner()
    console.print(f"[cyan]Quick-scanning[/] [bold]{target}[/] (top 100 ports, timeout={timeout}s)…\n")

    t0 = time.time()
    result = scan_host(target, TOP_100_PORTS, timeout=timeout, threads=threads, grab_banners=True)

    if not result.ip:
        console.print(f"[red]Cannot resolve host:[/] {target}")
        sys.exit(1)

    render_host_result(result)
    elapsed = time.time() - t0
    console.print(f"\n[dim]Completed in {elapsed:.2f}s | {len(TOP_100_PORTS)} ports probed[/]")


# ---------------------------------------------------------------------------
# cidrinfo
# ---------------------------------------------------------------------------
@cli.command()
@click.argument("cidr")
def cidrinfo(cidr):
    """Display CIDR network information (range, broadcast, usable hosts).

    \b
    Examples:
      portmap cidrinfo 192.168.1.0/24
      portmap cidrinfo 10.0.0.0/8
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        console.print(f"[red]Invalid CIDR: {e}[/]")
        sys.exit(1)

    hosts = list(net.hosts())
    tbl = Table(title=f"Network: {net}", box=box.ROUNDED, border_style="blue")
    tbl.add_column("Field", style="bold cyan")
    tbl.add_column("Value", style="green")
    tbl.add_row("Network address", str(net.network_address))
    tbl.add_row("Broadcast address", str(net.broadcast_address))
    tbl.add_row("Netmask", str(net.netmask))
    tbl.add_row("Wildcard mask", str(net.hostmask))
    tbl.add_row("Prefix length", str(net.prefixlen))
    tbl.add_row("Usable hosts", f"{len(hosts):,}")
    tbl.add_row("First host", str(hosts[0]) if hosts else "—")
    tbl.add_row("Last host", str(hosts[-1]) if hosts else "—")
    tbl.add_row("IP version", f"IPv{net.version}")
    tbl.add_row("Is private", str(net.is_private))
    tbl.add_row("Is global", str(net.is_global))

    console.print(tbl)
