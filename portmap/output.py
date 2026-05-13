"""Rich-based output helpers."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import json

console = Console()


STATE_STYLE = {
    "open": "bold green",
    "closed": "dim red",
    "filtered": "yellow",
    "open|filtered": "cyan",
}


def print_banner():
    banner = Text()
    banner.append("portmap", style="bold cyan")
    banner.append(" — fast network scanner", style="dim")
    console.print(Panel(banner, expand=False, border_style="cyan"))


def render_host_result(result, show_closed: bool = False):
    status = "[bold green]ALIVE[/]" if result.alive else "[bold red]DOWN[/]"
    ip_str = f"  IP: [cyan]{result.ip}[/]" if result.ip and result.ip != result.host else ""
    rdns_str = f"  rDNS: [dim]{result.hostname}[/]" if result.hostname and result.hostname != result.host else ""

    header = f"[bold]{result.host}[/] {status}{ip_str}{rdns_str}  [dim]({result.scan_time:.2f}s)[/]"
    console.print(header)

    if not result.open_ports:
        console.print("  [dim]No open ports found.[/]")
        return

    tbl = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE, padding=(0, 1))
    tbl.add_column("Port", style="bold cyan", justify="right", width=7)
    tbl.add_column("Proto", width=5)
    tbl.add_column("State", width=14)
    tbl.add_column("Service", width=16)
    tbl.add_column("Banner", no_wrap=False)

    for pr in result.open_ports:
        style = STATE_STYLE.get(pr.state, "")
        tbl.add_row(
            str(pr.port),
            pr.proto,
            f"[{style}]{pr.state}[/]",
            pr.service or "—",
            pr.banner or "",
        )

    console.print(tbl)


def render_summary(results: list):
    total_hosts = len(results)
    alive = sum(1 for r in results if r.alive)
    total_ports = sum(len(r.open_ports) for r in results)

    tbl = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
    tbl.add_column("Metric", style="bold")
    tbl.add_column("Value", style="cyan")
    tbl.add_row("Hosts scanned", str(total_hosts))
    tbl.add_row("Hosts alive", str(alive))
    tbl.add_row("Open ports found", str(total_ports))
    console.print(tbl)


def render_as_json(results: list):
    data = []
    for r in results:
        data.append({
            "host": r.host,
            "ip": r.ip,
            "hostname": r.hostname,
            "alive": r.alive,
            "scan_time": round(r.scan_time, 3),
            "ports": [
                {"port": p.port, "proto": p.proto, "state": p.state,
                 "service": p.service, "banner": p.banner}
                for p in r.open_ports
            ],
        })
    console.print_json(json.dumps(data, indent=2))


def render_services_table(results: list):
    tbl = Table(title="Discovered Services", box=box.ROUNDED, border_style="green")
    tbl.add_column("Host", style="cyan")
    tbl.add_column("IP")
    tbl.add_column("Port", justify="right", style="bold")
    tbl.add_column("Proto")
    tbl.add_column("Service", style="green")
    tbl.add_column("Banner")

    for r in results:
        for p in r.open_ports:
            tbl.add_row(r.host, r.ip, str(p.port), p.proto, p.service or "—", p.banner or "")

    if tbl.row_count:
        console.print(tbl)
    else:
        console.print("[dim]No services found.[/]")
