#!/usr/bin/env python3
"""Discover live IPv4 hosts on the local LAN.

Uses ICMP echo plus the kernel ARP/neighbor table. Optional mDNS (avahi)
and NetBIOS (nmblookup) names are attached when those binaries exist.
No extra Python packages. Linux only (ip/ping).
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

from oui import vendor_from_mac

ProgressCb = Callable[[int, int, str], None]
CancelCheck = Callable[[], bool]

ALIVE_ARP_STATES = frozenset(
    {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
)
DEAD_ARP_STATES = frozenset({"FAILED", "INCOMPLETE"})


@dataclass
class Iface:
    name: str
    ip: str
    prefix: int
    network: str

    @property
    def cidr(self) -> str:
        return f"{self.ip}/{self.prefix}"


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    icmp: bool = False
    arp: bool = False
    is_self: bool = False
    is_gateway: bool = False

    @property
    def alive(self) -> bool:
        return self.icmp or self.arp or self.is_self

    @property
    def method(self) -> str:
        parts = []
        if self.is_self:
            parts.append("self")
        if self.icmp:
            parts.append("icmp")
        if self.arp:
            parts.append("arp")
        if self.is_gateway:
            parts.append("gw")
        return "+".join(parts) if parts else "none"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["method"] = self.method
        d["alive"] = self.alive
        return d


@dataclass
class ScanResult:
    iface: str
    subnet: str
    self_ip: str
    gateway: str
    elapsed_sec: float
    probed: int
    hosts: list[Host] = field(default_factory=list)

    @property
    def live(self) -> list[Host]:
        return [h for h in self.hosts if h.alive]

    def to_dict(self) -> dict:
        return {
            "iface": self.iface,
            "subnet": self.subnet,
            "self_ip": self.self_ip,
            "gateway": self.gateway,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "probed": self.probed,
            "live_count": len(self.live),
            "hosts": [h.to_dict() for h in self.live],
        }


def _run(cmd: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=timeout,
        check=False,
    )


def list_ifaces() -> list[Iface]:
    """IPv4 interfaces that are up and have a global address (not loopback)."""
    out = _run(["ip", "-4", "-o", "addr", "show", "scope", "global"]).stdout
    found: list[Iface] = []
    for line in out.splitlines():
        # 2: enp131s0    inet 192.168.0.104/24 brd ...
        m = re.match(
            r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
            line.strip(),
        )
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if name == "lo" or name.startswith("lo:"):
            continue
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        found.append(Iface(name=name, ip=ip, prefix=prefix, network=str(net)))
    return found


def default_gateway(iface: str | None = None) -> str:
    out = _run(["ip", "-4", "route", "show", "default"]).stdout
    for line in out.splitlines():
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)(?:\s+dev\s+(\S+))?", line)
        if not m:
            continue
        gw, dev = m.group(1), m.group(2)
        if iface is None or dev is None or dev == iface:
            return gw
    return ""


def pick_iface(name: str | None = None, subnet: str | None = None) -> Iface:
    ifaces = list_ifaces()
    if not ifaces:
        raise RuntimeError("No IPv4 interface with a global address is up.")
    if name:
        for i in ifaces:
            if i.name == name:
                return i
        raise RuntimeError(f"Interface {name!r} not found or has no IPv4 address.")
    if subnet:
        net = ipaddress.ip_network(subnet, strict=False)
        for i in ifaces:
            if ipaddress.ip_address(i.ip) in net:
                return i
    return ifaces[0]


def parse_neigh(iface: str) -> dict[str, tuple[str, str]]:
    """ip -> (mac, state). MAC may be empty."""
    out = _run(["ip", "-4", "neigh", "show", "dev", iface]).stdout
    table: dict[str, tuple[str, str]] = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = ""
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        state = parts[-1].upper()
        table[ip] = (mac.lower(), state)
    return table


def ping_one(ip: str, timeout: int) -> bool:
    r = _run(["ping", "-c", "1", "-W", str(max(1, timeout)), ip], timeout=timeout + 2)
    return r.returncode == 0


def _hosts_in(network: ipaddress.IPv4Network) -> list[str]:
    if network.prefixlen >= 31:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def _ip_key(ip: str) -> tuple[int, ...]:
    return tuple(int(x) for x in ip.split("."))


def _short_name(name: str) -> str:
    name = name.strip().rstrip(".")
    if name.endswith(".local"):
        name = name[: -len(".local")]
    return name


def reverse_dns(ip: str) -> str:
    try:
        name = socket.getfqdn(ip)
    except OSError:
        return ""
    if not name or name == ip:
        return ""
    return _short_name(name)


def mdns_name(ip: str, timeout: float = 1.5) -> str:
    if not shutil.which("avahi-resolve"):
        return ""
    try:
        r = _run(["avahi-resolve", "-a", ip], timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    line = (r.stdout or "").strip().splitlines()
    if not line:
        return ""
    # "192.168.0.11	kodh-cubeisys.local"
    parts = line[0].split()
    if len(parts) >= 2:
        return _short_name(parts[-1])
    return ""


def netbios_name(ip: str, timeout: float = 2.0) -> str:
    if not shutil.which("nmblookup"):
        return ""
    try:
        r = _run(["nmblookup", "-A", ip], timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    for raw in r.stdout.splitlines():
        if "<GROUP>" in raw:
            continue
        m = re.search(r"^\s+(\S+)\s+<00>\s+", raw)
        if m:
            return m.group(1)
    return ""


def resolve_hostname(ip: str) -> str:
    fallback = ""
    for fn in (mdns_name, netbios_name, reverse_dns):
        name = fn(ip)
        if not name or name == ip:
            continue
        if name == "_gateway":
            fallback = name
            continue
        return name
    return fallback


def _resolve_one(ip: str) -> tuple[str, str]:
    return ip, resolve_hostname(ip)


def scan_lan(
    iface: str | None = None,
    subnet: str | None = None,
    timeout: int = 1,
    workers: int = 128,
    resolve: bool = True,
    max_hosts: int = 1024,
    progress: ProgressCb | None = None,
    cancelled: CancelCheck | None = None,
) -> ScanResult:
    """Sweep a subnet. Live = ICMP reply, confirmed ARP, or this host."""
    chosen = pick_iface(iface, subnet)
    net = ipaddress.ip_network(subnet or chosen.network, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise RuntimeError("Only IPv4 subnets are supported.")
    targets = _hosts_in(net)
    if len(targets) > max_hosts:
        raise RuntimeError(
            f"Subnet {net} has {len(targets)} hosts; raise --max-hosts to scan it."
        )

    gateway = default_gateway(chosen.name)
    self_ip = chosen.ip
    t0 = time.time()

    icmp_ok: set[str] = set()
    done = 0
    total = len(targets)

    def _cancelled() -> bool:
        return bool(cancelled and cancelled())

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(ping_one, ip, timeout): ip for ip in targets}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            if _cancelled():
                break
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                icmp_ok.add(ip)
            done += 1
            if progress:
                progress(done, total, ip)

    neigh = parse_neigh(chosen.name)
    # ICMP-silent ARP hits from a flood can be DELAY leftovers. Re-check them.
    arp_candidates = []
    for ip, (mac, state) in neigh.items():
        if ip in icmp_ok or ip == self_ip:
            continue
        if mac and state in ALIVE_ARP_STATES:
            arp_candidates.append(ip)

    arp_ok: dict[str, str] = {}
    for ip, (mac, state) in neigh.items():
        if ip in icmp_ok and mac and state not in DEAD_ARP_STATES:
            arp_ok[ip] = mac

    if arp_candidates and not _cancelled():
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, len(arp_candidates))
        ) as pool:
            list(pool.map(lambda ip: ping_one(ip, timeout), arp_candidates))
        neigh = parse_neigh(chosen.name)
        for ip in arp_candidates:
            mac, state = neigh.get(ip, ("", ""))
            if mac and state not in DEAD_ARP_STATES:
                arp_ok[ip] = mac

    live_ips = set(icmp_ok) | set(arp_ok) | {self_ip}
    # Drop IPs outside the chosen subnet (stale neigh from elsewhere).
    live_ips = {ip for ip in live_ips if ipaddress.ip_address(ip) in net}

    names: dict[str, str] = {}
    if resolve and live_ips and not _cancelled():
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, len(live_ips))
        ) as pool:
            for ip, name in pool.map(_resolve_one, live_ips):
                if name:
                    names[ip] = name

    hosts: list[Host] = []
    for ip in sorted(live_ips, key=_ip_key):
        mac = arp_ok.get(ip, "")
        if not mac:
            mac, state = neigh.get(ip, ("", ""))
            if state in DEAD_ARP_STATES:
                mac = ""
        if ip == self_ip and not mac:
            mac = _self_mac(chosen.name)
        vendor = vendor_from_mac(mac) if mac else ""
        host = Host(
            ip=ip,
            mac=mac,
            hostname=names.get(ip, ""),
            vendor=vendor,
            icmp=ip in icmp_ok or ip == self_ip,
            arp=bool(mac) and ip != self_ip,
            is_self=ip == self_ip,
            is_gateway=ip == gateway,
        )
        if ip == self_ip:
            host.icmp = True
            if not host.hostname:
                host.hostname = socket.gethostname()
        if host.is_gateway and not host.hostname:
            host.hostname = "_gateway"
        hosts.append(host)

    elapsed = time.time() - t0
    return ScanResult(
        iface=chosen.name,
        subnet=str(net),
        self_ip=self_ip,
        gateway=gateway,
        elapsed_sec=elapsed,
        probed=total,
        hosts=hosts,
    )


def _self_mac(iface: str) -> str:
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path, encoding="ascii") as fh:
            return fh.read().strip().lower()
    except OSError:
        return ""


def format_table(result: ScanResult) -> str:
    rows = result.live
    headers = ("IP", "HOSTNAME", "MAC", "VENDOR", "METHOD")
    body: list[tuple[str, ...]] = []
    for h in rows:
        body.append((h.ip, h.hostname, h.mac, h.vendor, h.method))
    cols = list(zip(*([headers] + body))) if body else [[h] for h in headers]
    widths = [max(len(cell) for cell in col) for col in cols]
    def fmt(row: Iterable[str]) -> str:
        return "  ".join(cell.ljust(w) for cell, w in zip(row, widths))
    lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    lines.extend(fmt(r) for r in body)
    lines.append("")
    lines.append(
        f"{len(rows)} live  ·  {result.probed} probed  ·  "
        f"{result.subnet} on {result.iface}  ·  {result.elapsed_sec:.2f}s"
    )
    return "\n".join(lines)
