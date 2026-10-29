#!/usr/bin/env python3
"""CLI for LAN IPv4 host discovery."""

from __future__ import annotations

import argparse
import csv
import json
import sys

from scanner import ScanResult, format_table, list_ifaces, scan_lan


def _progress(done: int, total: int, _ip: str) -> None:
    if not sys.stderr.isatty():
        return
    width = 28
    filled = int(width * done / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    sys.stderr.write(f"\r  [{bar}] {done}/{total}")
    if done >= total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="Find live IPv4 hosts on the local LAN (ICMP ping + ARP).",
    )
    p.add_argument("-i", "--iface", help="interface name (default: first global IPv4)")
    p.add_argument("-s", "--subnet", help="IPv4 CIDR to scan (default: the iface network)")
    p.add_argument("-t", "--timeout", type=int, default=1, help="ping timeout seconds (default: 1)")
    p.add_argument("-w", "--workers", type=int, default=128, help="parallel ping workers")
    p.add_argument("--max-hosts", type=int, default=1024, dest="max_hosts")
    p.add_argument("--no-resolve", action="store_true", help="skip mDNS / NetBIOS / DNS names")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.add_argument("--csv", metavar="FILE", help="write CSV to FILE")
    p.add_argument("--list-ifaces", action="store_true", help="print local IPv4 interfaces and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress bar")
    return p


def write_csv(path: str, result: ScanResult) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "hostname", "mac", "vendor", "method", "icmp", "arp", "self", "gateway"])
        for h in result.live:
            w.writerow(
                [
                    h.ip,
                    h.hostname,
                    h.mac,
                    h.vendor,
                    h.method,
                    int(h.icmp),
                    int(h.arp),
                    int(h.is_self),
                    int(h.is_gateway),
                ]
            )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_ifaces:
        ifaces = list_ifaces()
        if not ifaces:
            print("No IPv4 interfaces.", file=sys.stderr)
            return 1
        for i in ifaces:
            print(f"{i.name:16} {i.cidr:22} {i.network}")
        return 0

    try:
        result = scan_lan(
            iface=args.iface,
            subnet=args.subnet,
            timeout=args.timeout,
            workers=args.workers,
            resolve=not args.no_resolve,
            max_hosts=args.max_hosts,
            progress=None if args.quiet or args.json else _progress,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.csv:
        write_csv(args.csv, result)

    if args.json:
        json.dump(result.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(format_table(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
