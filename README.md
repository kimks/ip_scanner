# LAN Sweep (`ip_scanner`)

Find live IPv4 hosts on the local LAN. Same engine for a CLI table and a desktop window.

**How:** ICMP ping of every address in the subnet, then the kernel ARP/neighbor table. Hostnames come from mDNS (`avahi-resolve`), NetBIOS (`nmblookup`), or reverse DNS when those exist.

No extra Python packages. Linux (`ip`, `ping`). Does not open a network listener.

## Run

```sh
cd ip_scanner

# interfaces
python3 cli.py --list-ifaces

# table
python3 cli.py

# JSON / CSV
python3 cli.py --json
python3 cli.py --csv hosts.csv -q

# desktop GUI (needs python3-tk and a display)
python3 gui.py
```

Useful flags: `-i enp131s0`, `-s 192.168.0.0/24`, `-t 1`, `--no-resolve`, `--max-hosts 1024`.

## Layout

| file | role |
|------|------|
| `scanner.py` | shared sweep |
| `cli.py` | command line |
| `gui.py` | Tk window |
| `oui.py` | small MAC-vendor table |

A host is listed if it answers ICMP, still has a confirmed ARP MAC after a re-check, or is this machine.

## Limits

- IPv4 only. Default cap is 1024 addresses (a `/24` is 254).
- Hosts that drop both ICMP and ARP stay invisible.
- The OUI table is a short list, not the full IEEE registry.
- GUI needs `python3-tk`.

## License

MIT. See `LICENSE`.

Repository: https://github.com/kimks/ip_scanner
