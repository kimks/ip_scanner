"""Small OUI (MAC prefix) map. Unknown prefixes return an empty string.

This is a convenience table, not a full IEEE registry.
"""

from __future__ import annotations

# First 3 octets, uppercase, no separators -> vendor
OUI: dict[str, str] = {
    "000C29": "VMware",
    "001A11": "Google",
    "001B63": "Apple",
    "001D0F": "TP-Link",
    "001E06": "Wistron NeWeb",
    "00259D": "Motorola",
    "0050F2": "Microsoft",
    "00D861": "Micro-Star INT'L",
    "00E04C": "Realtek",
    "081077": "NETIS",
    "08ED9D": "Tecno Mobile",
    "0C9D92": "ASUSTeK",
    "104F58": "Hewlett Packard",
    "18D6C7": "TP-Link",
    "1C697A": "EliteGroup",
    "2016D8": "Liteon",
    "247703": "Intel",
    "28D0EA": "Intel",
    "2C56DC": "ASUSTeK",
    "30C599": "ASUSTeK",
    "30CDA7": "Samsung",
    "3C5AB4": "Google",
    "3C7C3F": "ASUSTeK",
    "4851B7": "Intel",
    "4CEDFB": "ASUSTeK",
    "50E4E0": "Hewlett Packard",
    "54E1AD": "LCFC",
    "5CF370": "Apple",
    "605718": "Intel",
    "70B5E8": "Dell",
    "74D435": "GIGA-BYTE",
    "78843C": "Sony",
    "80FA5B": "Wistron Infocomm",
    "88366C": "EFM Networks",
    "88B111": "Intel",
    "8C8CAA": "LCFC",
    "9077EE": "IEEE Registration",
    "98FAE3": "Xiaomi",
    "A4C3F0": "Intel",
    "ACBC32": "Apple",
    "B827EB": "Raspberry Pi",
    "B8AEED": "Elitegroup",
    "C8D9D2": "Hewlett Packard",
    "D05099": "ASRock",
    "D8BBC1": "Micro-Star INT'L",
    "DC4A3E": "Hewlett Packard",
    "DCA632": "Raspberry Pi",
    "E4B97A": "Dell",
    "F0DE41": "Shanghai Xiaoyi",
    "F4F5E8": "Google",
    "FC3497": "ASUSTeK",
}


def vendor_from_mac(mac: str) -> str:
    if not mac:
        return ""
    hex_only = "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")
    if len(hex_only) < 6:
        return ""
    return OUI.get(hex_only[:6], "")
