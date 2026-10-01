"""Regular expressions and validators for indicator extraction.

Domain extraction is the main false-positive risk (``System.Management.Automation``,
``kernel32.dll``...), so candidates must end in a known TLD and must not end in
a file extension.
"""

from __future__ import annotations

import ipaddress
import re

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()\]]+", re.I)
DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))\b", re.I)
WIN_PATH = re.compile(r"(?:[a-z]:\\|\\\\[\w.$-]+\\)[^\"'<>|\r\n*?]+?\.(?:exe|dll|sys|ps1|bat|cmd|vbs|vbe|js|jse|hta|scr|"
                      r"tmp|dat|bin|lnk|wsf|msi|ocx|cpl)\b", re.I)
REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT|"
                      r"\\REGISTRY\\(?:MACHINE|USER))\\[^\s\"']+", re.I)
MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)

KNOWN_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "ru", "cn", "su", "xyz", "top", "online", "site", "club",
    "tk", "ml", "ga", "cf", "gq", "pw", "cc", "me", "us", "uk", "de", "fr", "nl", "br", "in", "jp", "kr",
    "tw", "hk", "ua", "ir", "kp", "vn", "id", "pl", "it", "es", "ca", "au", "eu", "edu", "gov", "mil", "int",
    "app", "dev", "cloud", "live", "space", "website", "tech", "store", "shop", "link", "click", "win",
    "work", "zip", "mov", "onion", "example", "test", "invalid", "local", "lan", "corp", "internal", "ws",
}
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "tmp", "dat", "bin", "lnk", "msi",
    "ocx", "cpl", "txt", "log", "ini", "xml", "json", "cfg", "config", "mui", "nls", "pdb", "doc", "docx",
    "xls", "xlsx", "pdf", "zip", "rar", "jpg", "png", "gif", "manifest", "etl", "evtx", "db", "drv",
}


def is_valid_domain(candidate: str) -> bool:
    parts = candidate.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld in FILE_EXTENSIONS and tld not in {"zip", "mov"}:
        return False
    if tld not in KNOWN_TLDS:
        return False
    return not all(p.isdigit() for p in parts)


def classify_ip(value: str) -> str | None:
    """Return 'public', 'private', 'loopback', ... or None if not a valid IP."""
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        # RFC 5737 / 3849 documentation ranges are "private" in ipaddress; report them distinctly.
        if any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
            return "documentation"
        return "private"
    return "public"


def is_external(value: str | None) -> bool:
    """External = routable beyond the local network (documentation ranges count, for the demo dataset)."""
    return bool(value) and classify_ip(value) in {"public", "documentation"}
