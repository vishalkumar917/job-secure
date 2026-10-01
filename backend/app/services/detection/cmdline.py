"""Command-line analysis helpers: pattern matching and safe decoding of encoded PowerShell.

Decoding is purely textual (Base64 -> UTF-16LE string) for display and pattern
matching; the decoded content is never executed.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from app.services.detection.knowledge import KnowledgeBase

_ENC_ARG = re.compile(
    r"[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+[\"']?([A-Za-z0-9+/=]{16,})", re.I)
_MAX_DECODED = 4000


@dataclass
class CmdlineMatch:
    pattern_id: str
    severity: str
    points: int
    why: str
    attack: list[str]
    matched: str
    in_decoded_payload: bool = False


def decode_powershell(cmdline: str | None) -> str | None:
    """Return the decoded text of a PowerShell -EncodedCommand argument, if present and decodable."""
    if not cmdline or not re.search(r"powershell|pwsh", cmdline, re.I):
        return None
    m = _ENC_ARG.search(cmdline)
    if not m:
        return None
    blob = m.group(1)
    blob += "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.9:
            return text[:_MAX_DECODED]
    return None


def analyze_cmdline(cmdline: str | None, kb: KnowledgeBase) -> tuple[list[CmdlineMatch], str | None]:
    if not cmdline:
        return [], None
    matches: list[CmdlineMatch] = []
    seen: set[str] = set()
    for pat in kb.cmdline_patterns:
        m = pat.regex.search(cmdline)
        if m:
            seen.add(pat.id)
            matches.append(CmdlineMatch(pat.id, pat.severity, pat.points, pat.why, pat.attack, m.group(0)[:300]))
    decoded = decode_powershell(cmdline)
    if decoded:
        for pat in kb.cmdline_patterns:
            if pat.id in seen or pat.id == "PS_ENCODED_COMMAND":
                continue
            m = pat.regex.search(decoded)
            if m:
                matches.append(CmdlineMatch(pat.id, pat.severity, pat.points, pat.why, pat.attack,
                                            m.group(0)[:300], in_decoded_payload=True))
    return matches, decoded
