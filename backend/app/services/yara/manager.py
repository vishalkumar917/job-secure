"""YARA rule management: validation of uploaded rules and assembly of a scan bundle.

Uploaded rules are untrusted input. They are size-limited, must be UTF-8 text,
may not use ``include`` directives (which could read arbitrary files on the
server) and are compiled with yara-python when it is installed. Enabled rule
files are concatenated into one bundle inside the job work directory, which is
the only YARA path the Volatility runner accepts.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path

from app.core.exceptions import EvidenceValidationError

MAX_RULE_BYTES = 1024 * 1024
_RULE_DECL = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]{0,127})\b", re.M)
_INCLUDE = re.compile(r"^\s*include\s+\"", re.M)
_IMPORT = re.compile(r"^\s*import\s+\"[a-z0-9_]+\"\s*$", re.M)
_SEVERITY = re.compile(r"severity\s*=\s*\"(info|low|medium|high|critical)\"", re.I)


@dataclass
class RuleFileInfo:
    rule_names: list[str]
    severities: dict[str, str]
    sha256: str
    compiled_check: bool


def yara_python_available() -> bool:
    return importlib.util.find_spec("yara") is not None


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def parse_rule_text(text: str) -> tuple[list[str], dict[str, str]]:
    clean = _strip_comments(text)
    names = _RULE_DECL.findall(clean)
    severities: dict[str, str] = {}
    # Associate each rule with the severity declared in its meta block (if any).
    positions = [(m.start(), m.group(1)) for m in _RULE_DECL.finditer(clean)] + [(len(clean), "")]
    for (start, name), (end, _) in zip(positions, positions[1:]):
        m = _SEVERITY.search(clean[start:end])
        if m:
            severities[name] = m.group(1).lower()
    return names, severities


def validate_rule_bytes(data: bytes) -> RuleFileInfo:
    if len(data) > MAX_RULE_BYTES:
        raise EvidenceValidationError("YARA rule file exceeds 1 MiB.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceValidationError("YARA rule file must be UTF-8 text.") from exc
    if _INCLUDE.search(_strip_comments(text)):
        raise EvidenceValidationError("YARA 'include' directives are not permitted in uploaded rules.")
    names, severities = parse_rule_text(text)
    if not names:
        raise EvidenceValidationError("No YARA rule declarations found in file.")
    if _strip_comments(text).count("{") != _strip_comments(text).count("}"):
        raise EvidenceValidationError("Unbalanced braces - the YARA rule file is malformed.")
    compiled = False
    if yara_python_available():
        import yara  # type: ignore[import-not-found]

        try:
            yara.compile(source=text)
            compiled = True
        except yara.SyntaxError as exc:  # type: ignore[attr-defined]
            raise EvidenceValidationError(f"YARA syntax error: {exc}") from exc
    return RuleFileInfo(names, severities, hashlib.sha256(data).hexdigest(), compiled)


def build_bundle(rule_files: list[Path], dest: Path) -> tuple[Path | None, dict[str, str]]:
    """Concatenate rule files into ``dest`` (imports hoisted). Returns (path, rule->severity)."""
    imports: set[str] = set()
    bodies: list[str] = []
    severities: dict[str, str] = {}
    seen_rules: set[str] = set()
    for f in rule_files:
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        names, sev = parse_rule_text(text)
        if any(n in seen_rules for n in names):
            continue  # duplicate rule names would make the bundle fail to compile
        seen_rules.update(names)
        severities.update(sev)
        imports.update(m.group(0).strip() for m in _IMPORT.finditer(text))
        bodies.append(f"// ---- {f.name}\n" + _IMPORT.sub("", text))
    if not bodies:
        return None, {}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(sorted(imports)) + "\n\n" + "\n\n".join(bodies), encoding="utf-8")
    return dest, severities
