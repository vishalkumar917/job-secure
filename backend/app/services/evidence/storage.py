"""Evidence intake: streaming upload, hashing and structural validation.

Uploaded memory images are *untrusted input*. This module:

* only accepts the configured extensions (.raw, .mem, .dmp, .vmem);
* never uses the client-supplied filename on disk (a UUID is used instead);
* streams to a private temp directory, enforcing the size limit while copying;
* computes SHA-256 in the same pass (no second read of a multi-GB file);
* rejects files whose header proves they are *not* a memory image
  (archives, documents, executables, user-mode minidumps ...);
* moves the file into the evidence store and marks it read-only so the
  original evidence is never modified by the analysis pipeline.

Note: a raw memory image has no header, so the definitive validation is
whether Volatility can locate a Windows kernel (``windows.info``). The header
checks here are a cheap first gate, not proof that the file is a valid image.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from app.core.config import Settings
from app.core.exceptions import EvidenceTooLargeError, EvidenceValidationError

CHUNK_SIZE = 4 * 1024 * 1024
HEADER_BYTES = 8192

# Signatures that prove a file is *not* a Windows physical memory image.
_REJECT_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP archive / Office document"),
    (b"%PDF", "PDF document"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"\x7fELF", "ELF executable / Linux core file"),
    (b"MDMP", "user-mode minidump (Volatility 3 requires a full physical memory image or kernel crash dump)"),
    (b"EMiL", "LiME (Linux) memory image - this platform analyses Windows images only"),
]
_HIBERNATION = (b"hibr", b"HIBR", b"wake", b"WAKE")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\- ]+")


@dataclass
class StoredEvidence:
    path: Path
    original_filename: str
    sha256: str
    size_bytes: int
    format_hint: str
    notes: list[str] = field(default_factory=list)


def sanitize_filename(name: str) -> str:
    """Return a display-safe filename (path components and control chars removed)."""
    base = os.path.basename(name.replace("\\", "/")).strip()
    base = _SAFE_NAME.sub("_", base)[:200]
    return base or "unnamed"


def validate_extension(filename: str, settings: Settings) -> str:
    ext = Path(filename).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise EvidenceValidationError(
            f"Unsupported file type '{ext or '(none)'}'. Accepted memory image formats: "
            + ", ".join(settings.allowed_extensions)
        )
    return ext


def inspect_header(header: bytes, ext: str, size: int, settings: Settings) -> tuple[str, list[str]]:
    """Classify the image format from its first bytes. Raises on files that are clearly not memory."""
    notes: list[str] = []
    if size < settings.min_image_bytes:
        raise EvidenceValidationError(
            f"File is {size} bytes; a Windows memory image cannot be smaller than "
            f"{settings.min_image_bytes} bytes. The file is truncated or not a memory image."
        )
    for sig, label in _REJECT_SIGNATURES:
        if header.startswith(sig):
            raise EvidenceValidationError(f"File header identifies a {label}, not a Windows memory image.")
    if header[:4] in _HIBERNATION:
        raise EvidenceValidationError(
            "File appears to be a Windows hibernation file. Convert it to a raw image first "
            "(e.g. Volatility 3 'windows.hibernation.Dump' or hibr2bin) and upload the raw output."
        )
    if header.startswith(b"MZ") and len(header) >= 0x40:
        e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
        if 0 < e_lfanew < len(header) - 4 and header[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            raise EvidenceValidationError("File is a Windows PE executable, not a memory image.")

    if header.startswith(b"PAGEDU64"):
        notes.append("Header: Windows kernel crash dump (64-bit, PAGEDU64).")
        return "crashdump", notes
    if header.startswith(b"PAGEDUMP"):
        notes.append("Header: Windows kernel crash dump (32-bit, PAGEDUMP).")
        return "crashdump", notes
    if ext == ".dmp":
        notes.append(
            "Extension .dmp but no PAGEDUMP/PAGEDU64 crash-dump header found; "
            "the file will be treated as a raw physical memory image."
        )
    if ext == ".vmem":
        notes.append("VMware .vmem (raw guest physical memory). If analysis fails, the matching .vmss/.vmsn may be needed.")
        return "vmware", notes
    notes.append("Raw physical memory image (no file header). Format confirmed only when Volatility locates a kernel.")
    return "raw", notes


def store_stream(stream: BinaryIO, original_filename: str, settings: Settings,
                 declared_size: int | None = None) -> StoredEvidence:
    """Copy an upload stream into the evidence store, hashing and validating as we go."""
    settings.ensure_directories()
    display_name = sanitize_filename(original_filename)
    ext = validate_extension(display_name, settings)
    if declared_size is not None and declared_size > settings.max_upload_bytes:
        raise EvidenceTooLargeError(_too_large_msg(settings))

    token = uuid.uuid4().hex
    tmp_path = settings.upload_tmp_dir / f"{token}.part"
    hasher = hashlib.sha256()
    size = 0
    header = b""
    try:
        with open(tmp_path, "xb") as out:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise EvidenceTooLargeError(_too_large_msg(settings))
                if len(header) < HEADER_BYTES:
                    header += chunk[: HEADER_BYTES - len(header)]
                hasher.update(chunk)
                out.write(chunk)
        format_hint, notes = inspect_header(header, ext, size, settings)
        final_path = settings.evidence_dir / f"{token}{ext}"
        os.replace(tmp_path, final_path)
        make_read_only(final_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    return StoredEvidence(final_path, display_name, hasher.hexdigest(), size, format_hint, notes)


def make_read_only(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_directory_manifest(directory: Path) -> str:
    """Deterministic hash of a directory (used for the synthetic demo bundle)."""
    hasher = hashlib.sha256()
    for f in sorted(p for p in directory.rglob("*") if p.is_file()):
        hasher.update(f.relative_to(directory).as_posix().encode())
        hasher.update(sha256_file(f).encode())
    return hasher.hexdigest()


def compute_evidence_hash(path: Path) -> str:
    return sha256_directory_manifest(path) if path.is_dir() else sha256_file(path)


def _too_large_msg(settings: Settings) -> str:
    return f"File exceeds the maximum permitted size of {settings.max_upload_bytes / 1024**3:.1f} GiB."
