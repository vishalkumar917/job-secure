"""Upload validation, hashing and evidence preservation."""

from __future__ import annotations

import hashlib
import io
import os
import stat

import pytest

from app.core.exceptions import EvidenceTooLargeError, EvidenceValidationError
from app.services.evidence.storage import (
    compute_evidence_hash,
    inspect_header,
    sanitize_filename,
    sha256_file,
    store_stream,
    validate_extension,
)

BLOB = os.urandom(64 * 1024)


def test_sha256_is_computed_during_intake(settings):
    stored = store_stream(io.BytesIO(BLOB), "case.raw", settings)
    assert stored.sha256 == hashlib.sha256(BLOB).hexdigest()
    assert stored.size_bytes == len(BLOB)
    assert sha256_file(stored.path) == stored.sha256


def test_evidence_is_stored_read_only_under_generated_name(settings):
    stored = store_stream(io.BytesIO(BLOB), "..\\..\\evil name.mem", settings)
    assert stored.path.parent == settings.evidence_dir
    assert "evil" not in stored.path.name  # client-supplied name never used on disk
    assert not (os.stat(stored.path).st_mode & stat.S_IWUSR)
    assert stored.original_filename == "evil name.mem"


@pytest.mark.parametrize("name", ["image.zip", "memory.exe", "noext", "dump.vmss"])
def test_rejects_unsupported_extensions(settings, name):
    with pytest.raises(EvidenceValidationError):
        validate_extension(name, settings)


@pytest.mark.parametrize("ext", [".raw", ".mem", ".dmp", ".vmem", ".RAW"])
def test_accepts_supported_extensions(settings, ext):
    assert validate_extension("x" + ext, settings) == ext.lower()


@pytest.mark.parametrize("header,needle", [
    (b"PK\x03\x04" + b"\x00" * 100, "ZIP"),
    (b"%PDF-1.7" + b"\x00" * 100, "PDF"),
    (b"MDMP" + b"\x00" * 100, "minidump"),
    (b"\x7fELF" + b"\x00" * 100, "ELF"),
    (b"hibr" + b"\x00" * 100, "hibernation"),
])
def test_rejects_non_memory_signatures(settings, header, needle):
    with pytest.raises(EvidenceValidationError, match=needle):
        inspect_header(header, ".raw", 10 * 1024 * 1024, settings)


def test_rejects_pe_executable(settings):
    hdr = bytearray(512)
    hdr[0:2] = b"MZ"
    hdr[0x3C:0x40] = (0x80).to_bytes(4, "little")
    hdr[0x80:0x84] = b"PE\x00\x00"
    with pytest.raises(EvidenceValidationError, match="PE executable"):
        inspect_header(bytes(hdr), ".raw", 10 * 1024 * 1024, settings)


def test_rejects_truncated_file(settings):
    with pytest.raises(EvidenceValidationError, match="truncated"):
        inspect_header(b"\x00" * 10, ".raw", 100, settings)


def test_crash_dump_header_detected(settings):
    fmt, notes = inspect_header(b"PAGEDU64" + b"\x00" * 100, ".dmp", 10 * 1024 * 1024, settings)
    assert fmt == "crashdump" and "64-bit" in notes[0]


def test_dmp_without_header_is_treated_as_raw_with_note(settings):
    fmt, notes = inspect_header(b"\x00" * 100, ".dmp", 10 * 1024 * 1024, settings)
    assert fmt == "raw" and any("PAGEDUMP" in n for n in notes)


def test_size_limit_enforced_and_temp_cleaned(settings, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 32 * 1024)
    before = set(settings.upload_tmp_dir.iterdir())
    with pytest.raises(EvidenceTooLargeError):
        store_stream(io.BytesIO(BLOB), "big.raw", settings)
    assert set(settings.upload_tmp_dir.iterdir()) == before


def test_invalid_upload_leaves_no_partial_file(settings):
    before = set(settings.upload_tmp_dir.iterdir()) | set(settings.evidence_dir.iterdir())
    with pytest.raises(EvidenceValidationError):
        store_stream(io.BytesIO(b"PK\x03\x04" + BLOB), "archive.raw", settings)
    assert set(settings.upload_tmp_dir.iterdir()) | set(settings.evidence_dir.iterdir()) == before


def test_sanitize_filename_strips_paths_and_controls():
    assert sanitize_filename("C:\\Users\\x\\..\\a<b>.raw") == "a_b_.raw"
    assert sanitize_filename("") == "unnamed"


def test_directory_manifest_hash_is_deterministic(tmp_path):
    (tmp_path / "a.json").write_text("1")
    (tmp_path / "b.json").write_text("2")
    h1 = compute_evidence_hash(tmp_path)
    assert h1 == compute_evidence_hash(tmp_path)
    (tmp_path / "b.json").write_text("3")
    assert compute_evidence_hash(tmp_path) != h1
