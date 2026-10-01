"""Hardened subprocess wrapper around the Volatility 3 CLI.

Security controls for running a parser over untrusted input:

* ``shell=False`` with an argv list - no shell interpretation of any value.
* Plugin names come from an allow-list; only ``--pid`` (integers) and
  ``--yara-file`` (a path inside the managed YARA directories) may be passed.
  Dump/output flags are never permitted, so Volatility cannot write extracted
  binaries to disk.
* The evidence path must exist inside the evidence store.
* Each run gets its own working directory under the job's work dir.
* A minimal environment is passed: variables that look like secrets
  (``*KEY*``, ``*TOKEN*``, ``*SECRET*``, ``*PASSWORD*``) are stripped.
* Per-plugin timeout; on timeout the whole process group is killed.
* Output size cap to protect the database/parser from pathological output.
* Raw JSON output is kept on disk with its SHA-256 for reproducibility.

Process-level isolation (non-root user, memory/CPU limits, read-only evidence
mount, no network) is provided by the Docker deployment.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.core.exceptions import VolatilityUnavailableError
from app.core.logging import get_logger
from app.services.volatility.plugins import ALLOWED_PLUGINS, PLUGINS

log = get_logger(__name__)

_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
_MAX_PIDS = 64
_UNKNOWN_PLUGIN = "Plugin not available in this Volatility version"


@dataclass
class PluginResult:
    plugin: str
    status: str  # success | failed | timeout | skipped
    rows: list[dict[str, Any]] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    output_path: str | None = None
    output_sha256: str | None = None
    synthetic: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "success"


def flatten_tree(rows: list[dict[str, Any]], depth: int = 0) -> list[dict[str, Any]]:
    """Volatility's JSON renderer nests TreeGrid children under ``__children``."""
    flat: list[dict[str, Any]] = []
    for row in rows:
        children = row.get("__children") or []
        item = {k: v for k, v in row.items() if k != "__children"}
        item["__depth"] = depth
        flat.append(item)
        if children:
            flat.extend(flatten_tree(children, depth + 1))
    return flat


def explain_volatility_error(stderr: str) -> str:
    """Translate common Volatility failures into investigator-friendly messages."""
    s = stderr.lower()
    if "symbol_table_name" in s or "kernel.layer_name" in s or (
            "unsatisfied requirement" in s and ("symbol" in s or "kernel" in s)):
        return ("Volatility could not satisfy kernel/symbol requirements. Either the file is not a supported "
                "Windows memory image, it is corrupted, or matching Windows symbol tables are unavailable "
                "(enable online symbol download or place symbol packs in VOLATILITY_SYMBOLS_DIR).")
    if "no suitable address space" in s or "unable to validate the plugin requirements" in s:
        return "Volatility could not build a memory layer for this file - the image may be corrupted or unsupported."
    if "no module named" in s:
        return "A Python dependency required by this plugin is missing: " + stderr.strip().splitlines()[-1][:300]
    tail = [ln for ln in stderr.strip().splitlines() if ln.strip()]
    return (tail[-1] if tail else "Volatility exited with an error and no diagnostic output.")[:500]


class VolatilityRunner:
    def __init__(self, settings: Settings, work_dir: Path):
        self.settings = settings
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._base_cmd = self.resolve_command(settings)

    # ------------------------------------------------------------------ discovery
    @staticmethod
    def resolve_command(settings: Settings) -> list[str]:
        if settings.volatility_cmd:
            # Non-POSIX splitting (needed for Windows backslashes) keeps the quotes - strip them.
            return [t.strip('"') for t in shlex.split(settings.volatility_cmd, posix=os.name != "nt")]
        exe = shutil.which("vol") or shutil.which("vol.py")
        if exe:
            return [exe]
        if importlib.util.find_spec("volatility3") is not None:
            return [sys.executable, "-c", "import sys; from volatility3.cli import main; sys.exit(main())"]
        raise VolatilityUnavailableError(
            "Volatility 3 is not installed. Install it with 'pip install volatility3' or set VOLATILITY_CMD. "
            "Demo mode works without Volatility."
        )

    @staticmethod
    def detect(settings: Settings) -> dict[str, Any]:
        try:
            cmd = VolatilityRunner.resolve_command(settings)
        except VolatilityUnavailableError as exc:
            return {"available": False, "version": None, "message": exc.message}
        version = None
        try:
            if importlib.util.find_spec("volatility3") is not None:
                from importlib.metadata import version as pkg_version
                version = pkg_version("volatility3")
        except Exception:  # pragma: no cover - metadata edge cases
            version = None
        return {"available": True, "version": version, "command": cmd[0]}

    # ------------------------------------------------------------------ validation
    def _validate_args(self, plugin: str, pids: list[int] | None, yara_file: Path | None) -> list[str]:
        if plugin not in ALLOWED_PLUGINS:
            raise ValueError(f"Plugin '{plugin}' is not in the allow-list")
        args: list[str] = []
        if pids:
            clean = sorted({int(p) for p in pids if 0 <= int(p) < 2**32})[:_MAX_PIDS]
            if clean:
                args += ["--pid", *[str(p) for p in clean]]
        if yara_file is not None:
            resolved = yara_file.resolve()
            allowed_roots = [self.settings.yara_rules_dir.resolve(), self.settings.user_yara_dir.resolve(),
                             self.work_dir.resolve()]
            if not any(resolved.is_relative_to(root) for root in allowed_roots) or not resolved.is_file():
                raise ValueError("YARA rule file must reside in a managed YARA rules directory")
            args += ["--yara-file", str(resolved)]
        return args

    def _check_image(self, image: Path) -> Path:
        resolved = image.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Evidence file not found: {image.name}")
        if not resolved.is_relative_to(self.settings.evidence_dir.resolve()):
            raise ValueError("Evidence path is outside the evidence store")
        return resolved

    @staticmethod
    def _sanitized_env() -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
        return env

    # ------------------------------------------------------------------ execution
    def run(self, image: Path, plugin: str, *, pids: list[int] | None = None,
            yara_file: Path | None = None, timeout: int | None = None) -> PluginResult:
        """Run a catalogued plugin, trying its CLI name aliases (new name first, legacy name second)."""
        result = PluginResult(plugin, "failed", error="no CLI name configured")
        for cli_name in PLUGINS[plugin].candidates if plugin in PLUGINS else (plugin,):
            result = self._run_once(image, plugin, cli_name, pids, yara_file, timeout)
            if not (result.status == "failed" and result.error and result.error.startswith(_UNKNOWN_PLUGIN)):
                break
        return result

    def _run_once(self, image: Path, plugin: str, cli_name: str, pids: list[int] | None,
                  yara_file: Path | None, timeout: int | None) -> PluginResult:
        timeout = timeout or self.settings.plugin_timeout_seconds
        try:
            image = self._check_image(image)
            plugin_args = self._validate_args(plugin, pids, yara_file)
        except (ValueError, FileNotFoundError) as exc:
            return PluginResult(plugin, "failed", error=str(exc))

        argv = [*self._base_cmd, "-q", "-r", "json", "-f", str(image)]
        if self.settings.volatility_symbols_dir:
            argv += ["-s", str(self.settings.volatility_symbols_dir)]
        if self.settings.volatility_offline:
            argv.append("--offline")
        argv += [cli_name, *plugin_args]

        run_dir = self.work_dir / plugin.replace(".", "_")
        run_dir.mkdir(parents=True, exist_ok=True)
        out_path = run_dir / "output.json"
        err_path = run_dir / "stderr.txt"

        popen_kwargs: dict[str, Any] = {"cwd": run_dir, "env": self._sanitized_env(), "shell": False,
                                        "stdin": subprocess.DEVNULL}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        else:
            popen_kwargs["start_new_session"] = True

        started = time.monotonic()
        with open(out_path, "wb") as out, open(err_path, "wb") as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, **popen_kwargs)  # noqa: S603 - argv validated
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill(proc)
                duration = int((time.monotonic() - started) * 1000)
                return PluginResult(plugin, "timeout", args=plugin_args, duration_ms=duration,
                                    error=f"Plugin exceeded the {timeout}s timeout and was terminated.")
        duration = int((time.monotonic() - started) * 1000)
        stderr = err_path.read_text(encoding="utf-8", errors="replace")[-8000:]
        if rc != 0:  # Volatility prints requirement diagnostics to stdout on failure
            with open(out_path, "rb") as fh:
                stderr += "\n" + fh.read(8000).decode("utf-8", errors="replace")

        if rc != 0:
            if "invalid choice" in stderr.lower() and cli_name in stderr:
                return PluginResult(plugin, "failed", args=plugin_args, duration_ms=duration,
                                    error=f"{_UNKNOWN_PLUGIN}: {cli_name}")
            return PluginResult(plugin, "failed", args=plugin_args, duration_ms=duration,
                                error=explain_volatility_error(stderr))
        if out_path.stat().st_size > self.settings.plugin_max_output_bytes:
            return PluginResult(plugin, "failed", args=plugin_args, duration_ms=duration,
                                error="Plugin output exceeded the configured size limit.")
        raw = out_path.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8", errors="replace") or "[]")
        except json.JSONDecodeError:
            return PluginResult(plugin, "failed", args=plugin_args, duration_ms=duration,
                                error="Volatility output was not valid JSON. " + explain_volatility_error(stderr))
        if not isinstance(data, list):
            data = []
        return PluginResult(plugin, "success", rows=flatten_tree(data), args=plugin_args, duration_ms=duration,
                            output_path=str(out_path), output_sha256=hashlib.sha256(raw).hexdigest())

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            if os.name == "nt":
                proc.kill()
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            log.error("volatility process did not exit after kill", extra={"pid": proc.pid})
