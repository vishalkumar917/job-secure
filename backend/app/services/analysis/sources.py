"""Evidence sources feeding the analysis pipeline.

* :class:`VolatilitySource` runs real Volatility 3 plugins against a memory image.
* :class:`DemoSource` replays a synthetic bundle of Volatility-format JSON files
  from ``sample_data/demo_case``. It exists so the platform can be demonstrated
  without a real memory image. Its output is flagged ``synthetic`` end-to-end and
  the UI/report label it "DEMO DATA - NOT REAL FORENSIC EVIDENCE".

Both sources go through the *same* parsers, detection rules, scoring, IOC
extraction and AI layers, so the demo exercises the real engine.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Protocol

from app.services.volatility.parsers import to_int
from app.services.volatility.runner import PluginResult, VolatilityRunner, flatten_tree


class EvidenceSource(Protocol):
    synthetic: bool

    def run(self, plugin: str, *, pids: list[int] | None = None, yara_file: Path | None = None) -> PluginResult:
        ...

    def version(self) -> str | None:
        ...


class VolatilitySource:
    synthetic = False

    def __init__(self, runner: VolatilityRunner, image_path: Path, vol_version: str | None):
        self.runner = runner
        self.image_path = image_path
        self._version = vol_version

    def run(self, plugin: str, *, pids: list[int] | None = None, yara_file: Path | None = None) -> PluginResult:
        return self.runner.run(self.image_path, plugin, pids=pids, yara_file=yara_file)

    def version(self) -> str | None:
        return self._version


class DemoSource:
    synthetic = True

    def __init__(self, bundle_dir: Path):
        self.bundle_dir = bundle_dir
        manifest = bundle_dir / "manifest.json"
        self.manifest = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}

    def run(self, plugin: str, *, pids: list[int] | None = None, yara_file: Path | None = None) -> PluginResult:
        started = time.monotonic()
        path = self.bundle_dir / f"{plugin}.json"
        if not path.exists():
            return PluginResult(plugin, "failed", error="Plugin output is not included in the synthetic demo bundle.",
                                synthetic=True)
        rows = flatten_tree(json.loads(path.read_text(encoding="utf-8")))
        if pids:
            wanted = set(pids)
            rows = [r for r in rows if to_int(r.get("PID", r.get("Pid"))) in wanted]
        time.sleep(0.15)  # make progress visible in the UI; no effect on results
        args = ["--pid", *map(str, sorted(pids))] if pids else []
        return PluginResult(plugin, "success", rows=rows, args=args, synthetic=True,
                            duration_ms=int((time.monotonic() - started) * 1000), output_path=str(path))

    def version(self) -> str | None:
        return f"synthetic demo bundle v{self.manifest.get('version', '1')}"
