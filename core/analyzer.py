from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any


class APKAnalyzer:
    """Evidence-based APK inspection. It never modifies an input APK."""

    def inspect(self, apk_path: str | Path) -> dict[str, Any]:
        apk = Path(apk_path)
        if not apk.is_file() or apk.suffix.lower() != ".apk":
            raise ValueError("Please select a valid .apk file")
        result: dict[str, Any] = {
            "file": apk.name,
            "path": str(apk.resolve()),
            "size": apk.stat().st_size,
            "sha256": self._sha256(apk),
            "package": "Unknown",
            "version": "Unknown",
            "entries": [],
            "signals": [],
            "warnings": [],
            "tools": [],
        }
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            result["entries"] = names
            result["dex_count"] = len([n for n in names if re.fullmatch(r"classes\d*\.dex", n)])
            result["native_libs"] = len([n for n in names if n.startswith("lib/") and n.endswith(".so")])
            result["certificate_files"] = [n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
            result["package"], result["version"] = self._manifest_metadata(apk)
            self._signals(result, names)
        return result

    def compare(self, left: str | Path, right: str | Path) -> dict[str, Any]:
        def listing(path: str | Path) -> dict[str, str]:
            with zipfile.ZipFile(path) as zf:
                return {n: hashlib.sha256(zf.read(n)).hexdigest() for n in zf.namelist() if not n.endswith("/")}
        a, b = listing(left), listing(right)
        return {
            "left": str(Path(left).resolve()),
            "right": str(Path(right).resolve()),
            "added": sorted(set(b) - set(a)),
            "removed": sorted(set(a) - set(b)),
            "changed": sorted(n for n in set(a) & set(b) if a[n] != b[n]),
            "same": sorted(n for n in set(a) & set(b) if a[n] == b[n]),
        }

    def _signals(self, result: dict[str, Any], names: list[str]) -> None:
        low = [n.lower() for n in names]
        def add(name: str, level: str, evidence: str, detail: str) -> None:
            result["signals"].append({"name": name, "level": level, "evidence": evidence, "detail": detail})
        dex = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
        if len(dex) > 1:
            add("Multiple DEX files", "review", ", ".join(dex), "Multiple DEX files are common in large apps; inspect ownership and build history before drawing conclusions.")
        if any("libprotect" in n or "libjiagu" in n or "libsec" in n for n in low):
            add("Native security-related library indicator", "review", "matched native library name", "This is only a filename indicator, not proof of a protection mechanism.")
        if any("obfus" in n or "string" in n and "encrypt" in n for n in low):
            add("Protection naming indicator", "review", "matched archive path", "A path/name alone cannot establish that protection is active.")
        short = [n for n in names if n.endswith(".dex") and len(Path(n).name) <= 12]
        if short and len(short) == len(dex):
            add("DEX files present", "info", ", ".join(short), "DEX bytecode is present; obfuscation requires deeper code-level evidence.")
        if not result["certificate_files"]:
            add("No APK signing certificate entry", "warning", "META-INF certificate entry absent", "The package may be unsigned, APK Signature Scheme-only, or malformed. Verify with apksigner when available.")
        if "AndroidManifest.xml" not in names:
            add("Missing AndroidManifest.xml", "warning", "archive entry absent", "This does not look like a valid installable APK.")
        suspicious = [n for n in names if n.startswith(("assets/.", "res/.", "lib/.")) or "patch" in n.lower()]
        if suspicious:
            add("Suspicious modification indicators", "review", ", ".join(suspicious[:12]), "These paths need comparison with a trusted original; they are not automatically malicious or fake.")
        result["warnings"].append("Heuristics are evidence, not proof. Use a trusted original/source and review the report before restoration.")

    def _manifest_metadata(self, apk: Path) -> tuple[str, str]:
        try:
            proc = subprocess.run(["aapt2", "dump", "badging", str(apk)], capture_output=True, text=True, timeout=15)
            text = proc.stdout
            m = re.search(r"package: name='([^']+)' versionName='([^']*)'", text)
            if m:
                return m.group(1), m.group(2) or "Unknown"
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        return "Unknown", "Unknown"

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def write_json(data: dict[str, Any], destination: str | Path) -> None:
        Path(destination).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
