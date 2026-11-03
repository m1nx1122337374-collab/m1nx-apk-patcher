from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any


CATEGORY_RULES = {
    "dex": lambda n: n.endswith(".dex"),
    "resources": lambda n: n.startswith("res/") or n in {"resources.arsc", "resources.pb"},
    "manifest": lambda n: n == "AndroidManifest.xml",
    "native_libraries": lambda n: n.startswith("lib/") and n.endswith(".so"),
    "assets": lambda n: n.startswith("assets/"),
    "signing": lambda n: n.startswith("META-INF/") or n.startswith("META-INF"),
}


class APKAnalyzer:
    """Static, evidence-first APK inspection. It never modifies an input APK."""

    def inspect(self, apk_path: str | Path) -> dict[str, Any]:
        apk = self._validate(apk_path)
        with zipfile.ZipFile(apk) as zf:
            files = self._file_map(zf)
            payloads = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/")}
            names = sorted(files)
            result: dict[str, Any] = {
                "file": apk.name, "path": str(apk.resolve()), "size": apk.stat().st_size,
                "sha256": self._sha256(apk), "package": "Unknown", "version": "Unknown",
                "archive": {"file_count": len(names), "dex_count": len(self._category(names, "dex")),
                            "resource_count": len(self._category(names, "resources")),
                            "native_library_count": len(self._category(names, "native_libraries"))},
                "signature": self._signature_info(apk, names),
                "protection_report": [], "warnings": [], "tools": [],
            }
            result["package"], result["version"], tool = self._manifest_metadata(apk)
            if tool: result["tools"].append(tool)
            result["protection_report"] = self._protection_report(payloads, names)
            result["components"] = {key: self._category(names, key) for key in CATEGORY_RULES}
            result["warnings"].append("A static APK cannot prove runtime behavior. Items labelled heuristic or unverified require source/build evidence or controlled testing.")
            return result

    def compare(self, left: str | Path, right: str | Path) -> dict[str, Any]:
        left_path, right_path = self._validate(left), self._validate(right)
        with zipfile.ZipFile(left_path) as a, zipfile.ZipFile(right_path) as b:
            amap, bmap = self._file_map(a), self._file_map(b)
        added = sorted(set(bmap) - set(amap)); removed = sorted(set(amap) - set(bmap))
        changed = sorted(n for n in set(amap) & set(bmap) if amap[n] != bmap[n])
        same = sorted(n for n in set(amap) & set(bmap) if amap[n] == bmap[n])
        category_changes = {}
        for category in CATEGORY_RULES:
            aa, bb = set(self._category(amap, category)), set(self._category(bmap, category))
            category_changes[category] = {
                "added": sorted(bb - aa), "removed": sorted(aa - bb),
                "changed": sorted(n for n in aa & bb if amap[n] != bmap[n]),
                "unchanged": sorted(n for n in aa & bb if amap[n] == bmap[n]),
            }
        return {"left": str(left_path.resolve()), "right": str(right_path.resolve()),
                "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "unchanged": len(same)},
                "added": added, "removed": removed, "changed": changed, "same": same,
                "category_changes": category_changes,
                "manifest_changed": "AndroidManifest.xml" in changed or "AndroidManifest.xml" in added or "AndroidManifest.xml" in removed,
                "dex_changed": bool(category_changes["dex"]["changed"] or category_changes["dex"]["added"] or category_changes["dex"]["removed"]),
                "native_changed": bool(category_changes["native_libraries"]["changed"] or category_changes["native_libraries"]["added"] or category_changes["native_libraries"]["removed"])}

    def _protection_report(self, files: dict[str, bytes], names: list[str]) -> list[dict[str, Any]]:
        report: list[dict[str, Any]] = []
        def add(name: str, status: str, confidence: str, evidence: list[str], explanation: str):
            report.append({"component": name, "status": status, "confidence": confidence, "evidence": evidence, "explanation": explanation})
        certs = self._category(names, "signing")
        add("APK Signature Information", "confirmed" if certs else "unknown", "high" if certs else "low", certs or ["No META-INF signature entries"], "Certificate filenames prove archive signature entries exist, but only apksigner can validate the signing scheme and certificate chain.")
        native = self._category(names, "native_libraries")
        add("Native Libraries", "confirmed" if native else "not observed", "high", native[:40] or ["No lib/**/*.so entries"], "Native library files are directly observable in the APK archive.")
        dex = self._category(names, "dex")
        add("Dex Protection", "heuristic" if len(dex) > 1 else "unknown", "medium" if len(dex) > 1 else "low", dex or ["No DEX entries found"], "Multiple DEX files are not proof of protection; runtime loaders and source/build evidence are required.")
        blob = b"\n".join(files[n][:2_000_000] for n in names if n.endswith((".dex", ".so", ".bin")))
        marker_groups = {
            "ScKit Shield": [b"scmain", b"scikit", b"sckit", b"sc_protect"],
            "Virbox / Techdavisk VM": [b"virbox", b"techdavisk", b"dongbao", b"tdvm"],
        }
        for component, markers in marker_groups.items():
            hits = [m.decode("ascii", "ignore") for m in markers if m in blob.lower()]
            add(component, "heuristic" if hits else "not observed", "medium" if hits else "low", hits or ["No known marker found in inspected DEX/native bytes"], "A marker is an indicator only; it does not prove the protection is active or belongs to this vendor.")
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in blob[:8_000_000]) / max(1, len(blob[:8_000_000]))
        string_status = "heuristic" if printable < 0.22 and blob else "unknown"
        add("String Encryption", string_status, "low", [f"Printable-byte ratio in inspected code/native payloads: {printable:.2%}"], "Low printable density can result from compiled code, compression, packing, or encryption; it is not proof of encrypted strings.")
        class_tokens = re.findall(rb"L[a-zA-Z0-9_$]{1,3}/[a-zA-Z0-9_$]{1,3};", blob)
        obf = len(class_tokens) > 15
        add("Code Obfuscation", "heuristic" if obf else "unknown", "low", [f"Short class-token matches: {len(class_tokens)}"], "Short identifiers are a weak heuristic. A decompiler or mapping file is needed for confirmation.")
        suspicious = [n for n in names if any(x in n.lower() for x in ("patch", "inject", "hook", "frida", "substrate"))]
        add("Suspicious or Modified Components", "heuristic" if suspicious else "not observed", "low" if suspicious else "low", suspicious[:40] or ["No suspicious archive-name indicator"], "Names alone are never proof; compare hashes against a trusted build.")
        add("Anti-Tamper Indicators", "unverified", "low", ["No runtime execution test performed"], "Static inspection cannot confirm anti-tamper behavior. Review manifest, native code, and controlled runtime logs if authorized.")
        return report

    def _manifest_metadata(self, apk: Path) -> tuple[str, str, str | None]:
        if shutil.which("aapt2"):
            try:
                proc = subprocess.run(["aapt2", "dump", "badging", str(apk)], capture_output=True, text=True, timeout=15)
                match = re.search(r"package: name='([^']+)'(?: versionCode='[^']*')? versionName='([^']*)'", proc.stdout)
                if match: return match.group(1), match.group(2) or "Unknown", "aapt2"
            except subprocess.SubprocessError: pass
        return "Unknown", "Unknown", None

    @staticmethod
    def _signature_info(apk: Path, names: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {"archive_entries": [n for n in names if n.startswith("META-INF/")], "apksigner": "not available"}
        if shutil.which("apksigner"):
            try:
                proc = subprocess.run(["apksigner", "verify", "--verbose", str(apk)], capture_output=True, text=True, timeout=30)
                result["apksigner"] = "valid" if proc.returncode == 0 else "invalid or unverifiable"
                result["evidence"] = (proc.stdout + proc.stderr).strip()[-3000:]
            except subprocess.SubprocessError as exc: result["evidence"] = str(exc)
        return result

    @staticmethod
    def _file_map(zf: zipfile.ZipFile) -> dict[str, str]:
        return {n: hashlib.sha256(zf.read(n)).hexdigest() for n in zf.namelist() if not n.endswith("/")}

    @staticmethod
    def _category(values: dict[str, Any] | list[str], category: str) -> list[str]:
        items = values.keys() if isinstance(values, dict) else values
        return sorted(n for n in items if CATEGORY_RULES[category](n))

    @staticmethod
    def _validate(path: str | Path) -> Path:
        p = Path(path)
        if not p.is_file() or p.suffix.lower() != ".apk": raise ValueError("Please select a valid APK file")
        with zipfile.ZipFile(p) as zf:
            if "AndroidManifest.xml" not in zf.namelist(): raise ValueError("The archive has no AndroidManifest.xml and is not a valid APK")
        return p

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def write_json(data: dict[str, Any], destination: str | Path) -> None:
        Path(destination).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
