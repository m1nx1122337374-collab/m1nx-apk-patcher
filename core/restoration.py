from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from .analyzer import APKAnalyzer


class RestorationService:
    """Rebuilds a modified APK by replacing selected entries with trusted-original bytes.

    It never removes third-party protections or signs an APK with an unknown key.
    """

    def restore_components(self, modified: str | Path, trusted_original: str | Path, output: str | Path,
                           replace_changed: bool = True, remove_added: bool = False) -> dict[str, Any]:
        modified, trusted_original = Path(modified), Path(trusted_original)
        analyzer = APKAnalyzer()
        comparison = analyzer.compare(trusted_original, modified)
        replacement_set = set(comparison["changed"]) | set(comparison["removed"])
        if not replace_changed: replacement_set = set()
        removed_set = set(comparison["added"]) if remove_added else set()
        out = Path(output); out.parent.mkdir(parents=True, exist_ok=True)
        trusted_bytes: dict[str, bytes]
        with zipfile.ZipFile(trusted_original) as original_zip, zipfile.ZipFile(modified) as modified_zip:
            trusted_bytes = {n: original_zip.read(n) for n in original_zip.namelist() if not n.endswith("/")}
            modified_names = [n for n in modified_zip.namelist() if not n.endswith("/")]
            final_names = [n for n in modified_names if n not in removed_set]
            for n in sorted(replacement_set):
                if n in trusted_bytes and n not in final_names: final_names.append(n)
            with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as out_zip:
                for name in final_names:
                    if name in replacement_set and name in trusted_bytes:
                        data = trusted_bytes[name]; source = "trusted_original"
                    else:
                        data = modified_zip.read(name); source = "modified_unchanged"
                    info = modified_zip.getinfo(name) if name in modified_names else zipfile.ZipInfo(name)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    out_zip.writestr(info, data)
        verification = self.verify(out)
        actually_replaced = sorted(n for n in replacement_set if n in trusted_bytes)
        limitations = []
        if verification["signature"] != "valid": limitations.append("The rebuilt archive is not validly signed by the original publisher; install compatibility requires re-signing with an authorized key.")
        if not comparison["manifest_changed"] and "AndroidManifest.xml" not in actually_replaced: limitations.append("Manifest was not changed and was not replaced.")
        limitations.append("Runtime behavior cannot be proven by static archive reconstruction.")
        return {"output": str(out), "replacement_mode": "component-level trusted-source reconstruction", "replaced_files": actually_replaced,
                "removed_added_files": sorted(removed_set), "preserved_modified_files": sorted(set(comparison["same"]) - set(removed_set)),
                "verification": verification, "limitations": limitations, "restoration_occurred": bool(actually_replaced or removed_set)}

    def verify(self, apk_path: str | Path) -> dict[str, Any]:
        apk = Path(apk_path)
        result: dict[str, Any] = {"readable_zip": False, "manifest_present": False, "integrity": "failed", "signature": "not checked", "package_compatibility": "unknown", "evidence": []}
        try:
            with zipfile.ZipFile(apk) as zf:
                bad = zf.testzip(); result["readable_zip"] = bad is None
                result["manifest_present"] = "AndroidManifest.xml" in zf.namelist()
                result["integrity"] = "passed" if bad is None and result["manifest_present"] else "failed"
                result["evidence"].append(f"Archive entries: {len(zf.namelist())}; first bad entry: {bad or 'none'}")
        except zipfile.BadZipFile:
            result["evidence"].append("Not a readable ZIP/APK archive")
        if shutil.which("apksigner"):
            proc = subprocess.run(["apksigner", "verify", "--verbose", str(apk)], capture_output=True, text=True, timeout=30)
            result["signature"] = "valid" if proc.returncode == 0 else "invalid or unverifiable"
            result["evidence"].append((proc.stdout + proc.stderr).strip()[-2500:])
        else:
            result["signature"] = "not checked: apksigner is not installed"
        if result["manifest_present"]:
            result["package_compatibility"] = "manifest present; install compatibility still requires authorized signing and device/API testing"
        return result

    @staticmethod
    def write_json(data: dict[str, Any], destination: str | Path) -> None:
        Path(destination).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
