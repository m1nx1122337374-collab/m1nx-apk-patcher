from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class RestorationService:
    """Only restores from a user-selected trusted APK or source/backup directory."""

    def restore_from_apk(self, trusted_apk: str | Path, output: str | Path) -> Path:
        source = Path(trusted_apk)
        if source.suffix.lower() != ".apk" or not source.is_file():
            raise ValueError("A trusted original APK is required")
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    def rebuild_from_source(self, source_dir: str | Path, output: str | Path) -> Path:
        source = Path(source_dir)
        if not source.is_dir():
            raise ValueError("Select a source/backup directory")
        if shutil.which("apktool") is None:
            raise RuntimeError("apktool is not installed. Install it and ensure it is on PATH to rebuild a source project.")
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["apktool", "b", str(source), "-o", str(destination)], check=True, timeout=180)
        return destination

    def verify(self, apk_path: str | Path) -> dict[str, str | bool]:
        apk = Path(apk_path)
        result: dict[str, str | bool] = {"readable_zip": False, "signature": "not checked", "installation_compatibility": "review required"}
        import zipfile
        try:
            with zipfile.ZipFile(apk) as zf:
                result["readable_zip"] = zf.testzip() is None and "AndroidManifest.xml" in zf.namelist()
        except zipfile.BadZipFile:
            result["readable_zip"] = False
        if shutil.which("apksigner"):
            proc = subprocess.run(["apksigner", "verify", "--verbose", str(apk)], capture_output=True, text=True, timeout=30)
            result["signature"] = "valid" if proc.returncode == 0 else "invalid or unverifiable"
            result["apksigner_output"] = (proc.stdout + proc.stderr).strip()[-2000:]
        return result
