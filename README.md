# M1NX VIP APK Analyzer & Restoration Tool

A local PySide6 desktop application for authorized APK inspection, evidence-based comparison, and restoration from a trusted original APK or user-owned source/backup project.

## Safety boundary

This project does **not** bypass licensing, authentication, anti-cheat, DRM, access control, signatures, or third-party protections. Analysis findings are heuristic indicators and are never presented as proof. Automatic restoration only copies a selected trusted original APK or rebuilds a selected source/backup directory with `apktool`.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Optional tools are documented in `tools/README.md`. Use the **APK SELECT**, **START ANALYSIS**, **COMPARE APK**, **RESTORE APK**, and **EXPORT APK** controls in that order where applicable.

## Build ZIP

```bash
python scripts/build_zip.py
```
