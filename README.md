# M1NX VIP APK Analyzer & Restoration Tool

A Render-compatible Flask web application for authorized APK inspection, evidence-based comparison, component-level reconstruction from a trusted original, verification, and export.

## What it actually does

**Deep Analysis** reads the APK archive and reports directly observable signature entries, native libraries, DEX/resources/manifest inventory, SHA-256, package metadata when `aapt2` is available, and detailed protection findings. ScKit Shield, Virbox/Techdavisk, string encryption, obfuscation, and anti-tamper are reported as confirmed, heuristic, unknown, or unverified with evidence and an explanation. Static evidence is never presented as proof of runtime behavior.

**APK Comparison** hashes every archive entry and reports added, removed, changed, and unchanged files. It also reports manifest, DEX, resources, native-library, signing, and asset category changes.

**Restoration** takes both a modified APK and a trusted original APK. It reconstructs a new archive by preserving unchanged modified entries, replacing changed or missing entries with trusted-original bytes, and optionally removing entries that exist only in the modified APK. It produces a restoration report listing replacements, removals, preserved files, limitations, and verification results. This is not a copy-only button and it does not bypass any protection.

**Verification** checks ZIP integrity, manifest presence, and `apksigner` output when `apksigner` is installed. A rebuilt APK is not claimed to be installable or publisher-signed when the signature is invalid or unavailable; an authorized signing key and device/API testing may still be required.

## Safety boundary

This project does **not** bypass licensing, authentication, anti-cheat, DRM, access control, signatures, or third-party protections. Use it only with APKs and source/backup material you are authorized to analyze and restore.

## Render deployment

Connect this repository to Render as a Web Service. The included `render.yaml` sets the build command to `pip install -r requirements.txt`, binds Gunicorn to Render's `$PORT`, and uses `gunicorn --bind 0.0.0.0:$PORT app:app`. The included `Aptfile` contains the requested headless Java and xcb packages. Render installs only Flask and Gunicorn from `requirements.txt`.

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:8000 app:app
```

Open `http://127.0.0.1:8000`. Optional `aapt2` and `apksigner` tools improve metadata and signature verification. Upload limit is 300 MB.
