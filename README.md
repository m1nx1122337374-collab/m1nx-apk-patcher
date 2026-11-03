# M1NX VIP Fake Protection Detector & APK Restoration

A Render-compatible Flask application for authorized APK inspection, evidence-based protection assessment, restoration preview, component-level reconstruction, verification, and export.

## Detection behavior

The Deep Analysis report inspects archive bytes and locations rather than declaring a component fake from a filename. It records evidence for signature entries, DEX, resources, manifest, native libraries, known ScKit Shield and Virbox/Techdavisk markers, string-density indicators, obfuscation indicators, anti-tamper claims, suspicious paths, duplicate payload hashes, custom protection candidates, and cross-file references.

Each assessment has a status such as `confirmed`, `heuristic`, `unknown`, `possible_unnecessary`, or `unverified`. A `possible_unnecessary` result means a candidate was found without an observed cross-file reference; it is **not** permission to delete it. The report explicitly says when functionality cannot be established statically. Unknown components are never automatically removed.

## Restoration workflow

1. Upload the modified APK and a trusted original APK.
2. Run **COMPARE / PREVIEW** to see added, removed, changed, unchanged, manifest, DEX, resource, native-library, signing, and asset differences. No archive is written during preview.
3. Run **RESTORE ORIGINAL APK**. The output preserves unchanged modified entries, replaces changed or missing entries with bytes from the trusted original, and removes added entries only when the explicit checkbox is selected.
4. Review the restoration report listing replaced, preserved, and removed entries, limitations, integrity, signature, and package-compatibility evidence.
5. Download the exported APK only after reviewing the report.

A rebuilt APK is not claimed to be publisher-signed when `apksigner` reports invalid/unverifiable or is unavailable. An authorized signing key and device/API testing may still be needed. The tool does not bypass licensing, authentication, DRM, anti-cheat, access control, signatures, or third-party protections.

## Render deployment

Connect this repository to Render as a Web Service. Use `pip install -r requirements.txt` as the build command and `gunicorn --bind 0.0.0.0:$PORT app:app` as the start command. `render.yaml` contains these settings and the health path `/`. `requirements.txt` contains only Flask and Gunicorn.

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:8000 app:app
```

Optional `aapt2` improves package/version metadata and `apksigner` enables cryptographic signature verification. Upload limit is 300 MB.
