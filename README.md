# M1NX VIP APK Analyzer & Restoration Tool

A Render-compatible Flask web application for authorized APK inspection, evidence-based comparison, and restoration from a trusted original APK.

## Safety boundary

This project does **not** bypass licensing, authentication, anti-cheat, DRM, access control, signatures, or third-party protections. Findings are heuristic indicators and are never presented as proof. The RESTORE flow only returns a user-selected trusted original APK; it does not remove protection from a modified APK.

## Render deployment

Connect this repository to Render as a Web Service. The included `render.yaml` sets the build command to `pip install -r requirements.txt` and the start command to `gunicorn app:app`. The included `Aptfile` contains the requested headless Java and xcb packages. Render will use only Flask and Gunicorn from `requirements.txt`; no PySide6 or androguard package is installed.

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gunicorn app:app
```

Open `http://127.0.0.1:8000` when using Gunicorn's default port, or run `python app.py` for the development server. Upload limits are set to 300 MB. For production, use a private service and configure storage/retention policies appropriate for APK files.

The former PySide6 desktop prototype is retained in `main.py` for local desktop use, but Render imports only `app:app` and installs no desktop dependencies.
