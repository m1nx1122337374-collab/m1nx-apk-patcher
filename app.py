from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from flask import Flask, flash, redirect, render_template_string, request, send_file, url_for
from werkzeug.utils import secure_filename

from core.analyzer import APKAnalyzer
from core.restoration import RestorationService

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "m1nx-local-analysis-change-me")
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024
BASE = Path(os.environ.get("M1NX_WORKDIR", tempfile.gettempdir())) / "m1nx-apk-analyzer"
UPLOADS, OUTPUTS = BASE / "uploads", BASE / "outputs"
UPLOADS.mkdir(parents=True, exist_ok=True); OUTPUTS.mkdir(parents=True, exist_ok=True)
analyzer, restorer = APKAnalyzer(), RestorationService()

PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M1NX VIP APK ANALYZER</title><style>
:root{--bg:#0b1020;--card:#111a30;--line:#26395f;--text:#edf2ff;--muted:#95a6ca;--blue:#5d7cf2;--green:#2b9377;--amber:#a96f35}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#1a2d5a 0,transparent 35%),var(--bg);color:var(--text);font:15px Inter,system-ui,sans-serif}.wrap{max-width:1120px;margin:auto;padding:32px 20px}.hero{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:24px}.eyebrow{color:#7896ef;letter-spacing:2px;font-size:12px;font-weight:800}.title{font-size:clamp(30px,5vw,54px);line-height:.95;margin:8px 0;font-weight:900}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:760px){.grid{grid-template-columns:1fr}.hero{display:block}}.card{background:rgba(17,26,48,.9);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 18px 50px #0003}.drop{border:1px dashed #5574bd;background:#101d38;border-radius:14px;padding:30px;text-align:center}.drop input{max-width:100%;margin-top:14px}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:15px}button,.button{border:0;border-radius:9px;padding:12px 16px;color:#fff;font-weight:800;text-decoration:none;cursor:pointer;background:var(--blue)}button.green,.button.green{background:var(--green)}button.amber{background:var(--amber)}pre{white-space:pre-wrap;word-break:break-word;background:#0a1020;border:1px solid #1f3154;border-radius:12px;padding:15px;color:#cbd7ef;max-height:520px;overflow:auto}.flash{padding:12px;border-radius:10px;background:#42252b;color:#ffbec6;margin-bottom:15px}.badge{display:inline-block;color:#9fb7ff;background:#1c2c50;border-radius:20px;padding:5px 10px;margin:3px;font-size:12px}.note{font-size:12px;color:#8495b7;margin-top:22px}
</style></head><body><div class="wrap"><div class="hero"><div><div class="eyebrow">M1NX VIP / AUTHORIZED TOOLING</div><div class="title">APK ANALYZER<br>& RESTORATION</div><p class="muted">Evidence-based inspection for APKs you own or are authorized to analyze.</p></div><span class="badge">RENDER READY</span></div>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{message}}</div>{% endfor %}{% endwith %}
<div class="grid"><section class="card"><h2>1. Deep Analysis</h2><form action="{{url_for('analyze')}}" method="post" enctype="multipart/form-data"><div class="drop">Drop an APK here or select a file<br><input type="file" name="apk" accept=".apk" required></div><div class="actions"><button type="submit">DEEP ANALYSIS</button></div></form></section>
<section class="card"><h2>2. APK Comparison / Restoration Preview</h2><form action="{{url_for('compare')}}" method="post" enctype="multipart/form-data"><p class="muted">Preview changed, added, removed, DEX, resources, manifest and native components before writing anything.</p><input type="file" name="original" accept=".apk" required><br><br><input type="file" name="modified" accept=".apk" required><div class="actions"><button type="submit">COMPARE / PREVIEW</button></div></form></section>
<section class="card"><h2>3. RESTORE ORIGINAL APK</h2><form action="{{url_for('restore')}}" method="post" enctype="multipart/form-data"><p class="muted">Uses the previewed trusted-original bytes to reconstruct only selected components; unknown components are never auto-deleted.</p><label>Modified APK<br><input type="file" name="modified" accept=".apk" required></label><br><label>Trusted original APK<br><input type="file" name="original" accept=".apk" required></label><br><label><input type="checkbox" name="remove_added" value="yes"> remove added files only after reviewing the preview</label><div class="actions"><button class="amber" type="submit">RESTORE ORIGINAL APK</button></div></form></section>
<section class="card"><h2>Safety boundary</h2><p class="muted">Findings are heuristic indicators, not proof. The service does not bypass authentication, licensing, anti-cheat, DRM, signatures, or access controls.</p><p class="note">For large APKs, use a private deployment and configure appropriate storage/retention policies.</p></section></div>
{% if result %}<section class="card" style="margin-top:18px"><h2>Report</h2><pre>{{result}}</pre></section>{% endif %}</div></body></html>
"""


def save_upload(file_storage, suffix=".apk") -> Path:
    if not file_storage or not file_storage.filename or not file_storage.filename.lower().endswith(".apk"):
        raise ValueError("Please upload an APK file")
    name = secure_filename(file_storage.filename) or f"upload{suffix}"
    path = UPLOADS / f"{uuid.uuid4().hex}_{name}"
    file_storage.save(path)
    return path


@app.get("/")
def index():
    return render_template_string(PAGE, result=None)


@app.post("/analyze")
def analyze():
    try:
        data = analyzer.inspect(save_upload(request.files.get("apk")))
        return render_template_string(PAGE, result=json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as exc:
        flash(str(exc)); return redirect(url_for("index"))


@app.post("/compare")
def compare():
    try:
        original, modified = save_upload(request.files.get("original")), save_upload(request.files.get("modified"))
        data = analyzer.compare(original, modified)
        data["restoration_preview"] = {"would_replace_from_trusted_original": sorted(set(data["changed"]) | set(data["removed"])),
                                        "would_preserve_from_modified": data["same"],
                                        "added_files_require_explicit_review": data["added"],
                                        "no_archive_written": True}
        return render_template_string(PAGE, result=json.dumps(data, indent=2, ensure_ascii=False))
    except Exception as exc:
        flash(str(exc)); return redirect(url_for("index"))


@app.post("/restore")
def restore():
    try:
        modified = save_upload(request.files.get("modified"))
        source = save_upload(request.files.get("original"))
        output = OUTPUTS / f"M1NX_restored_{uuid.uuid4().hex[:8]}.apk"
        report = restorer.restore_components(modified, source, output, replace_changed=True, remove_added=request.form.get("remove_added") == "yes")
        report["download_url"] = url_for("download", filename=output.name)
        return render_template_string(PAGE, result=json.dumps(report, indent=2, ensure_ascii=False))
    except Exception as exc:
        flash(str(exc)); return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum upload size is 300 MB."); return redirect(url_for("index"))


@app.get("/download/<filename>")
def download(filename):
    path = (OUTPUTS / secure_filename(filename)).resolve()
    if path.parent != OUTPUTS.resolve() or not path.is_file():
        flash("Export file not found or expired"); return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name="M1NX_restored.apk", mimetype="application/vnd.android.package-archive")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
