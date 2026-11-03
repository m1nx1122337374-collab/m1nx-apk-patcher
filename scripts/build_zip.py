from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

root = Path(__file__).resolve().parents[1]
out = root.parent / "M1NX_VIP_APK_ANALYZER.zip"
if out.exists():
    out.unlink()
with ZipFile(out, "w", ZIP_DEFLATED) as archive:
    for path in root.rglob("*"):
        if path.is_dir() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        archive.write(path, Path(root.name) / path.relative_to(root))
print(out)
