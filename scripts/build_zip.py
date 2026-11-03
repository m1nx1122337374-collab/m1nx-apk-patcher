from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
out = root.parent / "M1NX_VIP_APK_ANALYZER.zip"
if out.exists(): out.unlink()
shutil.make_archive(str(out.with_suffix("")), "zip", root.parent, root.name)
print(out)
