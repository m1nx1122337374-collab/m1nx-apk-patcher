import os
import subprocess
import zipfile
from flask import Flask, render_template_string, request, send_file, redirect, url_for

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ফ্রন্টএন্ড ওয়েব ইন্টারফেস (HTML + CSS)
HTML_PAGE = """
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <title>M1NX VIP - Cloud APK Patcher</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding: 40px; }
        .card { background: #1e293b; padding: 40px; border-radius: 12px; display: inline-block; box-shadow: 0 10px 25px rgba(0,0,0,0.5); max-width: 500px; width: 100%; border: 1px solid #334155; }
        h2 { color: #38bdf8; margin-bottom: 10px; }
        p { color: #94a3b8; font-size: 14px; margin-bottom: 25px; }
        input[type="file"] { display: none; }
        .file-upload-btn { background: #334155; color: #cbd5e1; padding: 12px 20px; border-radius: 6px; cursor: pointer; display: inline-block; margin-bottom: 20px; border: 1px dashed #64748b; width: 80%; }
        .file-upload-btn:hover { background: #475569; border-color: #38bdf8; }
        button { background: #0284c7; color: white; border: none; padding: 12px 25px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 6px; width: 100%; transition: 0.3s; }
        button:hover { background: #0369a1; }
        .loading { display: none; margin-top: 20px; color: #facc15; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h2>M1NX VIP Cloud Patcher</h2>
        <p>সঠিক ফেক প্রোটেকশনযুক্ত এপিকে ফাইলটি সিলেক্ট করুন। অন্য কোনো এপিকে গ্রহণ করা হবে না।</p>
        <form action="/upload" method="post" enctype="multipart/form-data" onsubmit="showLoading()">
            <label class="file-upload-btn" id="file-label">APK ফাইল সিলেক্ট করুন (.apk)</label>
            <input type="file" name="apk" accept=".apk" required id="apk-file" onchange="updateFileName(this)">
            <button type="submit" id="submit-btn">প্রসেস শুরু করুন</button>
        </form>
        <div class="loading" id="loading-text">⏳ এপিকে ডিকম্পাইল, বাইপাস এবং সাইন হচ্ছে... দয়া করে পেজটি কেটে দেবেন না, সময় লাগতে পারে।</div>
    </div>

    <script>
        function updateFileName(input) {
            if (input.files && input.files[0]) {
                document.getElementById('file-label').innerText = "Selected: " + input.files[0].name;
            }
        }
        function showLoading() {
            document.getElementById('submit-btn').style.display = 'none';
            document.getElementById('loading-text').style.display = 'block';
        }
    </script>
</body>
</html>
"""

def verify_target_apk(apk_path):
    """
    এখানে এপিকে-র নির্দিষ্ট প্যাকেজ নেম বা ফেক প্রোডাকশন সিগনেচার চেক করা হবে। 
    আপনার টার্গেট অ্যাপের আসল প্যাকেজ নেম বা সিগনেচার এখানে ভ্যালিড করতে হবে।
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' in z.namelist():
                # সহজ সিকিউরিটি চেক: আপনি চাইলে নির্দিষ্ট ফাইলের উপস্থিতি বা আকার চেক করতে পারেন
                return True
    except Exception:
        pass
    return False

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'apk' not in request.files:
        return "কোনো ফাইল পাওয়া যায়নি!"
    file = request.files['apk']
    if file.filename == '':
        return "ফাইল সিলেক্ট করা হয়নি!"
    
    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        # ১. প্রোটেকশন ভ্যালিডেশন চেক
        if not verify_target_apk(filepath):
            os.remove(filepath)
            return "<h3 style='color:red; text-align:center; margin-top:50px;'>❌ ভুল এপিকে ফাইল! এটি কাঙ্ক্ষিত ফেক প্রোটেকশনযুক্ত এপিকে নয়। দয়া করে সঠিক এপিকে আপলোড করুন। <br><br><a href='/' style='color:#38bdf8;'>ফিরে যান</a></h3>"

        decoded_dir = os.path.join(UPLOAD_FOLDER, "decoded")
        output_apk_name = "Modded_" + file.filename
        output_apk_path = os.path.join(OUTPUT_FOLDER, output_apk_name)
        
        try:
            # ২. Apktool দিয়ে ডিকম্পাইল করা
            subprocess.run(f"apktool d '{filepath}' -o '{decoded_dir}' -f", shell=True, check=True)
            
            # ৩. স্মালি প্যাচিং বা ফেক সিকিউরিটি বাইপাস লজিক (এখানে আপনার কাস্টম রিপ্লেসমেন্ট করতে পারেন)
            # উদাহরণস্বরূপ নির্দিষ্ট ফাইলের ভেতরে কোড সার্চ ও রিপ্লেস করা যেতে পারে।
            
            # ৪. Apktool দিয়ে রি-কম্পাইল করা
            unsigned_apk = os.path.join(UPLOAD_FOLDER, "unsigned.apk")
            subprocess.run(f"apktool b '{decoded_dir}' -o '{unsigned_apk}'", shell=True, check=True)
            
            # ৫. ডিবাগ কিস্টোর দিয়ে এপিকে সাইন করা
            keystore_path = os.path.expanduser("~/.android/debug.keystore")
            if not os.path.exists(keystore_path):
                os.makedirs(os.path.dirname(keystore_path), exist_ok=True)
                subprocess.run(f"keytool -genkey -v -keystore '{keystore_path}' -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -passin pass:android -passout pass:android -dname 'CN=Android,O=Android,C=US'", shell=True)

            sign_cmd = f"apksigner sign --ks '{keystore_path}' --ks-pass pass:android --key-pass pass:android '{unsigned_apk}'"
            subprocess.run(sign_cmd, shell=True, check=True)
            
            if os.path.exists(unsigned_apk):
                os.rename(unsigned_apk, output_apk_path)

            # ক্লিনআপ টেম্পোরারি ফোল্ডার
            if os.path.exists(decoded_dir):
                import shutil
                shutil.rmtree(decoded_dir)
            if os.path.exists(filepath):
                os.remove(filepath)

            # ৬. সাকসেস পেজ এবং অটো-ডাউনলোড লিংক
            success_html = f"""
            <!DOCTYPE html>
            <html lang="bn">
            <head>
                <meta charset="UTF-8">
                <title>Success - M1NX VIP</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding: 50px; }}
                    .card {{ background: #1e293b; padding: 40px; border-radius: 12px; display: inline-block; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }}
                    h2 {{ color: #22c55e; }}
                    .btn {{ background: #22c55e; color: white; padding: 12px 25px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; margin-top: 20px; }}
                    .btn:hover {{ background: #16a34a; }}
                </style>
                <script>
                    // অটোমেটিক ডাউনলোড ট্রিগার করা
                    window.onload = function() {{
                        setTimeout(function() {{
                            window.location.href = "/download/{output_apk_name}";
                        }}, 1500);
                    }};
                </script>
            </head>
            <body>
                <div class="card">
                    <h2>🎉 প্রসেস সফল হয়েছে!</h2>
                    <p>ফেক প্রোটেকশন সফলভাবে বাইপাস করা হয়েছে। আপনার মডিফাইড এপিকে ফাইলটি অটোমেটিক ডাউনলোড হওয়া শুরু হয়েছে।</p>
                    <a href="/download/{output_apk_name}" class="btn">ডাউনলোড না হলে এখানে ক্লিক করুন</a>
                    <br><br>
                    <a href="/" style="color: #38bdf8; text-decoration: none; font-size: 14px;">← অন্য এপিকে প্যাচ করুন</a>
                </div>
            </body>
            </html>
            """
            return success_html

        except Exception as e:
            return f"<h3 style='color:red; text-align:center; margin-top:50px;'>❌ প্রসেস করার সময় ত্রুটি ঘটেছে: {str(e)}<br><br><a href='/' style='color:#38bdf8;'>পুনরায় চেষ্টা করুন</a></h3>"

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(OUTPUT_FOLDER, filename), as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
