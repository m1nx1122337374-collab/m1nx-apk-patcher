import os
import subprocess
import zipfile
from flask import Flask, render_template_string, request, send_file

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# একদম সিম্পল এবং ডাইরেক্ট ফাইল সিলেক্ট অপশন সহ ফ্রন্টএন্ড
HTML_PAGE = """
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <title>M1NX VIP - APK Patcher</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #fff; text-align: center; padding: 30px; }
        .card { background: #1e293b; padding: 30px; border-radius: 12px; display: inline-block; max-width: 450px; width: 100%; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h2 { color: #38bdf8; }
        input[type="file"] { background: #334155; color: #fff; padding: 10px; border-radius: 6px; width: 100%; margin: 15px 0; border: 1px solid #64748b; }
        button { background: #22c55e; color: white; border: none; padding: 12px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 6px; width: 100%; }
        button:hover { background: #16a34a; }
        .loading { display: none; color: #facc15; margin-top: 15px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h2>M1NX VIP Cloud Patcher</h2>
        <p>সঠিক প্রোটেকশনযুক্ত APK ফাইলটি সিলেক্ট করুন:</p>
        <form action="/upload" method="post" enctype="multipart/form-data" onsubmit="showLoading()">
            <input type="file" name="apk" accept=".apk" required>
            <button type="submit" id="btn">প্রসেস শুরু করুন</button>
        </form>
        <div class="loading" id="load">⏳ কাজ চলছে... দয়া করে অপেক্ষা করুন, এপিকে প্যাচ ও সাইন হতে সময় লাগবে।</div>
    </div>
    <script>
        function showLoading() {
            document.getElementById('btn').style.display = 'none';
            document.getElementById('load').style.display = 'block';
        }
    </script>
</body>
</html>
"""

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

        decoded_dir = os.path.join(UPLOAD_FOLDER, "decoded")
        output_apk_name = "Modded_" + file.filename
        output_apk_path = os.path.join(OUTPUT_FOLDER, output_apk_name)
        
        try:
            # Apktool দিয়ে ডিকম্পাইল
            subprocess.run(f"apktool d '{filepath}' -o '{decoded_dir}' -f", shell=True, check=True)
            
            # এখানে আপনার কাস্টম প্যাচিং লজিক বা বাইপাস কোড বসাতে পারবেন
            
            # Apktool দিয়ে রি-কম্পাইল
            unsigned_apk = os.path.join(UPLOAD_FOLDER, "unsigned.apk")
            subprocess.run(f"apktool b '{decoded_dir}' -o '{unsigned_apk}'", shell=True, check=True)
            
            # সাইন করা
            keystore_path = os.path.expanduser("~/.android/debug.keystore")
            if not os.path.exists(keystore_path):
                os.makedirs(os.path.dirname(keystore_path), exist_ok=True)
                subprocess.run(f"keytool -genkey -v -keystore '{keystore_path}' -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -passin pass:android -passout pass:android -dname 'CN=Android,O=Android,C=US'", shell=True)

            sign_cmd = f"apksigner sign --ks '{keystore_path}' --ks-pass pass:android --key-pass pass:android '{unsigned_apk}'"
            subprocess.run(sign_cmd, shell=True, check=True)
            
            if os.path.exists(unsigned_apk):
                os.rename(unsigned_apk, output_apk_path)

            # ক্লিনআপ
            if os.path.exists(decoded_dir):
                import shutil
                shutil.rmtree(decoded_dir)
            if os.path.exists(filepath):
                os.remove(filepath)

            # অটো ডাউনলোড পেজ
            success_html = f"""
            <!DOCTYPE html>
            <html lang="bn">
            <head>
                <meta charset="UTF-8">
                <title>Success</title>
                <style>
                    body {{ font-family: Arial; background: #0f172a; color: #fff; text-align: center; padding: 50px; }}
                    .card {{ background: #1e293b; padding: 30px; border-radius: 12px; display: inline-block; }}
                    .btn {{ background: #22c55e; color: white; padding: 12px 25px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; margin-top: 20px; }}
                </style>
                <script>
                    window.onload = function() {{
                        setTimeout(function() {{
                            window.location.href = "/download/{output_apk_name}";
                        }}, 1000);
                    }};
                </script>
            </head>
            <body>
                <div class="card">
                    <h2 style="color: #22c55e;">🎉 সাকসেস!</h2>
                    <p>এপিকে সফলভাবে মডিফাইড ও সাইন করা হয়েছে। ডাউনলোড শুরু হচ্ছে...</p>
                    <a href="/download/{output_apk_name}" class="btn">ডাউনলোড করুন</a>
                </div>
            </body>
            </html>
            """
            return success_html

        except Exception as e:
            return f"<h3 style='color:red; text-align:center; margin-top:50px;'>❌ এরর এসেছে: {str(e)}<br><br><a href='/' style='color:#38bdf8;'>ফিরে যান</a></h3>"

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(OUTPUT_FOLDER, filename), as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
