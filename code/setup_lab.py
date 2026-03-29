# [Harini P], Roll No. 727823TUCY014
# setup_lab.py - SSRF Testing Tool Lab Setup

import subprocess
import sys
import os
from datetime import datetime

ROLL_NUMBER ="727823TUCy014"
print(f"Roll No: 727823TUCY014 | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

REQUIRED_PACKAGES = ["requests", "flask", "colorama", "tabulate"]

def install_packages():
    print("\n[*] Installing required Python packages...")
    for pkg in REQUIRED_PACKAGES:
        print(f"    Installing {pkg}...", end=" ")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "-q"],
            capture_output=True, text=True
        )
        print("OK" if result.returncode == 0 else f"FAILED: {result.stderr.strip()}")

def create_vulnerable_server():
    """Write a minimal Flask app that simulates an SSRF-vulnerable endpoint."""
    server_code = '''# Vulnerable test server for SSRF lab - Roll No. 14
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    """Simulates a vulnerable fetch endpoint - DO NOT deploy outside lab."""
    url = request.args.get("url", "")
    if not url:
        return "Missing ?url= parameter", 400
    try:
        resp = requests.get(url, timeout=3)
        return resp.text, resp.status_code
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    print("[*] Vulnerable test server running on http://127.0.0.1:5000")
    print("[!] FOR LAB USE ONLY - isolated VM only")
    app.run(host="127.0.0.1", port=5000, debug=False)
'''
    os.makedirs("lab_server", exist_ok=True)
    with open("lab_server/vulnerable_server.py", "w") as f:
        f.write(server_code)
    print("\n[*] Vulnerable test server written to lab_server/vulnerable_server.py")

def create_output_dirs():
    for d in ["outputs", "screenshots", "logs"]:
        os.makedirs(d, exist_ok=True)
    print("[*] Output directories created: outputs/, screenshots/, logs/")

def verify_setup():
    print("\n[*] Verifying setup...")
    try:
        import requests
        print("    requests      OK")
        import flask
        print("    flask         OK")
        print("\n[✓] Lab environment ready!")
    except ImportError as e:
        print(f"    [!] Missing: {e}")

if __name__ == "__main__":
    install_packages()
    create_vulnerable_server()
    create_output_dirs()
    verify_setup()
