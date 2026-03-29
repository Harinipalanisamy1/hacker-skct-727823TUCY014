# Vulnerable test server for SSRF lab - Roll No. 14
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
