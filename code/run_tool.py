# [Harini P], Roll No. 727823TUCY014
# run_tool.py - Executes SSRF Testing Tool against 3 distinct test cases

import subprocess
import sys
import os
from datetime import datetime

ROLL_NUMBER ="727823TUCY014"
print(f"Roll No: 727823TUCY014 | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

TARGET = "http://127.0.0.1:5000/fetch"

TEST_CASES = [
    {
        "name": "Test Case 1 - Localhost Bypass",
        "args": ["--url", TARGET, "--param", "url", "--category", "localhost_bypass"],
        "description": "Tests if the server can be tricked into fetching its own localhost services."
    },
    {
        "name": "Test Case 2 - Cloud Metadata Endpoints",
        "args": ["--url", TARGET, "--param", "url", "--category", "cloud_metadata"],
        "description": "Tests for AWS/GCP/DigitalOcean metadata endpoint exposure via SSRF."
    },
    {
        "name": "Test Case 3 - Protocol Abuse",
        "args": ["--url", TARGET, "--param", "url", "--category", "protocol_abuse"],
        "description": "Tests non-HTTP protocols: file://, dict://, gopher:// for SSRF."
    },
]

def run_test_case(tc):
    print(f"\n{'='*60}")
    print(f"  {tc['name']}")
    print(f"  {tc['description']}")
    print(f"{'='*60}")

    cmd = [sys.executable, "code/tool_main.py"] + tc["args"] + ["--output", "outputs"]
    result = subprocess.run(cmd, capture_output=False, text=True)

    if result.returncode != 0:
        print(f"[!] Test case exited with code {result.returncode}")

if __name__ == "__main__":
    print(f"\n[*] Starting SSRF Test Pipeline | {len(TEST_CASES)} test cases\n")

    # Ensure tool exists
    if not os.path.exists("code/tool_main.py"):
        print("[!] tool_main.py not found. Run setup_lab.py first.")
        sys.exit(1)

    for tc in TEST_CASES:
        run_test_case(tc)

    print(f"\n[✓] All test cases completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Results saved in outputs/ directory")
