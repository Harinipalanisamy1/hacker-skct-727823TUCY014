# [Harini P], Roll No. 727823TUCY014
# analyze_results.py - Parses SSRF scan outputs and generates summary report

import json
import os
import glob
from datetime import datetime
from collections import defaultdict

ROLL_NUMBER ="727823TUCY014"
print(f"Roll No: 727823TUCY014 | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

OUTPUTS_DIR = "outputs"

def load_latest_results():
    """Load the most recently generated results JSON."""
    files = sorted(glob.glob(os.path.join(OUTPUTS_DIR, "ssrf_results_*.json")), reverse=True)
    if not files:
        print(f"[!] No result files found in {OUTPUTS_DIR}/")
        return None
    print(f"[*] Loading: {files[0]}")
    with open(files[0]) as f:
        return json.load(f)

def analyze(data):
    results = data["results"]
    print(f"\n{'='*65}")
    print(f"  SSRF ANALYSIS REPORT  |  Roll No: {ROLL_NUMBER}")
    print(f"  Scan Time: {data['scan_time']}")
    print(f"{'='*65}")

    # Group by category
    by_category = defaultdict(list)
    for r in results:
        by_category[r["category"]].append(r)

    print(f"\n{'CATEGORY':<22} {'TOTAL':<8} {'VULN':<8} {'POSSIBLE':<10} {'BLOCKED'}")
    print(f"{'-'*65}")
    for cat, items in by_category.items():
        total    = len(items)
        vuln     = sum(1 for i in items if i["verdict"] == "VULNERABLE")
        possible = sum(1 for i in items if i["verdict"] == "POSSIBLE")
        blocked  = sum(1 for i in items if i["verdict"] == "BLOCKED")
        print(f"{cat:<22} {total:<8} {vuln:<8} {possible:<10} {blocked}")

    # Top findings
    hits = [r for r in results if r["verdict"] in ("VULNERABLE", "POSSIBLE")]
    if hits:
        print(f"\n[!] Notable findings ({len(hits)} total):")
        for h in hits[:10]:
            print(f"    [{h['verdict']}] {h['payload']}  (HTTP {h['status_code']}, {h['elapsed_ms']}ms)")
    else:
        print("\n[✓] No SSRF vulnerabilities confirmed.")

    # Save text report
    report_path = os.path.join(OUTPUTS_DIR, "analysis_report.txt")
    with open(report_path, "w") as f:
        f.write(f"SSRF Analysis Report\n")
        f.write(f"Roll No: {ROLL_NUMBER}\n")
        f.write(f"Scan Time: {data['scan_time']}\n")
        f.write(f"Total Payloads: {data['total_payloads']}\n")
        f.write(f"Vulnerable: {data['vulnerable']}\n")
        f.write(f"Possible: {data['possible']}\n\n")
        for r in results:
            f.write(f"[{r['verdict']}] {r['category']} | {r['payload']} | HTTP {r['status_code']} | {r['elapsed_ms']}ms\n")
    print(f"\n[*] Text report saved to: {report_path}")
    print(f"{'='*65}")

if __name__ == "__main__":
    data = load_latest_results()
    if data:
        analyze(data)
