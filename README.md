# SSRF Testing Tool | Roll No. 14

**Project:** SSRF Testing Tool  
**Roll No:** 727823TUCY014  
**Category:** Web Application Security  
**Course:** Hacker Techniques  
**Repo:** hacker-skct-727823TUCY014  

---

## What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker tricks a server into making HTTP requests to unintended internal or external resources — bypassing firewalls and exposing internal services.

---

## Tools & Technologies

- Python 3.8+
- `requests` library
- `flask` (vulnerable lab server)
- VirtualBox + Kali Linux
- Metasploitable2 (optional extended target)

---

## Lab Environment Setup

```
VirtualBox
├── Kali Linux (attacker)    - 192.168.56.101
└── Metasploitable2 (target) - 192.168.56.102
    └── also runs lab_server/vulnerable_server.py on port 5000
```

---

## Project Structure

```
SKCT_14_SSRFTestingTool/
├── code/
│   ├── tool_main.py           # Main SSRF scanner
│   ├── setup_lab.py           # Lab setup script
│   ├── run_tool.py            # Runs 3 test cases
│   └── analyze_results.py     # Parses and reports results
├── lab_server/
│   └── vulnerable_server.py   # Flask test target (lab only)
├── notebooks/
│   └── demo.ipynb             # Jupyter demo
├── screenshots/               # Tool in action
├── outputs/                   # JSON results + analysis
├── report/
│   └── report.pdf
├── pipeline_14.yml
├── requirements.txt
└── README.md
```

---

## Usage

### Step 1 – Setup
```bash
python code/setup_lab.py
```

### Step 2 – Start the vulnerable test server (in a separate terminal)
```bash
python lab_server/vulnerable_server.py
```

### Step 3 – Run all 3 test cases
```bash
python code/run_tool.py
```

### Step 4 – Or run the main tool directly
```bash
# Test localhost bypass payloads
python code/tool_main.py --url http://127.0.0.1:5000/fetch --category localhost_bypass

# Test cloud metadata payloads
python code/tool_main.py --url http://127.0.0.1:5000/fetch --category cloud_metadata

# Test protocol abuse payloads
python code/tool_main.py --url http://127.0.0.1:5000/fetch --category protocol_abuse

# Run all categories
python code/tool_main.py --url http://127.0.0.1:5000/fetch --category all
```

### Step 5 – Analyze results
```bash
python code/analyze_results.py
```

---

## Test Cases

| # | Category | Example Payload | What it Tests |
|---|----------|----------------|---------------|
| 1 | Localhost bypass | `http://127.0.0.1` | Server fetching itself |
| 2 | Cloud metadata | `http://169.254.169.254/latest/meta-data/` | AWS credential exposure |
| 3 | Protocol abuse | `file:///etc/passwd` | Non-HTTP protocol SSRF |

---

## Ethical Notice

All testing performed on:
- Systems owned by the student
- Isolated VirtualBox VMs with no internet access
- Written permission obtained for any external systems

**Never run this tool against systems you do not own or have explicit written permission to test.**
