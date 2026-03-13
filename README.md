# CVE Scanner

A multi-threaded network CVE scanner with a graphical user interface. Scans hosts for known vulnerabilities by grabbing service banners and matching them against a built-in CVE signature database.

No third-party packages required — runs on **Windows, Linux, and macOS** out of the box.

---

## Files

| File | Purpose |
|---|---|
| `cve_scanner_gui.py` | Full GUI application — **this is all you need** |
| `cve_scanner.py` | Optional terminal/CLI version |

---

## Requirements

- Python 3.10 or newer
- Tkinter (bundled with Python on Windows and macOS; on Linux install with `sudo apt install python3-tk`)

No `pip install` needed.

---

## Quick Start

```bash
python cve_scanner_gui.py
```

That's it. The GUI will open and you're ready to scan.

---

## How to Use the GUI

### 1. Enter Targets
Type or paste hosts into the **Targets** box — one per line. Accepts hostnames and IP addresses.

```
192.168.1.1
192.168.1.2
example.com
```

Or click **Load from file** to import a plain `.txt` file of hosts.

### 2. Configure Options

| Setting | Default | Description |
|---|---|---|
| Ports | All CVE ports | Space-separated list of ports to probe |
| Threads | 50 | Concurrent scan threads (increase for large scans) |
| Timeout | 3.0s | Socket timeout per connection |

### 3. Start the Scan
Click **▶ START SCAN**. Click **■ STOP** at any time to abort.

### 4. Read the Results

The results panel has four tabs:

- **FINDINGS** — Color-coded vulnerability table. Click any row to see the raw banner evidence at the bottom.
- **LIVE LOG** — Real-time output as each host completes.
- **HOST SUMMARY** — Per-host status: `CLEAN`, `VULNERABLE`, or `ERROR`.
- **CVE REFERENCE** — Full list of all built-in CVE signatures.

### 5. Export
Use **Save JSON** or **Save CSV** to export results via a file dialog.

---

## CVE Signatures (17 included)

| Severity | CVE | Service | Description |
|---|---|---|---|
| 🔴 CRITICAL | CVE-2024-6387 | SSH | regreSSHion — OpenSSH unauthenticated RCE |
| 🔴 CRITICAL | CVE-2023-38408 | SSH | OpenSSH ssh-agent RCE via PKCS#11 |
| 🟠 HIGH | CVE-2023-48795 | SSH | Terrapin Attack — SSH prefix truncation |
| 🔴 CRITICAL | CVE-2021-41773 | HTTP | Apache 2.4.49 path traversal and RCE |
| 🔴 CRITICAL | CVE-2021-42013 | HTTP | Apache 2.4.50 path traversal (bypass) |
| 🟠 HIGH | CVE-2022-31813 | HTTP | Apache mod_proxy header forgery |
| 🟠 HIGH | CVE-2021-23017 | HTTP | nginx resolver heap OOB write |
| 🔴 CRITICAL | CVE-2022-21907 | HTTP | IIS HTTP Protocol Stack RCE |
| 🔴 CRITICAL | CVE-2014-0160 | HTTPS | Heartbleed — OpenSSL buffer over-read |
| 🟠 HIGH | CVE-2022-0778 | HTTPS | OpenSSL infinite loop DoS |
| 🔴 CRITICAL | CVE-2011-2523 | FTP | vsftpd 2.3.4 backdoor |
| 🟠 HIGH | CVE-2020-9273 | FTP | ProFTPD use-after-free |
| 🔴 CRITICAL | CVE-2019-15846 | SMTP | Exim heap overflow RCE |
| 🟡 MEDIUM | CVE-2023-51764 | SMTP | Postfix SMTP smuggling |
| 🟠 HIGH | CVE-2012-2122 | MySQL | MySQL/MariaDB auth bypass |
| 🔴 CRITICAL | CVE-2022-0543 | Redis | Redis Lua sandbox escape |
| 🔴 CRITICAL | CVE-2020-1938 | AJP | Ghostcat — Apache Tomcat AJP RCE |

---

## Adding Your Own CVE Signatures

Open either Python file and add a new entry to the `CVE_SIGNATURES` list:

```python
{
    "cve_id": "CVE-YYYY-XXXXX",
    "description": "Brief description of the vulnerability",
    "severity": "CRITICAL",   # CRITICAL | HIGH | MEDIUM | LOW
    "port": 8080,
    "service": "HTTP",
    "pattern": r"SomeServer/1\.[0-3]",  # regex matched against the service banner
}
```

The pattern is matched case-insensitively against the raw TCP/TLS banner grabbed from that port.

---

## CLI Usage (optional)

If you prefer the terminal, use `cve_scanner.py`:

```bash
# Scan hosts from a file, 100 threads, save JSON and CSV
python cve_scanner.py -f hosts.txt -t 100 -o results.json --csv report.csv

# Scan inline hosts with verbose output
python cve_scanner.py --hosts 10.0.0.1 10.0.0.2 -v

# Scan specific ports only
python cve_scanner.py -f hosts.txt --ports 22 80 443

# List all built-in CVE signatures
python cve_scanner.py --list-cves
```

---

## How It Works

1. **Port sweep** — each host is checked for open ports using fast TCP connect attempts
2. **Banner grabbing** — open ports receive a protocol-appropriate probe and the server response is captured
3. **CVE matching** — the banner is matched against all signatures for that port using regular expressions
4. **Reporting** — findings are displayed in the UI and can be exported to JSON or CSV

All scanning runs on a thread pool (`concurrent.futures.ThreadPoolExecutor`), making it fast enough to handle hundreds of hosts simultaneously.

---

## Output Format

### JSON
```json
{
  "scan_date": "2026-03-13T10:00:00+00:00",
  "total_hosts": 3,
  "hosts": [
    {
      "host": "192.168.1.1",
      "ip": "192.168.1.1",
      "open_ports": [22, 80],
      "findings": [
        {
          "cve_id": "CVE-2024-6387",
          "severity": "CRITICAL",
          "port": 22,
          "service": "SSH",
          "description": "regreSSHion: OpenSSH unauthenticated RCE",
          "evidence": "SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.2"
        }
      ]
    }
  ]
}
```

### CSV
```
host, ip, port, cve_id, severity, description, evidence
192.168.1.1, 192.168.1.1, 22, CVE-2024-6387, CRITICAL, regreSSHion..., SSH-2.0-OpenSSH_9.2...
```

---

## Limitations

- Detection is based on **banner grabbing only** — it does not exploit vulnerabilities or confirm them with a proof-of-concept payload
- Services that hide or spoof version strings will not be detected
- False positives are possible if a banner matches a pattern but the service has been patched without changing its version string

---

## Legal Notice

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized port scanning and vulnerability scanning is illegal in most jurisdictions and may violate computer fraud laws. The authors accept no liability for misuse.
