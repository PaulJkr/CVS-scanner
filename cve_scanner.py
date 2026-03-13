import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import time
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import threading

# ── Thread-safe print lock ──────────────────────────────────────────────────
_print_lock = threading.Lock()

def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

# ── Data models ─────────────────────────────────────────────────────────────

@dataclass
class CVECheck:
    cve_id: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    port: int
    service: str

@dataclass
class Finding:
    cve_id: str
    description: str
    severity: str
    port: int
    service: str
    evidence: str

@dataclass
class HostResult:
    host: str
    ip: str = ""
    scan_time: str = ""
    open_ports: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    error: str = ""

# ── CVE signature database ───────────────────────────────────────────────────
# Each entry maps a banner pattern (regex) to CVE metadata.
# Extend this dict to add more checks.

CVE_SIGNATURES: list[dict] = [
    # ── OpenSSH ──────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-38408",
        "description": "OpenSSH ssh-agent remote code execution via PKCS#11 providers",
        "severity": "CRITICAL",
        "port": 22,
        "service": "SSH",
        "pattern": r"OpenSSH_([0-6]\.|7\.[0-9][^0-9]|8\.[0-8][^0-9]|9\.[0-2][^0-9])",
    },
    {
        "cve_id": "CVE-2024-6387",
        "description": "regreSSHion: OpenSSH unauthenticated RCE (signal handler race condition)",
        "severity": "CRITICAL",
        "port": 22,
        "service": "SSH",
        "pattern": r"OpenSSH_(8\.[0-9][^0-9]|9\.[0-7][^0-9])",
    },
    {
        "cve_id": "CVE-2023-48795",
        "description": "Terrapin Attack: SSH prefix truncation (BPP sequence number manipulation)",
        "severity": "HIGH",
        "port": 22,
        "service": "SSH",
        "pattern": r"OpenSSH_([0-8]\.|9\.[0-3][^0-9])",
    },
    # ── Apache httpd ─────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-41773",
        "description": "Apache 2.4.49 path traversal and RCE",
        "severity": "CRITICAL",
        "port": 80,
        "service": "HTTP",
        "pattern": r"Apache/2\.4\.49",
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Apache 2.4.49-2.4.50 path traversal (bypass of CVE-2021-41773 fix)",
        "severity": "CRITICAL",
        "port": 80,
        "service": "HTTP",
        "pattern": r"Apache/2\.4\.50",
    },
    {
        "cve_id": "CVE-2022-31813",
        "description": "Apache mod_proxy X-Forwarded-For header forgery",
        "severity": "HIGH",
        "port": 80,
        "service": "HTTP",
        "pattern": r"Apache/2\.4\.(5[0-2])[^0-9]",
    },
    # ── nginx ─────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-23017",
        "description": "nginx resolver 1-byte heap write OOB (DNS response handling)",
        "severity": "HIGH",
        "port": 80,
        "service": "HTTP",
        "pattern": r"nginx/1\.(0\.|[0-9]\.[0-9]+|1[0-9]\.|20\.[0])",
    },
    # ── ProFTPD ───────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-9273",
        "description": "ProFTPD use-after-free in memory pool",
        "severity": "HIGH",
        "port": 21,
        "service": "FTP",
        "pattern": r"ProFTPD 1\.(3\.[0-5]|[0-2]\.)",
    },
    # ── vsftpd ────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 backdoor (smiley-face trojan)",
        "severity": "CRITICAL",
        "port": 21,
        "service": "FTP",
        "pattern": r"vsftpd 2\.3\.4",
    },
    # ── Microsoft IIS ─────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-21907",
        "description": "HTTP Protocol Stack RCE in IIS (CVE-2022-21907)",
        "severity": "CRITICAL",
        "port": 80,
        "service": "HTTP",
        "pattern": r"Microsoft-IIS/10\.0",
    },
    # ── OpenSSL (via HTTPS banner) ────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-0778",
        "description": "OpenSSL infinite loop in BN_mod_sqrt() (DoS)",
        "severity": "HIGH",
        "port": 443,
        "service": "HTTPS",
        "pattern": r"OpenSSL/1\.(0\.|1\.[0-n])",
    },
    {
        "cve_id": "CVE-2014-0160",
        "description": "Heartbleed: OpenSSL TLS heartbeat buffer over-read",
        "severity": "CRITICAL",
        "port": 443,
        "service": "HTTPS",
        "pattern": r"OpenSSL/1\.0\.[12][a-f]",
    },
    # ── Exim ─────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2019-15846",
        "description": "Exim heap buffer overflow in TLS SNI handling (RCE)",
        "severity": "CRITICAL",
        "port": 25,
        "service": "SMTP",
        "pattern": r"Exim ([0-3]\.|4\.[0-9][012])",
    },
    # ── Postfix ───────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-51764",
        "description": "Postfix SMTP smuggling via BDAT command",
        "severity": "MEDIUM",
        "port": 25,
        "service": "SMTP",
        "pattern": r"Postfix ESMTP",
    },
    # ── MySQL / MariaDB ───────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2012-2122",
        "description": "MySQL/MariaDB authentication bypass via timing attack",
        "severity": "HIGH",
        "port": 3306,
        "service": "MySQL",
        "pattern": r"(5\.[0-5]\.|mariadb-5\.[0-5]\.)",
    },
    # ── Redis ─────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-0543",
        "description": "Redis Lua sandbox escape (Debian/Ubuntu packages)",
        "severity": "CRITICAL",
        "port": 6379,
        "service": "Redis",
        "pattern": r"Redis",          # presence check; no auth = exposed
    },
    # ── Tomcat ────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-1938",
        "description": "Ghostcat: Apache Tomcat AJP file read / RCE",
        "severity": "CRITICAL",
        "port": 8009,
        "service": "AJP",
        "pattern": r".",              # AJP open = potentially vulnerable
    },
]

# Ports we actively probe
PROBE_PORTS = sorted({sig["port"] for sig in CVE_SIGNATURES} | {22, 21, 25, 80, 443, 3306, 6379, 8009, 8080, 8443})

# ── Banner grabbing ──────────────────────────────────────────────────────────

def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Return a combined banner string for the given host:port."""
    probes = {
        22:   b"",                          # SSH sends banner first
        21:   b"",                          # FTP sends banner first
        25:   b"EHLO scanner\r\n",
        80:   b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
        443:  None,                         # handled via TLS
        8443: None,
        3306: b"",                          # MySQL sends greeting first
        6379: b"PING\r\n",
        8009: b"",                          # AJP – just check if open
    }

    banner_parts = []

    # ── HTTP(S) via TLS ───────────────────────────────────────────────────────
    if port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    data = s.recv(2048).decode(errors="replace")
                    banner_parts.append(data)
                    # Grab TLS cert fields for extra version info
                    cert = s.getpeercert()
                    if cert:
                        banner_parts.append(str(cert))
        except Exception:
            pass
        return "\n".join(banner_parts)

    # ── Plain TCP ─────────────────────────────────────────────────────────────
    probe = probes.get(port, b"")
    if probe is None:
        return ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            # Read greeting if server speaks first
            s.settimeout(timeout)
            try:
                greeting = s.recv(2048).decode(errors="replace")
                banner_parts.append(greeting)
            except socket.timeout:
                pass
            # Send probe if we have one
            if probe:
                try:
                    s.send(probe)
                    resp = s.recv(4096).decode(errors="replace")
                    banner_parts.append(resp)
                except Exception:
                    pass
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass

    return "\n".join(banner_parts)

# ── Port scanner ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ── CVE matching ─────────────────────────────────────────────────────────────

def check_cves(port: int, banner: str) -> list[Finding]:
    findings = []
    for sig in CVE_SIGNATURES:
        if sig["port"] != port:
            continue
        if re.search(sig["pattern"], banner, re.IGNORECASE):
            findings.append(Finding(
                cve_id=sig["cve_id"],
                description=sig["description"],
                severity=sig["severity"],
                port=port,
                service=sig["service"],
                evidence=banner[:200].strip(),
            ))
    return findings

# ── Per-host scanner ─────────────────────────────────────────────────────────

def scan_host(host: str, ports: list[int], timeout: float, verbose: bool) -> HostResult:
    result = HostResult(host=host, scan_time=datetime.now(timezone.utc).isoformat())

    # Resolve hostname
    try:
        result.ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        result.error = f"DNS resolution failed: {e}"
        tprint(f"  [!] {host} – DNS error: {e}")
        return result

    tprint(f"  [*] Scanning {host} ({result.ip}) ...")

    # Port sweep
    open_ports = [p for p in ports if scan_port(result.ip, p, timeout)]
    result.open_ports = open_ports

    if verbose:
        tprint(f"      Open ports: {open_ports}")

    # Banner grab + CVE match
    for port in open_ports:
        banner = grab_banner(result.ip, port, timeout)
        if banner:
            result.banners[port] = banner[:500]   # store truncated banner
        findings = check_cves(port, banner)
        for f in findings:
            result.findings.append(asdict(f))
            severity_colour = {
                "CRITICAL": "\033[91m",
                "HIGH":     "\033[93m",
                "MEDIUM":   "\033[94m",
                "LOW":      "\033[92m",
            }.get(f.severity, "")
            reset = "\033[0m"
            tprint(f"      {severity_colour}[{f.severity}]{reset} {f.cve_id} on port {port} – {f.description}")

    if not result.findings:
        tprint(f"      No CVEs detected on {host}")

    return result

# ── Output helpers ────────────────────────────────────────────────────────────

def print_summary(results: list[HostResult]):
    total_findings = sum(len(r.findings) for r in results)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        for f in r.findings:
            severity_counts[f.get("severity", "LOW")] += 1

    print("\n" + "═" * 60)
    print("  SCAN SUMMARY")
    print("═" * 60)
    print(f"  Hosts scanned : {len(results)}")
    print(f"  Total findings: {total_findings}")
    for sev, count in severity_counts.items():
        if count:
            print(f"    {sev:8s}: {count}")
    print("═" * 60)

def save_results(results: list[HostResult], output_path: str):
    data = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "total_hosts": len(results),
        "hosts": [asdict(r) for r in results],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    tprint(f"\n[+] Results saved to {output_path}")

def save_csv(results: list[HostResult], csv_path: str):
    import csv
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "ip", "port", "cve_id", "severity", "description", "evidence"])
        for r in results:
            if not r.findings:
                writer.writerow([r.host, r.ip, "", "", "", "No findings", ""])
            for finding in r.findings:
                writer.writerow([
                    r.host, r.ip,
                    finding.get("port", ""),
                    finding.get("cve_id", ""),
                    finding.get("severity", ""),
                    finding.get("description", ""),
                    finding.get("evidence", "")[:100],
                ])
    tprint(f"[+] CSV report saved to {csv_path}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Multi-threaded CVE Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan hosts from file with 50 threads:
  python cve_scanner.py -f hosts.txt -t 50 -o results.json

  # Scan specific hosts inline:
  python cve_scanner.py --hosts 192.168.1.1 192.168.1.2 -o out.json

  # Scan a CIDR range (requires hosts pre-expanded):
  python cve_scanner.py -f targets.txt --ports 22 80 443 8080 -t 100

  # Verbose mode with CSV output:
  python cve_scanner.py -f hosts.txt -v --csv report.csv
        """,
    )
    parser.add_argument("-f", "--file",   help="File with one host/IP per line")
    parser.add_argument("--hosts",        nargs="+", help="Hosts/IPs to scan (inline)")
    parser.add_argument("-t", "--threads",type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("-o", "--output", default="cve_scan_results.json", help="JSON output file")
    parser.add_argument("--csv",          help="Also write a CSV report")
    parser.add_argument("--ports",        nargs="+", type=int, help="Override ports to scan")
    parser.add_argument("--timeout",      type=float, default=3.0, help="Socket timeout in seconds")
    parser.add_argument("-v", "--verbose",action="store_true", help="Verbose output")
    parser.add_argument("--list-cves",    action="store_true", help="List all CVE signatures and exit")
    return parser.parse_args()


def load_hosts(args) -> list[str]:
    hosts = []
    if args.file:
        try:
            with open(args.file) as f:
                hosts += [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Host file not found: {args.file}")
            sys.exit(1)
    if args.hosts:
        hosts += args.hosts
    return list(dict.fromkeys(hosts))   # deduplicate, preserve order


def main():
    args = parse_args()

    if args.list_cves:
        print(f"\n{'CVE ID':<20} {'SEV':<10} {'PORT':<6} {'SERVICE':<10} DESCRIPTION")
        print("─" * 90)
        for sig in sorted(CVE_SIGNATURES, key=lambda x: x["cve_id"]):
            print(f"{sig['cve_id']:<20} {sig['severity']:<10} {sig['port']:<6} {sig['service']:<10} {sig['description']}")
        print(f"\nTotal: {len(CVE_SIGNATURES)} signatures")
        return

    hosts = load_hosts(args)
    if not hosts:
        print("[!] No hosts specified. Use -f <file> or --hosts <host1> <host2> ...")
        sys.exit(1)

    ports = args.ports if args.ports else PROBE_PORTS

    print("╔══════════════════════════════════════════════╗")
    print("║         Multi-threaded CVE Scanner           ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"  Hosts    : {len(hosts)}")
    print(f"  Ports    : {ports}")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  CVE sigs : {len(CVE_SIGNATURES)}")
    print(f"  Output   : {args.output}")
    print()

    start = time.time()
    results: list[HostResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_host, host, ports, args.timeout, args.verbose): host
            for host in hosts
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                host = futures[future]
                tprint(f"  [!] Unexpected error scanning {host}: {e}")

    elapsed = time.time() - start
    print(f"\n[+] Scan completed in {elapsed:.1f}s")

    print_summary(results)
    save_results(results, args.output)
    if args.csv:
        save_csv(results, args.csv)


if __name__ == "__main__":
    main()