import concurrent.futures
import json
import re
import socket
import ssl
import threading
import time
import tkinter as tk
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, font, messagebox, ttk

# ─────────────────────────────────────────────────────────────────────────────
#  CVE SIGNATURE DATABASE
# ─────────────────────────────────────────────────────────────────────────────

CVE_SIGNATURES: list[dict] = [
    {"cve_id": "CVE-2024-6387", "description": "regreSSHion: OpenSSH unauthenticated RCE (signal handler race)", "severity": "CRITICAL", "port": 22, "service": "SSH", "pattern": r"OpenSSH_(8\.[0-9][^0-9]|9\.[0-7][^0-9])"},
    {"cve_id": "CVE-2023-38408", "description": "OpenSSH ssh-agent RCE via PKCS#11 providers", "severity": "CRITICAL", "port": 22, "service": "SSH", "pattern": r"OpenSSH_([0-6]\.|7\.[0-9][^0-9]|8\.[0-8][^0-9]|9\.[0-2][^0-9])"},
    {"cve_id": "CVE-2023-48795", "description": "Terrapin Attack: SSH prefix truncation", "severity": "HIGH", "port": 22, "service": "SSH", "pattern": r"OpenSSH_([0-8]\.|9\.[0-3][^0-9])"},
    {"cve_id": "CVE-2021-41773", "description": "Apache 2.4.49 path traversal and RCE", "severity": "CRITICAL", "port": 80, "service": "HTTP", "pattern": r"Apache/2\.4\.49"},
    {"cve_id": "CVE-2021-42013", "description": "Apache 2.4.50 path traversal (bypass of 41773 fix)", "severity": "CRITICAL", "port": 80, "service": "HTTP", "pattern": r"Apache/2\.4\.50"},
    {"cve_id": "CVE-2022-31813", "description": "Apache mod_proxy X-Forwarded-For forgery", "severity": "HIGH", "port": 80, "service": "HTTP", "pattern": r"Apache/2\.4\.(5[0-2])[^0-9]"},
    {"cve_id": "CVE-2021-23017", "description": "nginx resolver 1-byte heap OOB write", "severity": "HIGH", "port": 80, "service": "HTTP", "pattern": r"nginx/1\.(0\.|[0-9]\.[0-9]+|1[0-9]\.|20\.[0])"},
    {"cve_id": "CVE-2022-21907", "description": "IIS HTTP Protocol Stack RCE", "severity": "CRITICAL", "port": 80, "service": "HTTP", "pattern": r"Microsoft-IIS/10\.0"},
    {"cve_id": "CVE-2014-0160", "description": "Heartbleed: OpenSSL TLS heartbeat buffer over-read", "severity": "CRITICAL", "port": 443, "service": "HTTPS", "pattern": r"OpenSSL/1\.0\.[12][a-f]"},
    {"cve_id": "CVE-2022-0778", "description": "OpenSSL infinite loop in BN_mod_sqrt() DoS", "severity": "HIGH", "port": 443, "service": "HTTPS", "pattern": r"OpenSSL/1\.(0\.|1\.[0-n])"},
    {"cve_id": "CVE-2011-2523", "description": "vsftpd 2.3.4 backdoor (smiley-face trojan)", "severity": "CRITICAL", "port": 21, "service": "FTP", "pattern": r"vsftpd 2\.3\.4"},
    {"cve_id": "CVE-2020-9273", "description": "ProFTPD use-after-free in memory pool", "severity": "HIGH", "port": 21, "service": "FTP", "pattern": r"ProFTPD 1\.(3\.[0-5]|[0-2]\.)"},
    {"cve_id": "CVE-2019-15846", "description": "Exim heap overflow in TLS SNI handling (RCE)", "severity": "CRITICAL", "port": 25, "service": "SMTP", "pattern": r"Exim ([0-3]\.|4\.[0-9][012])"},
    {"cve_id": "CVE-2023-51764", "description": "Postfix SMTP smuggling via BDAT", "severity": "MEDIUM", "port": 25, "service": "SMTP", "pattern": r"Postfix ESMTP"},
    {"cve_id": "CVE-2012-2122", "description": "MySQL/MariaDB auth bypass via timing attack", "severity": "HIGH", "port": 3306, "service": "MySQL", "pattern": r"(5\.[0-5]\.|mariadb-5\.[0-5]\.)"},
    {"cve_id": "CVE-2022-0543", "description": "Redis Lua sandbox escape (Debian/Ubuntu)", "severity": "CRITICAL", "port": 6379, "service": "Redis", "pattern": r"Redis"},
    {"cve_id": "CVE-2020-1938", "description": "Ghostcat: Tomcat AJP file read / RCE", "severity": "CRITICAL", "port": 8009, "service": "AJP", "pattern": r"."},
]

PROBE_PORTS = sorted({s["port"] for s in CVE_SIGNATURES} | {22, 21, 25, 80, 443, 3306, 6379, 8009, 8080, 8443})

SEV_COLOR = {"CRITICAL": "#ff4d4d", "HIGH": "#ff9900", "MEDIUM": "#f0c040", "LOW": "#4ddb6b"}
SEV_BG    = {"CRITICAL": "#3a1010", "HIGH": "#2e1e00", "MEDIUM": "#2a2200", "LOW": "#0d2a14"}

# ─────────────────────────────────────────────────────────────────────────────
#  SCANNER CORE  (same as CLI version, adapted for threaded callback)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HostResult:
    host: str
    ip: str = ""
    scan_time: str = ""
    open_ports: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    error: str = ""


def grab_banner(ip: str, port: int, timeout: float) -> str:
    parts = []
    if port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    parts.append(s.recv(2048).decode(errors="replace"))
        except Exception:
            pass
        return "\n".join(parts)

    probe = {22: b"", 21: b"", 25: b"EHLO scanner\r\n",
             80: b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
             8080: b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
             3306: b"", 6379: b"PING\r\n", 8009: b""}.get(port, b"")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                parts.append(s.recv(2048).decode(errors="replace"))
            except socket.timeout:
                pass
            if probe:
                try:
                    s.send(probe)
                    parts.append(s.recv(4096).decode(errors="replace"))
                except Exception:
                    pass
    except Exception:
        pass
    return "\n".join(parts)


def scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except Exception:
        return False


def check_cves(port: int, banner: str) -> list[dict]:
    found = []
    for sig in CVE_SIGNATURES:
        if sig["port"] == port and re.search(sig["pattern"], banner, re.IGNORECASE):
            found.append({**sig, "evidence": banner[:200].strip()})
    return found


def scan_host(host: str, ports: list[int], timeout: float) -> HostResult:
    r = HostResult(host=host, scan_time=datetime.now(timezone.utc).isoformat())
    try:
        r.ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        r.error = f"DNS error: {e}"
        return r
    r.open_ports = [p for p in ports if scan_port(r.ip, p, timeout)]
    for port in r.open_ports:
        banner = grab_banner(r.ip, port, timeout)
        if banner:
            r.banners[str(port)] = banner[:500]
        r.findings.extend(check_cves(port, banner))
    return r


# ─────────────────────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────────────────────

class CVEScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CVE Scanner")
        self.geometry("1200x780")
        self.minsize(900, 600)
        self.configure(bg="#0d0d14")

        self._results: list[HostResult] = []
        self._scan_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._build_fonts()
        self._build_ui()
        self._after_id = None

    # ── Fonts ─────────────────────────────────────────────────────────────────
    def _build_fonts(self):
        self.f_title  = font.Font(family="Courier New", size=16, weight="bold")
        self.f_mono   = font.Font(family="Courier New", size=10)
        self.f_mono_s = font.Font(family="Courier New", size=9)
        self.f_label  = font.Font(family="Courier New", size=10)
        self.f_btn    = font.Font(family="Courier New", size=10, weight="bold")

    # ── Master layout ─────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg="#0d0d14", pady=10)
        hdr.pack(fill="x", padx=20)
        tk.Label(hdr, text="[ CVE SCANNER ]", font=self.f_title,
                 fg="#00ffcc", bg="#0d0d14").pack(side="left")
        tk.Label(hdr, text="multi-threaded · cross-platform",
                 font=self.f_mono_s, fg="#445566", bg="#0d0d14").pack(side="left", padx=14)

        # Two-pane body
        body = tk.Frame(self, bg="#0d0d14")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self._build_left(body)
        self._build_right(body)

        # Status bar
        self._status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self._status_var, font=self.f_mono_s,
                 fg="#556677", bg="#0a0a10", anchor="w", padx=10
                 ).pack(fill="x", side="bottom")

    # ── Left panel (config + controls) ───────────────────────────────────────
    def _build_left(self, parent):
        left = tk.Frame(parent, bg="#0d0d14", width=310)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        # ── Targets ──
        self._section(left, "TARGETS")
        self._targets_text = self._textarea(left, height=7,
            placeholder="One host / IP per line\n192.168.1.1\nexample.com")
        btn_row = tk.Frame(left, bg="#0d0d14")
        btn_row.pack(fill="x", pady=(4, 0))
        self._ghost_btn(btn_row, "Load from file", self._load_file).pack(side="left")
        self._ghost_btn(btn_row, "Clear", lambda: self._targets_text.delete("1.0", "end")).pack(side="left", padx=6)

        # ── Ports ──
        self._section(left, "PORTS TO SCAN")
        ports_frame = tk.Frame(left, bg="#0d0d14")
        ports_frame.pack(fill="x")
        self._ports_var = tk.StringVar(value=" ".join(str(p) for p in PROBE_PORTS))
        self._entry(ports_frame, self._ports_var).pack(fill="x")
        self._ghost_btn(ports_frame, "Reset defaults",
                        lambda: self._ports_var.set(" ".join(str(p) for p in PROBE_PORTS))
                        ).pack(anchor="w", pady=(3, 0))

        # ── Options ──
        self._section(left, "OPTIONS")
        opt = tk.Frame(left, bg="#0d0d14")
        opt.pack(fill="x")

        tk.Label(opt, text="Threads", font=self.f_label, fg="#8899aa", bg="#0d0d14").grid(row=0, column=0, sticky="w")
        self._threads_var = tk.IntVar(value=50)
        self._spinbox(opt, self._threads_var, 1, 500).grid(row=0, column=1, sticky="ew", padx=(8, 0))

        tk.Label(opt, text="Timeout (s)", font=self.f_label, fg="#8899aa", bg="#0d0d14").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self._timeout_var = tk.DoubleVar(value=3.0)
        self._spinbox(opt, self._timeout_var, 0.5, 30, inc=0.5).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(6, 0))
        opt.columnconfigure(1, weight=1)

        # ── Scan button ──
        self._section(left, "")
        self._scan_btn = tk.Button(
            left, text="▶  START SCAN", font=self.f_btn,
            bg="#00ffcc", fg="#0d0d14", activebackground="#00ccaa",
            activeforeground="#0d0d14", relief="flat", padx=12, pady=8,
            cursor="hand2", command=self._start_scan)
        self._scan_btn.pack(fill="x", pady=(0, 6))

        self._stop_btn = tk.Button(
            left, text="■  STOP", font=self.f_btn,
            bg="#1a1a24", fg="#ff4d4d", activebackground="#2a0a0a",
            activeforeground="#ff6666", relief="flat", padx=12, pady=8,
            cursor="hand2", state="disabled", command=self._stop_scan)
        self._stop_btn.pack(fill="x")

        # ── Export ──
        self._section(left, "EXPORT")
        exp_row = tk.Frame(left, bg="#0d0d14")
        exp_row.pack(fill="x")
        self._ghost_btn(exp_row, "Save JSON", self._export_json).pack(side="left")
        self._ghost_btn(exp_row, "Save CSV", self._export_csv).pack(side="left", padx=6)

        # ── Progress ──
        self._section(left, "")
        self._progress_var = tk.DoubleVar(value=0)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Cyber.Horizontal.TProgressbar",
                        troughcolor="#1a1a24", background="#00ffcc",
                        darkcolor="#00ffcc", lightcolor="#00ffcc", bordercolor="#0d0d14")
        self._progressbar = ttk.Progressbar(left, variable=self._progress_var,
                                            style="Cyber.Horizontal.TProgressbar",
                                            maximum=100, length=280)
        self._progressbar.pack(fill="x")
        self._prog_label = tk.Label(left, text="", font=self.f_mono_s,
                                    fg="#445566", bg="#0d0d14", anchor="w")
        self._prog_label.pack(fill="x")

    # ── Right panel (results) ─────────────────────────────────────────────────
    def _build_right(self, parent):
        right = tk.Frame(parent, bg="#0d0d14")
        right.pack(side="left", fill="both", expand=True)

        nb = ttk.Notebook(right)
        style = ttk.Style()
        style.configure("TNotebook", background="#0d0d14", borderwidth=0)
        style.configure("TNotebook.Tab", background="#12121e", foreground="#8899aa",
                        font=("Courier New", 9, "bold"), padding=[12, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", "#1e1e30")],
                  foreground=[("selected", "#00ffcc")])
        nb.pack(fill="both", expand=True)

        # Tab 1 – Findings table
        tab_findings = tk.Frame(nb, bg="#12121e")
        nb.add(tab_findings, text=" FINDINGS ")
        self._build_findings_tab(tab_findings)

        # Tab 2 – Live log
        tab_log = tk.Frame(nb, bg="#12121e")
        nb.add(tab_log, text=" LIVE LOG ")
        self._build_log_tab(tab_log)

        # Tab 3 – Host summary
        tab_hosts = tk.Frame(nb, bg="#12121e")
        nb.add(tab_hosts, text=" HOST SUMMARY ")
        self._build_hosts_tab(tab_hosts)

        # Tab 4 – CVE Reference
        tab_ref = tk.Frame(nb, bg="#12121e")
        nb.add(tab_ref, text=" CVE REFERENCE ")
        self._build_ref_tab(tab_ref)

    def _build_findings_tab(self, parent):
        cols = ("severity", "cve_id", "host", "port", "service", "description")
        self._findings_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                           selectmode="browse")
        style = ttk.Style()
        style.configure("Treeview", background="#12121e", foreground="#c0ccd8",
                        fieldbackground="#12121e", rowheight=26,
                        font=("Courier New", 9))
        style.configure("Treeview.Heading", background="#0d0d14", foreground="#00ffcc",
                        font=("Courier New", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#1e2e3e")])

        widths = {"severity": 80, "cve_id": 130, "host": 140, "port": 55,
                  "service": 65, "description": 400}
        for c in cols:
            self._findings_tree.heading(c, text=c.upper(),
                                        command=lambda _c=c: self._sort_tree(_c))
            self._findings_tree.column(c, width=widths[c], minwidth=40, anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical",
                            command=self._findings_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal",
                            command=self._findings_tree.xview)
        self._findings_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._findings_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        # Evidence pane
        ev_frame = tk.Frame(parent, bg="#0a0a10", height=90)
        ev_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        ev_frame.pack_propagate(False)
        tk.Label(ev_frame, text="BANNER EVIDENCE", font=self.f_mono_s,
                 fg="#445566", bg="#0a0a10", anchor="w", padx=8).pack(fill="x")
        self._evidence_text = tk.Text(ev_frame, font=self.f_mono_s, bg="#0a0a10",
                                      fg="#7799bb", relief="flat", wrap="word",
                                      state="disabled", padx=8)
        self._evidence_text.pack(fill="both", expand=True)
        self._findings_tree.bind("<<TreeviewSelect>>", self._on_finding_select)

    def _build_log_tab(self, parent):
        self._log_text = tk.Text(parent, font=self.f_mono_s, bg="#0a0a12",
                                 fg="#7799bb", relief="flat", state="disabled",
                                 wrap="none", padx=10, pady=6)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._log_text.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._log_text.xview)
        self._log_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._log_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        # Tag colours for log
        self._log_text.tag_config("critical", foreground="#ff4d4d")
        self._log_text.tag_config("high",     foreground="#ff9900")
        self._log_text.tag_config("medium",   foreground="#f0c040")
        self._log_text.tag_config("low",      foreground="#4ddb6b")
        self._log_text.tag_config("info",     foreground="#00ffcc")
        self._log_text.tag_config("dim",      foreground="#445566")
        self._log_text.tag_config("err",      foreground="#ff6666")

    def _build_hosts_tab(self, parent):
        cols = ("host", "ip", "open_ports", "findings", "status")
        self._hosts_tree = ttk.Treeview(parent, columns=cols, show="headings")
        widths = {"host": 180, "ip": 130, "open_ports": 200, "findings": 80, "status": 120}
        for c in cols:
            self._hosts_tree.heading(c, text=c.upper().replace("_", " "))
            self._hosts_tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._hosts_tree.yview)
        self._hosts_tree.configure(yscrollcommand=vsb.set)
        self._hosts_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    def _build_ref_tab(self, parent):
        cols = ("cve_id", "severity", "port", "service", "description")
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        widths = {"cve_id": 130, "severity": 80, "port": 55, "service": 70, "description": 500}
        for c in cols:
            tree.heading(c, text=c.upper())
            tree.column(c, width=widths[c], anchor="w")
        for sig in sorted(CVE_SIGNATURES, key=lambda x: x["cve_id"]):
            tree.insert("", "end", values=(
                sig["cve_id"], sig["severity"], sig["port"],
                sig["service"], sig["description"]))
        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    # ── Widget helpers ────────────────────────────────────────────────────────
    def _section(self, parent, title):
        f = tk.Frame(parent, bg="#0d0d14")
        f.pack(fill="x", pady=(10, 2))
        if title:
            tk.Label(f, text=title, font=self.f_mono_s, fg="#334455",
                     bg="#0d0d14").pack(side="left")
            tk.Frame(f, bg="#1e2e3e", height=1).pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _textarea(self, parent, height=5, placeholder=""):
        t = tk.Text(parent, font=self.f_mono_s, bg="#12121e", fg="#c0ccd8",
                    insertbackground="#00ffcc", relief="flat",
                    height=height, padx=8, pady=6,
                    highlightthickness=1, highlightbackground="#1e2e3e",
                    highlightcolor="#00ffcc")
        t.pack(fill="x")
        if placeholder:
            t.insert("1.0", placeholder)
            t.config(fg="#334455")
            def _focus_in(e):
                if t.get("1.0", "end-1c") == placeholder:
                    t.delete("1.0", "end")
                    t.config(fg="#c0ccd8")
            def _focus_out(e):
                if not t.get("1.0", "end-1c").strip():
                    t.insert("1.0", placeholder)
                    t.config(fg="#334455")
            t.bind("<FocusIn>", _focus_in)
            t.bind("<FocusOut>", _focus_out)
        return t

    def _entry(self, parent, var):
        return tk.Entry(parent, textvariable=var, font=self.f_mono_s,
                        bg="#12121e", fg="#c0ccd8", insertbackground="#00ffcc",
                        relief="flat", highlightthickness=1,
                        highlightbackground="#1e2e3e", highlightcolor="#00ffcc")

    def _spinbox(self, parent, var, lo, hi, inc=1):
        return tk.Spinbox(parent, textvariable=var, from_=lo, to=hi, increment=inc,
                          font=self.f_mono_s, bg="#12121e", fg="#c0ccd8",
                          buttonbackground="#1e2e3e", relief="flat",
                          highlightthickness=1, highlightbackground="#1e2e3e",
                          insertbackground="#00ffcc", width=8)

    def _ghost_btn(self, parent, text, cmd):
        return tk.Button(parent, text=text, font=self.f_mono_s,
                         bg="#12121e", fg="#00ffcc", activebackground="#1e2e3e",
                         activeforeground="#00ffcc", relief="flat",
                         padx=8, pady=4, cursor="hand2", command=cmd)

    # ── Scan control ──────────────────────────────────────────────────────────
    def _get_hosts(self) -> list[str]:
        raw = self._targets_text.get("1.0", "end").strip()
        placeholder = "One host / IP per line\n192.168.1.1\nexample.com"
        if raw == placeholder:
            return []
        return [h.strip() for h in raw.splitlines() if h.strip()]

    def _get_ports(self) -> list[int]:
        ports = []
        for tok in self._ports_var.get().split():
            try:
                ports.append(int(tok))
            except ValueError:
                pass
        return sorted(set(ports)) or PROBE_PORTS

    def _start_scan(self):
        hosts = self._get_hosts()
        if not hosts:
            messagebox.showwarning("No targets", "Enter at least one host or IP.")
            return
        ports   = self._get_ports()
        threads = self._threads_var.get()
        timeout = self._timeout_var.get()

        self._results.clear()
        self._clear_ui()
        self._stop_event.clear()
        self._scan_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._log(f"Starting scan — {len(hosts)} host(s), {len(ports)} ports, "
                  f"{threads} threads\n", "info")

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(hosts, ports, threads, timeout),
            daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        self._stop_event.set()
        self._log("Stop requested — waiting for active threads...\n", "err")

    def _run_scan(self, hosts, ports, thread_count, timeout):
        total = len(hosts)
        done  = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as ex:
            futures = {ex.submit(scan_host, h, ports, timeout): h for h in hosts}
            for fut in concurrent.futures.as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    result = fut.result()
                except Exception as e:
                    result = HostResult(host=futures[fut], error=str(e))
                with self._lock:
                    self._results.append(result)
                done += 1
                self.after(0, self._on_result, result, done, total)

        self.after(0, self._on_scan_done)

    def _on_result(self, result: HostResult, done: int, total: int):
        pct = (done / total) * 100
        self._progress_var.set(pct)
        self._prog_label.config(text=f"{done}/{total} hosts scanned")
        self._status_var.set(f"Scanning {result.host} ...")

        if result.error:
            self._log(f"  ✗ {result.host}  →  {result.error}\n", "err")
        else:
            ports_str = ",".join(str(p) for p in result.open_ports) or "none"
            self._log(f"  ✓ {result.host} ({result.ip})  open={ports_str}\n", "dim")
            for f in result.findings:
                sev = f["severity"].lower()
                self._log(f"    [{f['severity']}] {f['cve_id']} :{f['port']} — {f['description']}\n", sev)
                self._add_finding_row(result, f)
        self._add_host_row(result)

    def _on_scan_done(self):
        total_f = sum(len(r.findings) for r in self._results)
        self._log(f"\n── Scan complete. {len(self._results)} hosts · {total_f} findings ──\n", "info")
        self._status_var.set(f"Done. {len(self._results)} hosts scanned, {total_f} findings.")
        self._progress_var.set(100)
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

    # ── UI update helpers ─────────────────────────────────────────────────────
    def _clear_ui(self):
        self._findings_tree.delete(*self._findings_tree.get_children())
        self._hosts_tree.delete(*self._hosts_tree.get_children())
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.config(state="disabled")
        self._progress_var.set(0)
        self._prog_label.config(text="")
        self._evidence_text.config(state="normal")
        self._evidence_text.delete("1.0", "end")
        self._evidence_text.config(state="disabled")

    def _log(self, msg: str, tag: str = ""):
        self._log_text.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_text.insert("end", f"[{ts}] ", "dim")
        self._log_text.insert("end", msg, tag)
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    def _add_finding_row(self, result: HostResult, f: dict):
        sev  = f["severity"]
        iid  = self._findings_tree.insert(
            "", "end",
            values=(sev, f["cve_id"], result.host, f["port"], f["service"], f["description"]),
            tags=(sev,))
        self._findings_tree.tag_configure(sev,
            foreground=SEV_COLOR.get(sev, "#ffffff"),
            background=SEV_BG.get(sev, "#12121e"))
        # store evidence in item
        self._findings_tree.set(iid, "severity", sev)
        self._findings_tree.item(iid, values=(
            sev, f["cve_id"], result.host, f["port"], f["service"], f["description"]))
        # stash evidence as hidden data
        self._findings_tree.item(iid, tags=(sev, f.get("evidence", "")))

    def _add_host_row(self, result: HostResult):
        n = len(result.findings)
        status = "ERROR" if result.error else ("VULNERABLE" if n else "CLEAN")
        fg = "#ff4d4d" if result.error else ("#ff9900" if n else "#4ddb6b")
        iid = self._hosts_tree.insert("", "end", values=(
            result.host,
            result.ip or "—",
            ", ".join(str(p) for p in result.open_ports) or "—",
            n,
            status,
        ))
        self._hosts_tree.tag_configure(status, foreground=fg)
        self._hosts_tree.item(iid, tags=(status,))

    def _on_finding_select(self, _event):
        sel = self._findings_tree.selection()
        if not sel:
            return
        item = self._findings_tree.item(sel[0])
        tags = item["tags"]
        # evidence is stored as second tag
        evidence = tags[1] if len(tags) > 1 else ""
        self._evidence_text.config(state="normal")
        self._evidence_text.delete("1.0", "end")
        self._evidence_text.insert("end", evidence or "(no banner captured)")
        self._evidence_text.config(state="disabled")

    def _sort_tree(self, col):
        rows = [(self._findings_tree.set(k, col), k)
                for k in self._findings_tree.get_children("")]
        rows.sort()
        for idx, (_, k) in enumerate(rows):
            self._findings_tree.move(k, "", idx)

    # ── File I/O ──────────────────────────────────────────────────────────────
    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Select host file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            self._targets_text.delete("1.0", "end")
            self._targets_text.insert("1.0", "\n".join(lines))
            self._targets_text.config(fg="#c0ccd8")
            self._status_var.set(f"Loaded {len(lines)} hosts from {Path(path).name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _export_json(self):
        if not self._results:
            messagebox.showinfo("No data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        data = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "total_hosts": len(self._results),
            "hosts": [asdict(r) for r in self._results],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._status_var.set(f"JSON saved → {path}")
        messagebox.showinfo("Saved", f"Results saved to:\n{path}")

    def _export_csv(self):
        if not self._results:
            messagebox.showinfo("No data", "Run a scan first.")
            return
        import csv
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "ip", "port", "cve_id", "severity", "description", "evidence"])
            for r in self._results:
                if not r.findings:
                    w.writerow([r.host, r.ip, "", "", "", "No findings", r.error])
                for fnd in r.findings:
                    w.writerow([r.host, r.ip, fnd.get("port"), fnd.get("cve_id"),
                                fnd.get("severity"), fnd.get("description"),
                                fnd.get("evidence", "")[:120]])
        self._status_var.set(f"CSV saved → {path}")
        messagebox.showinfo("Saved", f"CSV saved to:\n{path}")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = CVEScannerApp()
    app.mainloop()