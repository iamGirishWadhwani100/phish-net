"""
PHISH-NET SECURE BACKEND
========================
Security: JWT auth, bcrypt passwords, rate limiting, env-based secrets
Intel:    Real VirusTotal (URL), AbuseIPDB (IP), Google DNS
AI:       OpenAI GPT-4o in PentestGPT mode as JARVIS brain
Team:     Cases, notes, shared audit log
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import hashlib, socket, base64, json, re as _re, ssl, html, sqlite3, os
try:
    import certifi
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# ── Optional heavy deps (graceful fallback if not installed) ──────────────────
try:
    import bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False

try:
    import jwt as pyjwt
    JWT_OK = True
except ImportError:
    JWT_OK = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_OK = True
except ImportError:
    LIMITER_OK = False

try:
    import openai
    OPENAI_OK = True
except ImportError:
    OPENAI_OK = False

load_dotenv()

# Serve frontend files from the same folder as app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")

# ── CORS ──────────────────────────────────────────────────────────────────────
allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000"
).split(",")
CORS(app, origins=allowed_origins, supports_credentials=True)

# ── Secrets from .env ─────────────────────────────────────────────────────────
JWT_SECRET    = os.getenv("JWT_SECRET", "")
VT_API_KEY    = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")

# Auto-generate JWT secret if missing (dev mode). Set it in .env for production.
if not JWT_SECRET:
    import secrets as _sec
    JWT_SECRET = _sec.token_hex(32)
    print("[WARN] JWT_SECRET not in .env — generated temporary secret.")
    print("  Sessions reset on each restart. Add to .env to persist logins.")

# ── Rate limiting ─────────────────────────────────────────────────────────────
if LIMITER_OK:
    limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day", "60 per hour"])
    def rl(limit): return limiter.limit(limit)
else:
    def rl(limit):
        def decorator(f): return f
        return decorator


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("phishnet.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT DEFAULT 'analyst',
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        email          TEXT,
        action         TEXT,
        target         TEXT,
        result_summary TEXT,
        ip_address     TEXT,
        timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        severity    TEXT DEFAULT 'medium',
        status      TEXT DEFAULT 'open',
        created_by  TEXT,
        assigned_to TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS case_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER,
        author     TEXT,
        note       TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id)
    )""")
    conn.commit()

    # Pre-populate famous real-world hacking cases
    existing = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if existing == 0:
        famous_cases = [
            ("SolarWinds Supply Chain Attack (2020)", "Nation-state attackers (APT29/Cozy Bear) compromised SolarWinds Orion software updates, affecting 18,000+ organizations including US govt agencies (Treasury, Commerce, DHS). Attackers had access for 9+ months undetected.", "critical", "historical", "SYSTEM"),
            ("Colonial Pipeline Ransomware (2021)", "DarkSide ransomware group attacked Colonial Pipeline, shutting down 5,500 miles of fuel pipeline supplying 45% of US East Coast fuel. Ransom of $4.4M paid. Attack vector: compromised VPN credentials with no MFA.", "critical", "historical", "SYSTEM"),
            ("Log4Shell / Log4j RCE (CVE-2021-44228)", "Critical RCE vulnerability in Apache Log4j logging library. CVSS 10.0. Affected millions of servers worldwide. Exploitation observed within hours of disclosure. Attack: malicious JNDI lookup string in HTTP headers.", "critical", "historical", "SYSTEM"),
            ("MOVEit Transfer Mass Exploitation (2023)", "Cl0p ransomware group exploited SQL injection zero-day (CVE-2023-34362) in MOVEit Transfer. 2,000+ organizations compromised including US govt agencies, airlines, banks. 60M+ individuals affected.", "critical", "historical", "SYSTEM"),
            ("Microsoft Exchange ProxyLogon (2021)", "Four zero-day vulnerabilities in Microsoft Exchange Server (CVE-2021-26855 to 26858). Exploited by HAFNIUM (Chinese APT) to install web shells. 250,000+ servers compromised worldwide before patch.", "critical", "historical", "SYSTEM"),
            ("Okta Breach via Lapsus$ Group (2022)", "Social engineering attack via a third-party support provider gave Lapsus$ group access to Okta's internal systems for 5 days. Okta serves 15,000+ organizations. Attack highlights third-party/supply chain risk.", "high", "historical", "SYSTEM"),
            ("Twitter Bitcoin Scam (2020)", "Insider threat: Twitter employees bribed/socially engineered to access admin tools. High-profile accounts (Obama, Biden, Musk, Apple, Bitcoin) hijacked. $120K in Bitcoin stolen in 3 hours.", "high", "historical", "SYSTEM"),
            ("Equifax Data Breach (2017)", "Apache Struts vulnerability (CVE-2017-5638) exploited. 147 million Americans' PII stolen including SSNs, DOBs, addresses, credit card numbers. Breach undetected for 78 days due to expired SSL cert on monitoring tool.", "critical", "historical", "SYSTEM"),
            ("NotPetya Cyberattack (2017)", "Destructive malware disguised as ransomware, attributed to Russia's Sandworm APT. Spread via Ukrainian accounting software MeDoc. Caused $10B+ damage globally. Shipping giant Maersk lost $300M. Used EternalBlue + Mimikatz.", "critical", "historical", "SYSTEM"),
            ("Uber Data Breach via Social Engineering (2022)", "Attacker texted an Uber contractor, claimed to be IT support, socially engineered MFA bypass. Accessed Slack, HackerOne bug bounty reports, internal dashboards. Full network compromise in hours.", "high", "historical", "SYSTEM"),
            ("LastPass Vault Theft (2022)", "Attacker compromised a DevOps engineer's home computer to steal LastPass vault backups. Encrypted password vaults of millions of users exfiltrated. Attack vector: vulnerable media software on personal device.", "high", "historical", "SYSTEM"),
            ("Change Healthcare Ransomware (2024)", "ALPHV/BlackCat ransomware attack on Change Healthcare (UnitedHealth Group subsidiary). Disrupted US prescription processing nationwide for weeks. $22M ransom paid. Largest healthcare cyberattack in US history.", "critical", "active", "SYSTEM"),
        ]
        for title, desc, sev, status, creator in famous_cases:
            conn.execute(
                "INSERT INTO cases (title, description, severity, status, created_by) VALUES (?,?,?,?,?)",
                (title, desc, sev, status, creator)
            )
        conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect("phishnet.db")
    conn.row_factory = sqlite3.Row
    return conn

def log_action(email, action, target, summary="", ip=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (email, action, target, result_summary, ip_address) VALUES (?,?,?,?,?)",
        (email or "GUEST", action, str(target)[:200], str(summary)[:500], ip)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    if BCRYPT_OK:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Fallback: salted SHA-256 (install bcrypt for production!)
    salt = os.urandom(16).hex()
    return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    if BCRYPT_OK and stored_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    if ":" in stored_hash:
        salt, hashed = stored_hash.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash

def make_token(email: str, role: str) -> str:
    if not JWT_OK:
        return email
    payload = {
        "sub":  email,
        "role": role,
        "exp":  datetime.now(timezone.utc) + timedelta(hours=8),
        "iat":  datetime.now(timezone.utc),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    if not JWT_OK:
        return {"sub": token, "role": "analyst"}
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def get_operator(req) -> dict | None:
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return decode_token(auth[7:])
    return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        op = get_operator(request)
        if not op:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
# ── Health check (lets the frontend verify backend is alive) ──────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ai": bool(OPENAI_KEY), "vt": bool(VT_API_KEY)})


@app.route("/api/register", methods=["POST"])
@rl("10 per hour")
def register():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "Valid email required."})
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be ≥ 8 characters."})

    try:
        conn = get_db()
        conn.execute("INSERT INTO users (email, password_hash) VALUES (?,?)",
                     (email, hash_password(password)))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Operator registered."})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered."})


@app.route("/api/login", methods=["POST"])
@rl("20 per hour")
def login():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"status": "error", "message": "Invalid credentials."})

    token = make_token(email, user["role"])
    log_action(email, "LOGIN", "", "success", request.remote_addr)
    return jsonify({"status": "success", "token": token, "email": email, "role": user["role"]})


# ─────────────────────────────────────────────────────────────────────────────
# JARVIS — OpenAI GPT-4o (PentestGPT mode)
# ─────────────────────────────────────────────────────────────────────────────
JARVIS_SYSTEM = """You are J.A.R.V.I.S., an elite autonomous SOC analyst and PentestGPT-powered cybersecurity assistant built into the Phish-Net platform.

Your role: Act as a tactical mentor for security analysts working on threat intelligence, incident response, CTF challenges, forensics, and penetration testing.

FORMATTING RULES — respond with HTML only, no markdown:
- Use <span class='text-yellow-muted font-bold'>[ADVISORY]</span> for section headers
- Use <span class='text-cyan-muted'>text</span> for general highlights and key terms
- Use <span class='text-green-muted'>text</span> for recommended commands and safe states
- Use <span class='text-red-muted'>text</span> for threats, warnings, malicious indicators
- Use <code>command</code> for all terminal commands
- Use <br><br> for paragraph breaks — no markdown, no backtick fences, no asterisks

Be concise, specific, and tactical. Always explain what a suggested command does and why."""


@app.route("/api/jarvis", methods=["POST"])
@require_auth
@rl("60 per hour")
def jarvis():
    operator = get_operator(request)
    data     = request.json or {}
    prompt   = data.get("prompt", "").strip()

    if not prompt:
        return jsonify({"status": "error", "message": "Empty prompt."})
    if len(prompt) > 4000:
        return jsonify({"status": "error", "message": "Prompt too long (max 4000 chars)."})

    if not OPENAI_KEY:
        fallback = _jarvis_fallback(prompt)
        return jsonify({
            "status":   "success",
            "response": fallback,
            "speech":   "Offline advisory mode active. Set OPENAI_API_KEY for full GPT-4o intelligence."
        })

    if not OPENAI_OK:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] openai package missing. Run: pip install openai</span>",
            "speech":   "OpenAI package not installed."
        })

    try:
        client     = openai.OpenAI(api_key=OPENAI_KEY)
        completion = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": JARVIS_SYSTEM},
                {"role": "user",   "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content
        # Strip HTML tags for TTS
        speech_text = _re.sub(r"<[^>]+>", "", response_text)[:300].strip()

        log_action(operator["sub"] if operator else "GUEST",
                   "JARVIS", prompt[:100], "ok", request.remote_addr)
        return jsonify({"status": "success", "response": response_text, "speech": speech_text})

    except openai.AuthenticationError:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] Invalid OpenAI API key. Check OPENAI_API_KEY in .env</span>",
            "speech":   "Authentication error. Check your API key."
        })
    except openai.RateLimitError:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] OpenAI rate limit reached. Try again shortly.</span>",
            "speech":   "Rate limit reached."
        })
    except Exception as e:
        return jsonify({
            "status":   "error",
            "response": f"<span class='text-red-muted'>[-] JARVIS API ERROR: {html.escape(str(e))}</span>",
            "speech":   "An error occurred."
        })


def _jarvis_fallback(prompt: str) -> str:
    p = prompt.lower()
    if any(k in p for k in ["nmap", "port", "scan", "enumerate"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] ENUMERATION</span><br><br>"
                "Firewall may be blocking ICMP. Try <code>nmap -Pn -sV --open TARGET</code> to skip ping.<br>"
                "Also scan UDP: <code>nmap -sU --top-ports 100 TARGET</code> — SNMP (161) is often missed.")
    if any(k in p for k in ["privesc", "root", "privilege", "escalat"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] PRIVILEGE ESCALATION</span><br><br>"
                "Linux: <code>sudo -l</code> and <code>find / -perm -4000 2>/dev/null</code>.<br>"
                "Windows: <code>whoami /priv</code> and check unquoted service paths.")
    if any(k in p for k in ["shell", "reverse", "payload", "meterpreter"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] REVERSE SHELLS</span><br><br>"
                "Try egress on ports <span class='text-cyan-muted'>443, 80, 53</span> — firewalls rarely block these.<br>"
                "Listener: <code>nc -lvnp 443</code>")
    if any(k in p for k in ["web", "sqli", "xss", "waf", "inject"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] WEB EXPLOITATION</span><br><br>"
                "WAF bypass: try URL-encoding or double-encoding keywords.<br>"
                "Blind SQLi: <code>'; WAITFOR DELAY '0:0:5'--</code>")
    if any(k in p for k in ["hello", "hi", "hey", "who are you"]):
        return "Hello Operator. <span class='text-green-muted'>JARVIS online.</span> Set OPENAI_API_KEY in .env for full GPT-4o intelligence."
    return "Specify a target or scenario — nmap, privilege escalation, web exploitation, or a CTF challenge."


# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC TOOLS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/tool/<tool_code>", methods=["POST"])
@require_auth
@rl("100 per hour")
def run_tool(tool_code):
    operator = get_operator(request)
    data     = request.json or {}
    payload  = data.get("payload", "").strip()
    email    = operator["sub"] if operator else "GUEST"

    if not payload:
        return jsonify({"status": "error", "result": "Empty payload."})
    if len(payload) > 2000:
        return jsonify({"status": "error", "result": "Payload too large (max 2000 chars)."})

    result = ""
    try:
        if tool_code == "hash":
            md5    = hashlib.md5(payload.encode()).hexdigest()
            sha1   = hashlib.sha1(payload.encode()).hexdigest()
            sha256 = hashlib.sha256(payload.encode()).hexdigest()
            sha512 = hashlib.sha512(payload.encode()).hexdigest()
            result = f"MD5:    {md5}\nSHA1:   {sha1}\nSHA256: {sha256}\nSHA512: {sha512}"

        elif tool_code == "url":
            target = payload if payload.startswith("http") else "https://" + payload
            vt_key = VT_API_KEY.strip()
            if not vt_key:
                return jsonify({"status": "error", "result": "[-] VT_API_KEY not set in .env\nGet a free key at: https://www.virustotal.com/gui/my-apikey"})
            # SSL_CONTEXT defined at startup

            # Step 1: Submit URL to VT for scanning
            submit_req = urllib.request.Request(
                "https://www.virustotal.com/api/v3/urls",
                data=urllib.parse.urlencode({"url": target}).encode(),
                method="POST"
            )
            submit_req.add_header("x-apikey", vt_key)
            submit_req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                with urllib.request.urlopen(submit_req, context=SSL_CONTEXT, timeout=15) as sresp:
                    submit_data = json.loads(sresp.read().decode())
                    analysis_id = submit_data["data"]["id"]
            except urllib.error.HTTPError as e:
                err_body = e.read().decode()
                result = f"[-] VT Submit Error: HTTP {e.code}\n{err_body[:300]}"
                log_action(email, tool_code.upper(), payload[:100], "vt_submit_error", request.remote_addr)
                return jsonify({"status": "error", "result": result})

            # Step 2: Poll until VT finishes scanning (up to 20s)
            import time as _time
            analysis_req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            )
            analysis_req.add_header("x-apikey", vt_key)
            vt = None
            for attempt in range(6):           # poll up to 6x with 4s gaps = 24s max
                _time.sleep(4)
                with urllib.request.urlopen(analysis_req, context=SSL_CONTEXT, timeout=15) as aresp:
                    vt = json.loads(aresp.read().decode())
                status = vt.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    break
            try:
                    attrs = vt["data"]["attributes"]
                    stats = attrs.get("stats", {})
                    mal   = stats.get("malicious", 0)
                    sus   = stats.get("suspicious", 0)
                    clean = stats.get("harmless", 0) + stats.get("undetected", 0)
                    total = mal + sus + clean
                    score   = round(((mal + sus) / total) * 100) if total else 0
                    verdict = "⚠ CRITICAL THREAT" if mal > 2 else ("⚡ SUSPICIOUS" if sus > 0 else "✓  CLEAN")
                    result  = (f"[*] VIRUSTOTAL SCAN COMPLETE\nTARGET: {target}\n"
                               f"{'─'*45}\n"
                               f"Engines Run:  {total}\n"
                               f"Malicious:    {mal}\n"
                               f"Suspicious:   {sus}\n"
                               f"Clean:        {clean}\n"
                               f"Risk Score:   {score}/100\n"
                               f"{'─'*45}\n"
                               f"VERDICT: {verdict}")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode()
                result = f"[-] VT Analysis Error: HTTP {e.code}\n{err_body[:300]}"

        elif tool_code == "ip_scan":
            abuse_key = ABUSEIPDB_KEY.strip()
            if not abuse_key:
                return jsonify({"status": "error", "result": "[-] ABUSEIPDB_KEY not set in .env\nGet a free key at: https://www.abuseipdb.com/account/api"})
            # Validate IP format loosely before sending
            ip_clean = payload.strip()
            ip_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_clean)}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(ip_url)
            req.add_header("Key", abuse_key)
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "PhishNet-SOC/1.0")
            try:
                with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
                    raw  = json.loads(resp.read().decode())
                    d    = raw.get("data", {})
                    score   = d.get("abuseConfidenceScore", 0)
                    country = d.get("countryCode", "?")
                    isp     = d.get("isp", "Unknown")
                    domain  = d.get("domain", "N/A")
                    reports = d.get("totalReports", 0)
                    usage   = d.get("usageType", "Unknown")
                    is_tor  = d.get("isTor", False)
                    is_pub  = d.get("isPublic", True)
                    verdict = "⚠ CRITICAL THREAT" if score > 75 else ("⚡ SUSPICIOUS" if score > 25 else "✓  CLEAN")
                    result  = (f"[*] ABUSEIPDB REAL-TIME REPORT\n"
                               f"IP: {ip_clean}\n"
                               f"{'─'*45}\n"
                               f"Country:       {country}\n"
                               f"ISP:           {isp}\n"
                               f"Domain:        {domain}\n"
                               f"Usage Type:    {usage}\n"
                               f"Public IP:     {'Yes' if is_pub else 'No'}\n"
                               f"Tor Exit Node: {'⚠ YES' if is_tor else 'No'}\n"
                               f"{'─'*45}\n"
                               f"Abuse Score:   {score}/100\n"
                               f"Total Reports: {reports}\n"
                               f"{'─'*45}\n"
                               f"VERDICT: {verdict}")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode()
                result = f"[-] AbuseIPDB Error: HTTP {e.code}\nDetails: {err_body[:300]}"

        elif tool_code == "dns":
            domain = payload.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            ip = socket.gethostbyname(domain)
            result = f"Domain: {domain}\nA Record: {ip}"

        elif tool_code == "conv_b64_enc":
            result = f"BASE64 ENCODED:\n{base64.b64encode(payload.encode()).decode()}"
        elif tool_code == "conv_b64_dec":
            result = f"BASE64 DECODED:\n{base64.b64decode(payload).decode('utf-8', errors='ignore')}"
        elif tool_code == "conv_hex_enc":
            result = f"HEX ENCODED:\n{payload.encode().hex()}"
        elif tool_code == "conv_hex_dec":
            cleaned = payload.replace(" ", "").replace("0x", "").replace("0X", "")
            result  = f"HEX DECODED:\n{bytes.fromhex(cleaned).decode('utf-8', errors='ignore')}"
        else:
            return jsonify({"status": "error", "result": f"Unknown tool: {tool_code}"})

        log_action(email, tool_code.upper(), payload[:100], "ok", request.remote_addr)
        return jsonify({"status": "success", "result": result})

    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        return jsonify({"status": "error", "result": f"[-] HTTP {e.code} from external API:\n{err_body[:400]}"})
    except urllib.error.URLError as e:
        return jsonify({"status": "error", "result": f"[-] Network error (check internet connection):\n{str(e.reason)}"})
    except Exception as e:
        import traceback
        return jsonify({"status": "error", "result": f"[-] Unexpected error: {html.escape(str(e))}\n{html.escape(traceback.format_exc()[-400:])}"})


# ─────────────────────────────────────────────────────────────────────────────
# TEAM / CASE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/team/activity", methods=["GET"])
@require_auth
def team_activity():
    conn = get_db()
    logs = conn.execute(
        "SELECT email, action, target, result_summary, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify({"status": "success", "activity": [dict(r) for r in logs]})


@app.route("/api/cases", methods=["GET", "POST"])
@require_auth
def manage_cases():
    op   = get_operator(request)
    conn = get_db()

    if request.method == "GET":
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        conn.close()
        return jsonify({"status": "success", "cases": [dict(r) for r in rows]})

    data = request.json or {}
    conn.execute(
        "INSERT INTO cases (title, description, severity, created_by) VALUES (?,?,?,?)",
        (data.get("title", "Untitled"), data.get("description", ""),
         data.get("severity", "medium"), op["sub"])
    )
    conn.commit()
    conn.close()
    log_action(op["sub"], "CASE_CREATE", data.get("title", ""), "", request.remote_addr)
    return jsonify({"status": "success", "message": "Case created."})


@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@require_auth
def update_case(case_id):
    data = request.json or {}
    conn = get_db()
    if "status" in data:
        conn.execute("UPDATE cases SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (data["status"], case_id))
    if "assigned_to" in data:
        conn.execute("UPDATE cases SET assigned_to=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (data["assigned_to"], case_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/cases/<int:case_id>/notes", methods=["GET", "POST"])
@require_auth
def case_notes(case_id):
    op   = get_operator(request)
    conn = get_db()

    if request.method == "GET":
        notes = conn.execute(
            "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at", (case_id,)
        ).fetchall()
        conn.close()
        return jsonify({"status": "success", "notes": [dict(n) for n in notes]})

    data = request.json or {}
    note = data.get("note", "").strip()
    if not note:
        return jsonify({"status": "error", "message": "Note is empty."})
    conn.execute("INSERT INTO case_notes (case_id, author, note) VALUES (?,?,?)",
                 (case_id, op["sub"], note))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/audit-log", methods=["GET"])
@require_auth
def audit_log():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return jsonify({"status": "success", "logs": [dict(r) for r in rows]})



# ─────────────────────────────────────────────────────────────────────────────
# WORLD INCIDENTS — CISA Known Exploited Vulnerabilities (no API key needed)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/incidents", methods=["GET"])
@require_auth
@rl("30 per hour")
def get_incidents():
    """
    Fetches real-world cyber incidents from CISA's Known Exploited Vulnerabilities catalog.
    Free, no API key required. Updated daily by CISA.
    Supports ?search=keyword and ?ransomware=yes filters.
    """
    search      = request.args.get("search", "").strip().lower()
    ransomware  = request.args.get("ransomware", "").strip().lower()
    limit       = min(int(request.args.get("limit", 50)), 200)

    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    req = urllib.request.Request(kev_url)
    req.add_header("User-Agent", "PhishNet-SOC/1.0")

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
            data  = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])

            # Most recent first
            vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)

            # Filters
            if search:
                vulns = [v for v in vulns if
                         search in v.get("vendorProject", "").lower() or
                         search in v.get("product", "").lower() or
                         search in v.get("vulnerabilityName", "").lower() or
                         search in v.get("cveID", "").lower() or
                         search in v.get("shortDescription", "").lower()]

            if ransomware == "yes":
                vulns = [v for v in vulns if
                         v.get("knownRansomwareCampaignUse", "").lower() == "known"]

            total    = len(vulns)
            vulns    = vulns[:limit]
            catalog_version = data.get("catalogVersion", "N/A")
            date_released   = data.get("dateReleased", "N/A")

            return jsonify({
                "status":          "success",
                "total":           total,
                "returned":        len(vulns),
                "catalogVersion":  catalog_version,
                "dateReleased":    date_released,
                "vulnerabilities": vulns
            })

    except urllib.error.URLError as e:
        return jsonify({"status": "error", "message": f"CISA feed unreachable: {str(e.reason)}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error fetching incidents: {html.escape(str(e))}"})




# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV CATALOG — Real known-exploited vulnerabilities database
# ─────────────────────────────────────────────────────────────────────────────
_kev_cache      = {"data": None, "ts": 0}
_KEV_CACHE_TTL  = 3600  # Re-fetch at most once per hour

@app.route("/api/incidents", methods=["GET"])
@rl("60 per hour")
def incidents():
    import time as _t
    search       = request.args.get("search", "").strip().lower()
    ransomware   = request.args.get("ransomware", "").lower() == "yes"
    limit        = min(int(request.args.get("limit", 100)), 200)

    # Use cache if fresh
    now = _t.time()
    if _kev_cache["data"] and (now - _kev_cache["ts"]) < _KEV_CACHE_TTL:
        catalog = _kev_cache["data"]
    else:
        try:
            req = urllib.request.Request(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                headers={"User-Agent": "PhishNet-SOC/1.0"}
            )
            with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
                catalog = json.loads(resp.read().decode())
            _kev_cache["data"] = catalog
            _kev_cache["ts"]   = now
        except Exception as e:
            return jsonify({"status": "error", "message": f"CISA feed unavailable: {str(e)}"})

    vulns = catalog.get("vulnerabilities", [])

    # Filters
    if ransomware:
        vulns = [v for v in vulns if v.get("knownRansomwareCampaignUse", "").lower() == "known"]
    if search:
        vulns = [v for v in vulns if search in json.dumps(v).lower()]

    # Most recent first
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    total = len(vulns)
    vulns = vulns[:limit]

    return jsonify({
        "status":          "success",
        "total":           total,
        "showing":         len(vulns),
        "catalogVersion":  catalog.get("catalogVersion", "N/A"),
        "dateReleased":    catalog.get("dateReleased", ""),
        "vulnerabilities": vulns
    })


# ─────────────────────────────────────────────────────────────────────────────
# WORLD INCIDENT FEED — Live RSS from CISA, THN, Krebs, Bleeping Computer
# ─────────────────────────────────────────────────────────────────────────────
import xml.etree.ElementTree as _ET
from email.utils import parsedate_to_datetime as _parsedate

INCIDENT_FEEDS = [
    {
        "source": "CISA",
        "url":    "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "tag":    "government",
        "color":  "red"
    },
    {
        "source": "The Hacker News",
        "url":    "https://feeds.feedburner.com/TheHackersNews",
        "tag":    "threat-intel",
        "color":  "yellow"
    },
    {
        "source": "Krebs on Security",
        "url":    "https://krebsonsecurity.com/feed/",
        "tag":    "breach",
        "color":  "pink"
    },
    {
        "source": "Bleeping Computer",
        "url":    "https://www.bleepingcomputer.com/feed/",
        "tag":    "malware",
        "color":  "cyan"
    },
]

# Keywords that flag an item as a high-severity incident
_HIGH_SEV_KEYWORDS = [
    "ransomware", "breach", "zero-day", "zeroday", "critical", "exploit",
    "vulnerability", "attack", "hacked", "leaked", "backdoor", "apt",
    "nation-state", "espionage", "cve-", "rce", "remote code"
]

def _fetch_feed(feed: dict) -> list:
    """Fetch and parse a single RSS feed, return list of incident dicts."""
    try:
        req = urllib.request.Request(
            feed["url"],
            headers={"User-Agent": "PhishNet-SOC/1.0"}
        )
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=10) as resp:
            raw = resp.read()
        root = _ET.fromstring(raw)
        items = root.findall(".//item")
        results = []
        for item in items[:8]:  # Max 8 per feed
            title   = (item.findtext("title") or "").strip()
            link    = (item.findtext("link")  or "").strip()
            desc    = (item.findtext("description") or "").strip()
            pub     = (item.findtext("pubDate") or "").strip()

            # Clean HTML tags from description
            desc_clean = _re.sub(r"<[^>]+>", "", desc)[:200]

            # Parse date
            try:
                dt  = _parsedate(pub)
                pub_fmt = dt.strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                pub_fmt = pub[:20] if pub else "Unknown"

            # Determine severity
            combined = (title + " " + desc_clean).lower()
            severity = "high" if any(k in combined for k in _HIGH_SEV_KEYWORDS) else "medium"

            results.append({
                "source":   feed["source"],
                "color":    feed["color"],
                "tag":      feed["tag"],
                "title":    title,
                "link":     link,
                "summary":  desc_clean,
                "date":     pub_fmt,
                "severity": severity,
            })
        return results
    except Exception as e:
        return [{"source": feed["source"], "color": feed["color"], "tag": feed["tag"],
                 "title": f"Feed unavailable: {str(e)[:80]}", "link": "",
                 "summary": "", "date": "", "severity": "low"}]


@app.route("/api/world-cases", methods=["GET"])
@rl("30 per hour")
def world_cases():
    """Aggregate live incident feeds from multiple cybersecurity sources."""
    all_incidents = []
    for feed in INCIDENT_FEEDS:
        all_incidents.extend(_fetch_feed(feed))

    # Sort: high severity first, then by date desc
    all_incidents.sort(key=lambda x: (0 if x["severity"] == "high" else 1, x["date"]), reverse=False)
    all_incidents.sort(key=lambda x: x["severity"] == "high", reverse=True)

    return jsonify({
        "status":    "success",
        "count":     len(all_incidents),
        "incidents": all_incidents
    })


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    missing = []
    if not VT_API_KEY:    missing.append("VT_API_KEY")
    if not ABUSEIPDB_KEY: missing.append("ABUSEIPDB_KEY")
    if not OPENAI_KEY:    missing.append("OPENAI_API_KEY")
    if not BCRYPT_OK:     missing.append("bcrypt (pip install bcrypt)")
    if not JWT_OK:        missing.append("PyJWT (pip install PyJWT)")
    if not OPENAI_OK:     missing.append("openai (pip install openai)")

    print("=" * 52)
    print("  🚀 PHISH-NET SECURE BACKEND ONLINE")
    print(f"  🔐 JWT: {'✓' if JWT_OK else '✗'}  |  bcrypt: {'✓' if BCRYPT_OK else '✗'}  |  Rate-limit: {'✓' if LIMITER_OK else '✗'}")
    print(f"  🧠 GPT-4o PentestGPT: {'✓' if OPENAI_KEY else '✗ (set OPENAI_API_KEY)'}")
    print(f"  🌐 VT: {'✓' if VT_API_KEY else '✗'}  |  AbuseIPDB: {'✓' if ABUSEIPDB_KEY else '✗'}")
    if missing:
        print(f"\n  ⚠  Missing: {', '.join(missing)}")
        print("     Copy .env.example → .env and fill in your keys.")
    print("=" * 52)
    app.run(debug=False, port=5000)