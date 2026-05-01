"""
PHISH-NET SECURE BACKEND
========================
AI:       OpenAI GPT-4o (PentestGPT mode)
Intel:    VirusTotal, AbuseIPDB, CISA KEV, NVD (200k+ CVEs), RSS news feeds
Auth:     JWT 24h + bcrypt + rate limiting
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import hashlib, socket, base64, json, re as _re, ssl, html, sqlite3, os, time as _time

# ── Turso / libsql ────────────────────────────────────────────────────────────
# Falls back to local SQLite when env vars are absent (local dev).
try:
    import libsql_experimental as _libsql
    _LIBSQL_OK = True
except ImportError:
    _LIBSQL_OK = False
import urllib.request, urllib.error, urllib.parse
import xml.etree.ElementTree as _ET
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

try:
    import bcrypt;        BCRYPT_OK  = True
except ImportError:       BCRYPT_OK  = False
try:
    import jwt as pyjwt;  JWT_OK     = True
except ImportError:       JWT_OK     = False
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_OK = True
except ImportError:       LIMITER_OK = False
try:
    import openai;        OPENAI_OK  = True
except ImportError:       OPENAI_OK  = False
try:
    import certifi
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode    = ssl.CERT_NONE

load_dotenv()
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
TURSO_URL     = os.getenv("TURSO_DATABASE_URL", "")   # e.g. libsql://your-db.turso.io
TURSO_TOKEN   = os.getenv("TURSO_AUTH_TOKEN",   "")
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")

allowed_origins = os.getenv("ALLOWED_ORIGINS",
    "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000,https://*.up.railway.app").split(",")
CORS(app, origins=allowed_origins, supports_credentials=True)

JWT_SECRET    = os.getenv("JWT_SECRET", "")
VT_API_KEY    = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")

if not JWT_SECRET:
    import secrets as _sec
    JWT_SECRET = _sec.token_hex(32)
    print("[WARN] JWT_SECRET not in .env — using temporary secret. Sessions reset on restart.")

if LIMITER_OK:
    limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day","120 per hour"])
    def rl(limit): return limiter.limit(limit)
else:
    def rl(limit):
        def d(f): return f
        return d


# -----------------------------------------------------------------------------
# DATABASE
# -----------------------------------------------------------------------------
FAMOUS_CASES = [
    ("SolarWinds Supply Chain Attack (2020)",
     "Nation-state attackers (APT29/Cozy Bear) compromised SolarWinds Orion software updates, affecting 18,000+ organizations including US government agencies. Attackers had access for 9+ months undetected. Attack vector: poisoned software build pipeline.",
     "critical", "historical"),
    ("Colonial Pipeline Ransomware (2021)",
     "DarkSide ransomware group shut down 5,500 miles of fuel pipeline supplying 45% of US East Coast fuel. $4.4M ransom paid. Attack vector: compromised VPN credentials with no MFA enabled.",
     "critical", "historical"),
    ("Log4Shell / Log4j RCE (CVE-2021-44228)",
     "CVSS 10.0 RCE in Apache Log4j logging library. Affected hundreds of millions of devices. Exploitation observed within hours of disclosure via malicious JNDI lookup strings injected into HTTP headers, user-agents, or any logged field.",
     "critical", "historical"),
    ("MOVEit Transfer Mass Exploitation (2023)",
     "Cl0p ransomware exploited SQL injection zero-day (CVE-2023-34362) in MOVEit Transfer. 2,000+ organizations compromised including US federal agencies, airlines, banks. 60M+ individuals affected. Largest data theft campaign of 2023.",
     "critical", "historical"),
    ("Microsoft Exchange ProxyLogon (2021)",
     "Four zero-days (CVE-2021-26855 to 26858) in Microsoft Exchange. HAFNIUM (Chinese APT) used pre-auth SSRF + post-auth RCE to install webshells. 250,000+ servers compromised worldwide before patch available.",
     "critical", "historical"),
    ("Okta Breach via Lapsus$ (2022)",
     "Lapsus$ group social-engineered a third-party Okta support provider, gaining 5 days of admin access. Okta serves 15,000+ organizations. Exposed the risk of third-party supply chains in identity infrastructure.",
     "high", "historical"),
    ("Twitter Bitcoin Hack (2020)",
     "Insider threat: Twitter employees bribed to access internal admin tools. 130 high-profile accounts hijacked (Obama, Biden, Musk, Apple). $120K BTC stolen in 3 hours. Exposed dangers of excessive internal tool access.",
     "high", "historical"),
    ("Equifax Data Breach (2017)",
     "Apache Struts CVE-2017-5638 exploited to steal 147M Americans' PII including SSNs, DOBs, addresses, credit card numbers. Breach undetected for 78 days due to an expired SSL cert on the internal traffic inspection tool.",
     "critical", "historical"),
    ("NotPetya Cyberattack (2017)",
     "Destructive wiper malware disguised as ransomware, attributed to Russia's Sandworm APT. Spread via Ukrainian accounting software MeDoc update. Used EternalBlue + Mimikatz. $10B+ global damage. Maersk lost $300M alone.",
     "critical", "historical"),
    ("Uber Data Breach via Social Engineering (2022)",
     "Attacker texted an Uber contractor posing as IT support and socially engineered MFA approval. Gained access to Slack, HackerOne reports, AWS, GCP, internal dashboards. Full network compromise within hours.",
     "high", "historical"),
    ("LastPass Vault Theft (2022)",
     "Attacker compromised a DevOps engineer's home machine via vulnerable Plex Media Server. Stole LastPass encrypted vault backups. Millions of users' password vaults exfiltrated. Attack shows risk of personal device access to prod systems.",
     "high", "historical"),
    ("Change Healthcare Ransomware (2024)",
     "ALPHV/BlackCat ransomware attacked Change Healthcare (UnitedHealth subsidiary). Disrupted US prescription processing nationwide for weeks. $22M ransom paid. 100M+ patient records exposed. Largest healthcare cyberattack in US history.",
     "critical", "active"),
    ("MGM Resorts Ransomware (2023)",
     "Scattered Spider social-engineered MGM IT helpdesk via LinkedIn research + phone call. Deployed ALPHV ransomware. $100M+ losses. Slot machines, hotel key systems, websites taken offline across Las Vegas properties for 10+ days.",
     "critical", "historical"),
    ("Poly Network DeFi Hack (2021)",
     "Hacker exploited cross-chain smart contract vulnerability in Poly Network to steal $611M in cryptocurrency — largest DeFi hack ever at the time. Attacker later returned most funds and was offered a security job by Poly Network.",
     "critical", "historical"),
    ("Kaseya VSA Supply Chain Attack (2021)",
     "REvil ransomware exploited zero-days in Kaseya VSA remote management software. 1,500+ businesses downstream affected via MSP supply chain. $70M ransom demanded. Attack timed to July 4th US holiday weekend.",
     "critical", "historical"),
    ("Microsoft Azure AD Token Forgery (2023)",
     "Chinese APT Storm-0558 obtained an MSA signing key and forged Azure AD tokens to access US government email accounts including State Dept and Commerce Dept. Method of key acquisition still partially unexplained by Microsoft.",
     "critical", "historical"),
    ("Medibank Data Breach (2022)",
     "Russian-linked REvil/RansomHouse group stole health data of 9.7M Medibank (Australia) customers including sensitive medical diagnoses and procedures. Company refused $10M ransom. Data released publicly on dark web.",
     "critical", "historical"),
    ("Twitter Source Code Leak (2023)",
     "Portions of Twitter/X source code leaked on GitHub. GitHub took down the repo after a DMCA notice. Twitter subpoenaed GitHub to identify the leaker. Exposed potential security vulnerabilities in core platform infrastructure.",
     "high", "historical"),
]

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT DEFAULT 'analyst',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, action TEXT,
        target TEXT, result_summary TEXT, ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
        description TEXT, severity TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'open', created_by TEXT, assigned_to TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS case_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, author TEXT,
        note TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id))""")
    conn.commit()
    if conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0:
        for title, desc, sev, status in FAMOUS_CASES:
            conn.execute(
                "INSERT INTO cases (title,description,severity,status,created_by) VALUES(?,?,?,?,?)",
                (title, desc, sev, status, "SYSTEM"))
        conn.commit()
    conn.close()

init_db()

def _row_factory(cursor, row):
    """Universal dict row factory — works with both sqlite3 and libsql."""
    return {col[0]: val for col, val in zip(cursor.description, row)}

def get_db():
    if TURSO_URL and TURSO_TOKEN and _LIBSQL_OK:
        conn = _libsql.connect(TURSO_URL, auth_token=TURSO_TOKEN)
    else:
        conn = sqlite3.connect("phishnet.db")
    conn.row_factory = _row_factory
    return conn

def log_action(email, action, target, summary="", ip=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log(email,action,target,result_summary,ip_address) VALUES(?,?,?,?,?)",
                 (email or "GUEST", action, str(target)[:200], str(summary)[:500], ip))
    conn.commit(); conn.close()


# -----------------------------------------------------------------------------
# AUTH
# -----------------------------------------------------------------------------
def hash_password(pw):
    if BCRYPT_OK:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    salt = os.urandom(16).hex()
    return salt + ":" + hashlib.sha256((salt + pw).encode()).hexdigest()

def verify_password(pw, stored):
    if BCRYPT_OK and stored.startswith("$2"):
        return bcrypt.checkpw(pw.encode(), stored.encode())
    if ":" in stored:
        salt, hashed = stored.split(":", 1)
        return hashlib.sha256((salt + pw).encode()).hexdigest() == hashed
    return hashlib.sha256(pw.encode()).hexdigest() == stored

def make_token(email, role):
    if not JWT_OK: return email
    return pyjwt.encode({
        "sub": email, "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "iat": datetime.now(timezone.utc),
    }, JWT_SECRET, algorithm="HS256")

def decode_token(token):
    if not JWT_OK: return {"sub": token, "role": "analyst"}
    try:    return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except: return None

def get_operator(req):
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return decode_token(auth[7:])
    return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_operator(request):
            return jsonify({"status":"error","message":"Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# -----------------------------------------------------------------------------
# HEALTH + AUTH ENDPOINTS
# -----------------------------------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({"status":"ok","ai":bool(OPENAI_KEY),"vt":bool(VT_API_KEY)})

@app.route("/api/token/refresh", methods=["POST"])
def refresh_token():
    op = get_operator(request)
    if not op:
        return jsonify({"status":"error","message":"Token invalid or expired."}), 401
    new_token = make_token(op["sub"], op.get("role","analyst"))
    return jsonify({"status":"success","token":new_token,"email":op["sub"],"role":op.get("role","analyst")})

@app.route("/api/register", methods=["POST"])
@rl("10 per hour")
def register():
    data  = request.json or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    if not email or "@" not in email:
        return jsonify({"status":"error","message":"Valid email required."})
    if len(pw) < 8:
        return jsonify({"status":"error","message":"Password must be 8+ chars."})
    try:
        conn = get_db()
        conn.execute("INSERT INTO users(email,password_hash) VALUES(?,?)",(email,hash_password(pw)))
        conn.commit(); conn.close()
        return jsonify({"status":"success","message":"Operator registered."})
    except Exception as e:
        if "UNIQUE" in str(e).upper() or "unique" in str(e).lower():
            return jsonify({"status":"error","message":"Email already registered."})
        raise

@app.route("/api/login", methods=["POST"])
@rl("20 per hour")
def login():
    data  = request.json or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    conn  = get_db()
    user  = conn.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    conn.close()
    if not user or not verify_password(pw, user["password_hash"]):
        return jsonify({"status":"error","message":"Invalid credentials."})
    token = make_token(email, user["role"])
    log_action(email,"LOGIN","","success",request.remote_addr)
    return jsonify({"status":"success","token":token,"email":email,"role":user["role"]})


# -----------------------------------------------------------------------------
# JARVIS — OpenAI GPT-4o PentestGPT
# -----------------------------------------------------------------------------
JARVIS_SYSTEM = """You are J.A.R.V.I.S., an elite autonomous SOC analyst and PentestGPT-powered cybersecurity assistant.
Your role: Tactical mentor for security analysts on threat intel, incident response, CTFs, forensics, and penetration testing.

FORMAT — HTML only, no markdown:
- <span class='text-yellow-muted font-bold'>[ADVISORY]</span> for headers
- <span class='text-cyan-muted'>text</span> for highlights
- <span class='text-green-muted'>text</span> for commands/safe states
- <span class='text-red-muted'>text</span> for threats/warnings
- <code>command</code> for terminal commands
- <br><br> for paragraph breaks"""

def _jarvis_fallback(prompt):
    p = prompt.lower()
    if any(k in p for k in ["nmap","port","scan","enumerate"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] ENUMERATION</span><br><br>"
                "Try <code>nmap -Pn -sV --open TARGET</code> to skip ping discovery.<br>"
                "UDP scan: <code>nmap -sU --top-ports 100 TARGET</code>")
    if any(k in p for k in ["privesc","root","privilege","escalat"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] PRIVILEGE ESCALATION</span><br><br>"
                "Linux: <code>sudo -l</code> and <code>find / -perm -4000 2>/dev/null</code><br>"
                "Windows: <code>whoami /priv</code>")
    if any(k in p for k in ["shell","reverse","payload"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] REVERSE SHELL</span><br><br>"
                "Try egress on <span class='text-cyan-muted'>443, 80, 53</span>.<br>"
                "Listener: <code>nc -lvnp 443</code>")
    if any(k in p for k in ["hello","hi","hey","who"]):
        return "Hello Operator. <span class='text-green-muted'>JARVIS online.</span> Set OPENAI_API_KEY in .env for full GPT-4o intelligence."
    return "Describe your scenario — nmap, privesc, web exploitation, or a CTF challenge."

@app.route("/api/jarvis", methods=["POST"])
@require_auth
@rl("60 per hour")
def jarvis():
    op     = get_operator(request)
    data   = request.json or {}
    prompt = data.get("prompt","").strip()
    if not prompt:
        return jsonify({"status":"error","message":"Empty prompt."})
    if len(prompt) > 4000:
        return jsonify({"status":"error","message":"Prompt too long (max 4000 chars)."})

    if not OPENAI_KEY:
        fb = _jarvis_fallback(prompt)
        return jsonify({"status":"success","response":fb,"speech":"Offline mode. Set OPENAI_API_KEY for GPT-4o."})

    if not OPENAI_OK:
        return jsonify({"status":"error","response":"<span class='text-red-muted'>[-] Run: pip install openai</span>","speech":"Package missing."})

    try:
        import httpx as _httpx
        http_client = _httpx.Client()
        client      = openai.OpenAI(api_key=OPENAI_KEY, http_client=http_client)
        completion  = client.chat.completions.create(
            model="gpt-4o", max_tokens=1024,
            messages=[{"role":"system","content":JARVIS_SYSTEM},{"role":"user","content":prompt}])
        response_text = completion.choices[0].message.content
        speech_text   = _re.sub(r"<[^>]+>","",response_text)[:300].strip()
        log_action(op["sub"],"JARVIS",prompt[:100],"ok",request.remote_addr)
        return jsonify({"status":"success","response":response_text,"speech":speech_text})
    except openai.AuthenticationError:
        return jsonify({"status":"error","response":"<span class='text-red-muted'>[-] Invalid OpenAI API key.</span>","speech":"Auth error."})
    except openai.RateLimitError:
        return jsonify({"status":"error","response":"<span class='text-red-muted'>[-] Rate limit reached.</span>","speech":"Rate limited."})
    except Exception as e:
        return jsonify({"status":"error","response":f"<span class='text-red-muted'>[-] {html.escape(str(e))}</span>","speech":"Error."})


# -----------------------------------------------------------------------------
# FORENSIC TOOLS
# -----------------------------------------------------------------------------
@app.route("/api/tool/<tool_code>", methods=["POST"])
@require_auth
@rl("100 per hour")
def run_tool(tool_code):
    op      = get_operator(request)
    data    = request.json or {}
    payload = data.get("payload","").strip()
    email   = op["sub"] if op else "GUEST"
    if not payload:       return jsonify({"status":"error","result":"Empty payload."})
    if len(payload)>2000: return jsonify({"status":"error","result":"Payload too large."})

    try:
        if tool_code == "hash":
            result = (f"MD5:    {hashlib.md5(payload.encode()).hexdigest()}\n"
                      f"SHA1:   {hashlib.sha1(payload.encode()).hexdigest()}\n"
                      f"SHA256: {hashlib.sha256(payload.encode()).hexdigest()}\n"
                      f"SHA512: {hashlib.sha512(payload.encode()).hexdigest()}")

        elif tool_code == "url":
            target  = payload if payload.startswith("http") else "https://" + payload
            vt_key  = VT_API_KEY.strip()
            if not vt_key:
                return jsonify({"status":"error","result":"VT_API_KEY not set in .env"})
            submit  = urllib.request.Request("https://www.virustotal.com/api/v3/urls",
                        data=urllib.parse.urlencode({"url":target}).encode(), method="POST")
            submit.add_header("x-apikey", vt_key)
            submit.add_header("Content-Type","application/x-www-form-urlencoded")
            with urllib.request.urlopen(submit, context=SSL_CONTEXT, timeout=15) as sr:
                analysis_id = json.loads(sr.read().decode())["data"]["id"]
            areq = urllib.request.Request(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}")
            areq.add_header("x-apikey", vt_key)
            vt = None
            for _ in range(6):
                _time.sleep(4)
                with urllib.request.urlopen(areq, context=SSL_CONTEXT, timeout=15) as ar:
                    vt = json.loads(ar.read().decode())
                if vt.get("data",{}).get("attributes",{}).get("status","") == "completed":
                    break
            attrs   = vt["data"]["attributes"]
            stats   = attrs.get("stats",{})
            mal     = stats.get("malicious",0); sus = stats.get("suspicious",0)
            clean   = stats.get("harmless",0) + stats.get("undetected",0)
            total   = mal + sus + clean
            score   = round(((mal+sus)/total)*100) if total else 0
            verdict = "CRITICAL THREAT" if mal>2 else ("SUSPICIOUS" if sus>0 else "CLEAN")
            result  = (f"[*] VIRUSTOTAL SCAN COMPLETE\nTARGET: {target}\n{'─'*45}\n"
                       f"Engines:   {total}\nMalicious: {mal}\nSuspicious:{sus}\nClean:     {clean}\n"
                       f"Risk Score:{score}/100\n{'─'*45}\nVERDICT: {verdict}")

        elif tool_code == "ip_scan":
            abuse_key = ABUSEIPDB_KEY.strip()
            if not abuse_key:
                return jsonify({"status":"error","result":"ABUSEIPDB_KEY not set in .env"})
            ip_clean = payload.strip()
            req = urllib.request.Request(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_clean)}&maxAgeInDays=90&verbose")
            req.add_header("Key", abuse_key)
            req.add_header("Accept","application/json")
            req.add_header("User-Agent","PhishNet-SOC/1.0")
            with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
                d       = json.loads(resp.read().decode())["data"]
                score   = d.get("abuseConfidenceScore",0)
                verdict = "CRITICAL THREAT" if score>75 else ("SUSPICIOUS" if score>25 else "CLEAN")
                result  = (f"[*] ABUSEIPDB REPORT\nIP: {ip_clean}\n{'─'*45}\n"
                           f"Country: {d.get('countryCode','?')} | ISP: {d.get('isp','?')}\n"
                           f"Domain:  {d.get('domain','N/A')} | Usage: {d.get('usageType','?')}\n"
                           f"Public:  {'Yes' if d.get('isPublic') else 'No'} | Tor: {'YES' if d.get('isTor') else 'No'}\n"
                           f"{'─'*45}\nAbuse Score: {score}/100 | Reports: {d.get('totalReports',0)}\n"
                           f"VERDICT: {verdict}")

        elif tool_code == "dns":
            domain = payload.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
            result = f"Domain: {domain}\nA Record: {socket.gethostbyname(domain)}"

        elif tool_code == "conv_b64_enc": result = f"BASE64 ENCODED:\n{base64.b64encode(payload.encode()).decode()}"
        elif tool_code == "conv_b64_dec": result = f"BASE64 DECODED:\n{base64.b64decode(payload).decode('utf-8',errors='ignore')}"
        elif tool_code == "conv_hex_enc": result = f"HEX ENCODED:\n{payload.encode().hex()}"
        elif tool_code == "conv_hex_dec":
            cleaned = payload.replace(" ","").replace("0x","").replace("0X","")
            result  = f"HEX DECODED:\n{bytes.fromhex(cleaned).decode('utf-8',errors='ignore')}"
        else:
            return jsonify({"status":"error","result":f"Unknown tool: {tool_code}"})

        log_action(email, tool_code.upper(), payload[:100], "ok", request.remote_addr)
        return jsonify({"status":"success","result":result})

    except urllib.error.HTTPError as e:
        return jsonify({"status":"error","result":f"[-] HTTP {e.code}: {e.read().decode()[:300]}"})
    except urllib.error.URLError as e:
        return jsonify({"status":"error","result":f"[-] Network error: {str(e.reason)}"})
    except Exception as e:
        import traceback
        return jsonify({"status":"error","result":f"[-] {html.escape(str(e))}\n{traceback.format_exc()[-300:]}"})


# -----------------------------------------------------------------------------
# NVD / NIST CVE SEARCH — 200,000+ real world vulnerabilities, no key needed
# -----------------------------------------------------------------------------
@app.route("/api/cve-search", methods=["GET"])
@rl("30 per hour")
def cve_search():
    keyword  = request.args.get("keyword","").strip()
    cve_id   = request.args.get("cveId","").strip().upper()
    severity = request.args.get("severity","").strip().upper()
    year     = request.args.get("year","").strip()
    start    = int(request.args.get("start",0))
    limit    = min(int(request.args.get("limit",20)),50)

    params = {"startIndex":start,"resultsPerPage":limit}
    if cve_id:   params["cveId"]          = cve_id
    if keyword:  params["keywordSearch"]  = keyword
    if severity: params["cvssV3Severity"] = severity
    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"]   = f"{year}-12-31T23:59:59.999"

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent":"PhishNet-SOC/1.0"})
    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
            raw   = json.loads(resp.read().decode())
            vulns = raw.get("vulnerabilities",[])
            total = raw.get("totalResults",0)
            results = []
            for v in vulns:
                cve     = v.get("cve",{})
                descs   = cve.get("descriptions",[])
                desc    = next((d["value"] for d in descs if d["lang"]=="en"),"No description.")
                metrics = cve.get("metrics",{})
                cvss3   = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30",[]))
                score   = cvss3[0]["cvssData"]["baseScore"]    if cvss3 else None
                sev_val = cvss3[0]["cvssData"]["baseSeverity"] if cvss3 else "UNKNOWN"
                cwes    = [w["description"][0]["value"] for w in cve.get("weaknesses",[]) if w.get("description")]
                refs    = [r["url"] for r in cve.get("references",[])[:3]]
                results.append({
                    "id":          cve.get("id",""),
                    "description": desc[:400],
                    "published":   cve.get("published","")[:10],
                    "modified":    cve.get("lastModified","")[:10],
                    "score":       score,
                    "severity":    sev_val,
                    "vector":      (cvss3[0]["cvssData"].get("vectorString","") if cvss3 else ""),
                    "weaknesses":  cwes[:2],
                    "references":  refs,
                })
            return jsonify({"status":"success","total":total,"start":start,"showing":len(results),"results":results})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)})


# -----------------------------------------------------------------------------
# CISA KEV CATALOG — known exploited vulnerabilities
# -----------------------------------------------------------------------------
_kev_cache = {"data":None,"ts":0}

@app.route("/api/incidents", methods=["GET"])
@rl("60 per hour")
def incidents():
    search     = request.args.get("search","").strip().lower()
    ransomware = request.args.get("ransomware","").lower() == "yes"
    limit      = min(int(request.args.get("limit",100)),200)
    now        = _time.time()

    if _kev_cache["data"] and (now - _kev_cache["ts"]) < 3600:
        catalog = _kev_cache["data"]
    else:
        try:
            req = urllib.request.Request(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                headers={"User-Agent":"PhishNet-SOC/1.0"})
            with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=15) as resp:
                catalog = json.loads(resp.read().decode())
            _kev_cache["data"] = catalog; _kev_cache["ts"] = now
        except Exception as e:
            return jsonify({"status":"error","message":f"CISA feed unavailable: {str(e)}"})

    vulns = catalog.get("vulnerabilities",[])
    if ransomware: vulns = [v for v in vulns if v.get("knownRansomwareCampaignUse","").lower()=="known"]
    if search:     vulns = [v for v in vulns if search in json.dumps(v).lower()]
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded",""), reverse=True)
    total = len(vulns)
    return jsonify({"status":"success","total":total,"showing":len(vulns[:limit]),
                    "catalogVersion":catalog.get("catalogVersion","N/A"),
                    "vulnerabilities":vulns[:limit]})


# -----------------------------------------------------------------------------
# WORLD NEWS FEED — RSS from CISA, THN, Krebs, Bleeping Computer
# -----------------------------------------------------------------------------
_HIGH_KEYWORDS = ["ransomware","breach","zero-day","critical","exploit","vulnerability",
                  "attack","hacked","leaked","backdoor","apt","espionage","cve-","rce","nation-state"]

FEEDS = [
    {"source":"CISA Alerts",          "url":"https://www.cisa.gov/uscert/ncas/alerts.xml",     "color":"yellow"},
    {"source":"The Hacker News",      "url":"https://feeds.feedburner.com/TheHackersNews",      "color":"cyan"},
    {"source":"Krebs on Security",    "url":"https://krebsonsecurity.com/feed/",                "color":"pink"},
    {"source":"Bleeping Computer",    "url":"https://www.bleepingcomputer.com/feed/",           "color":"green"},
]

def _fetch_feed(feed):
    try:
        req = urllib.request.Request(feed["url"], headers={"User-Agent":"PhishNet-SOC/1.0"})
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=10) as resp:
            root  = _ET.fromstring(resp.read())
        items = root.findall(".//item")
        results = []
        for item in items[:8]:
            title   = (item.findtext("title") or "").strip()
            link    = (item.findtext("link")  or "").strip()
            desc    = _re.sub(r"<[^>]+>","", item.findtext("description") or "")[:200]
            pub     = (item.findtext("pubDate") or "")[:25]
            combined = (title+" "+desc).lower()
            severity = "high" if any(k in combined for k in _HIGH_KEYWORDS) else "medium"
            results.append({"source":feed["source"],"color":feed["color"],
                            "title":title,"link":link,"summary":desc,"date":pub,"severity":severity})
        return results
    except Exception as e:
        return [{"source":feed["source"],"color":feed["color"],"title":f"Feed unavailable: {str(e)[:60]}",
                 "link":"","summary":"","date":"","severity":"low"}]

@app.route("/api/world-cases", methods=["GET"])
@rl("30 per hour")
def world_cases():
    all_items = []
    for feed in FEEDS:
        all_items.extend(_fetch_feed(feed))
    all_items.sort(key=lambda x: x["severity"]=="high", reverse=True)
    return jsonify({"status":"success","count":len(all_items),"incidents":all_items})


# -----------------------------------------------------------------------------
# CASES
# -----------------------------------------------------------------------------
@app.route("/api/cases", methods=["GET","POST"])
@require_auth
def manage_cases():
    op   = get_operator(request)
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        conn.close()
        return jsonify({"status":"success","cases":rows})
    data = request.json or {}
    conn.execute("INSERT INTO cases(title,description,severity,created_by) VALUES(?,?,?,?)",
                 (data.get("title","Untitled"),data.get("description",""),data.get("severity","medium"),op["sub"]))
    conn.commit(); conn.close()
    log_action(op["sub"],"CASE_CREATE",data.get("title",""),"",request.remote_addr)
    return jsonify({"status":"success","message":"Case created."})

@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@require_auth
def update_case(case_id):
    data = request.json or {}
    conn = get_db()
    if "status" in data:
        conn.execute("UPDATE cases SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(data["status"],case_id))
    if "assigned_to" in data:
        conn.execute("UPDATE cases SET assigned_to=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(data["assigned_to"],case_id))
    conn.commit(); conn.close()
    return jsonify({"status":"success"})

@app.route("/api/cases/<int:case_id>/notes", methods=["GET","POST"])
@require_auth
def case_notes(case_id):
    op   = get_operator(request)
    conn = get_db()
    if request.method == "GET":
        notes = conn.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at",(case_id,)).fetchall()
        conn.close()
        return jsonify({"status":"success","notes":notes})
    data = request.json or {}
    note = data.get("note","").strip()
    if not note: return jsonify({"status":"error","message":"Empty note."})
    conn.execute("INSERT INTO case_notes(case_id,author,note) VALUES(?,?,?)",(case_id,op["sub"],note))
    conn.commit(); conn.close()
    return jsonify({"status":"success"})

@app.route("/api/team/activity", methods=["GET"])
@require_auth
def team_activity():
    conn = get_db()
    logs = conn.execute("SELECT email,action,target,result_summary,timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify({"status":"success","activity":logs})

@app.route("/api/audit-log", methods=["GET"])
@require_auth
def audit_log():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify({"status":"success","logs":rows})


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    missing = [k for k,v in [("VT_API_KEY",VT_API_KEY),("ABUSEIPDB_KEY",ABUSEIPDB_KEY),("OPENAI_API_KEY",OPENAI_KEY)] if not v]
    print("="*52)
    print("  PHISH-NET SECURE BACKEND ONLINE")
    print(f"  JWT:{'OK' if JWT_OK else 'MISSING'} | bcrypt:{'OK' if BCRYPT_OK else 'MISSING'} | Rate-limit:{'OK' if LIMITER_OK else 'OFF'}")
    print(f"  GPT-4o PentestGPT: {'ACTIVE' if OPENAI_KEY else 'NOT SET'}")
    print(f"  NVD CVE Search: FREE (no key needed)")
    print(f"  CISA KEV: FREE (no key needed)")
    print(f"  VT: {'OK' if VT_API_KEY else 'NOT SET'} | AbuseIPDB: {'OK' if ABUSEIPDB_KEY else 'NOT SET'}")
    if missing: print(f"  Missing .env keys: {', '.join(missing)}")
    print("="*52)
    app.run(debug=False, port=5000)
