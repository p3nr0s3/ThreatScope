import streamlit as st
import requests
import pandas as pd
import json
import time
import re
import base64
from datetime import datetime
from io import BytesIO

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CORVUS — Unified Threat Intelligence",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────
# SESSION STATE BOOTSTRAP
# ─────────────────────────────────────────────────────────────
_RESULT_KEYS = ["results", "bulk_results", "mail_results", "osint_results", "hunt_results"]
for _k in _RESULT_KEYS:
    if _k not in st.session_state:
        st.session_state[_k] = []

# Load persisted secrets into session state once (setup_secrets.py writes ~/.streamlit/secrets.toml)
_SECRET_FIELDS = [
    "vt_key", "abuse_key", "shodan_key", "otx_key", "gn_key",
    "censys_id", "censys_secret", "pd_key", "intelx_key", "hibp_key", "mxtb_key",
]
for _f in _SECRET_FIELDS:
    if _f not in st.session_state:
        st.session_state[_f] = st.secrets.get(_f, "")

# Theme default
if "theme" not in st.session_state:
    st.session_state["theme"] = "dark"

# ─────────────────────────────────────────────────────────────
# THEME DEFINITIONS
# ─────────────────────────────────────────────────────────────
def inject_css() -> None:
    st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;500;700&display=swap');

/* ── Neo-Brutalist Base ── */
html, body, [data-testid="stAppViewContainer"] {
  background-color: #f0ebe3 !important;
  color: #111 !important;
  font-family: 'Inter', sans-serif !important;
}

[data-testid="stSidebar"] { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }
[data-testid="stAppViewContainer"] > section:first-child { padding-top: 0.5rem !important; }

h1, h2, h3, h4 {
  font-family: 'Space Mono', monospace !important;
  font-weight: 700 !important;
  letter-spacing: -0.02em;
  color: #111 !important;
}

/* ── Inputs ── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
  background: #fff !important;
  border: 2px solid #111 !important;
  color: #111 !important;
  font-family: 'Space Mono', monospace !important;
  font-size: 13px !important;
  border-radius: 0 !important;
  padding: 8px 12px !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
  border-color: #ff3f00 !important;
  box-shadow: 3px 3px 0 #111 !important;
}
.stSelectbox > div > div > div {
  background: #fff !important;
  border: 2px solid #111 !important;
  color: #111 !important;
  border-radius: 0 !important;
  font-family: 'Space Mono', monospace !important;
  font-size: 12px !important;
}

/* ── Buttons ── */
.stButton > button {
  background: #111 !important;
  color: #f0ebe3 !important;
  border: 2px solid #111 !important;
  font-family: 'Space Mono', monospace !important;
  font-weight: 700 !important;
  font-size: 12px !important;
  letter-spacing: 0.08em !important;
  border-radius: 0 !important;
  transition: all 0.1s ease !important;
  text-transform: uppercase !important;
}
.stButton > button:hover {
  background: #ff3f00 !important;
  border-color: #ff3f00 !important;
  color: #fff !important;
  transform: translate(-2px, -2px) !important;
  box-shadow: 3px 3px 0 #111 !important;
}
.stButton > button:active {
  transform: translate(0, 0) !important;
  box-shadow: none !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
  background: #111 !important;
  border-bottom: none !important;
  gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  background: transparent !important;
  color: #888 !important;
  font-family: 'Space Mono', monospace !important;
  font-weight: 700 !important;
  font-size: 11px !important;
  letter-spacing: 0.1em !important;
  border: none !important;
  border-right: 1px solid #333 !important;
  padding: 12px 18px !important;
  text-transform: uppercase !important;
}
.stTabs [aria-selected="true"] {
  color: #ff3f00 !important;
  background: #1a1a1a !important;
  border-bottom: 3px solid #ff3f00 !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
  background: #fff !important;
  border: 2px solid #111 !important;
  border-radius: 0 !important;
}

/* ── DataFrames ── */
div[data-testid="stDataFrame"] { border: 2px solid #111 !important; border-radius: 0 !important; }
[data-testid="stDataFrame"] th { background: #111 !important; color: #ff3f00 !important; font-family: 'Space Mono', monospace !important; font-size: 11px !important; }
[data-testid="stDataFrame"] td { background: #fff !important; color: #111 !important; font-family: 'Space Mono', monospace !important; font-size: 11px !important; }

/* ── Misc ── */
.stAlert { background: #fff !important; border: 2px solid #111 !important; border-radius: 0 !important; }
label { color: #111 !important; font-family: 'Space Mono', monospace !important; font-size: 12px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: .05em !important; }
.stProgress > div > div { background: #ff3f00 !important; }
div[data-testid="stSelectbox"] > div { background: #fff !important; }
[data-testid="stSelectbox"] * { color: #111 !important; background: #fff !important; font-family: 'Space Mono', monospace !important; }
.stCheckbox label { text-transform: none !important; letter-spacing: 0 !important; font-size: 13px !important; }
.stSlider > div > div > div { background: #ff3f00 !important; }

/* ── Neo-Brutalist custom components ── */
.corvus-header {
  background: #111;
  border-bottom: 4px solid #ff3f00;
  padding: 16px 24px;
  margin-bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.corvus-logo {
  font-family: 'Space Mono', monospace;
  font-size: 24px;
  font-weight: 700;
  color: #fff;
  letter-spacing: .1em;
}
.corvus-logo span { color: #ff3f00; }
.corvus-tagline {
  font-family: 'Space Mono', monospace;
  font-size: 10px;
  color: #888;
  letter-spacing: .15em;
  text-transform: uppercase;
  margin-top: 3px;
}
.corvus-pill {
  font-family: 'Space Mono', monospace;
  font-size: 9px;
  padding: 3px 8px;
  font-weight: 700;
  letter-spacing: .08em;
  text-transform: uppercase;
}

.metric-card {
  background: #fff;
  border: 2px solid #111;
  border-radius: 0;
  padding: 14px 18px;
  text-align: center;
  position: relative;
}
.metric-card::after {
  content: '';
  position: absolute;
  bottom: -4px;
  right: -4px;
  width: 100%;
  height: 100%;
  background: #111;
  z-index: -1;
}
.metric-value {
  font-family: 'Space Mono', monospace;
  font-size: 28px;
  font-weight: 700;
  color: #111;
}
.metric-label {
  font-size: 10px;
  color: #888;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  margin-top: 4px;
  font-family: 'Space Mono', monospace;
}

.result-card {
  background: #fff;
  border: 2px solid #111;
  border-radius: 0;
  padding: 12px 16px;
  margin: 6px 0;
  font-family: 'Space Mono', monospace;
  font-size: 11px;
  position: relative;
}
.result-card::after {
  content: '';
  position: absolute;
  bottom: -3px;
  right: -3px;
  width: 100%;
  height: 100%;
  background: #111;
  z-index: -1;
}
.result-card.malicious  { border-left: 5px solid #ff3f00; }
.result-card.clean      { border-left: 5px solid #16a34a; }
.result-card.suspicious { border-left: 5px solid #d97706; }
.result-card.unknown    { border-left: 5px solid #888; }

.corvus-section {
  border: 2px solid #111;
  border-radius: 0;
  overflow: hidden;
  margin-bottom: 16px;
}
.corvus-section-header {
  background: #111;
  padding: 8px 14px;
  font-family: 'Space Mono', monospace;
  font-size: 11px;
  font-weight: 700;
  color: #ff3f00;
  letter-spacing: .1em;
  text-transform: uppercase;
}
.corvus-section-body {
  background: #fff;
  padding: 12px 14px;
}
.ioc-detect-bar {
  background: #fff;
  border: 2px solid #111;
  padding: 8px 12px;
  margin-bottom: 10px;
  font-family: 'Space Mono', monospace;
  font-size: 11px;
  display: flex;
  align-items: center;
  gap: 10px;
}
</style>
""", unsafe_allow_html=True)

inject_css()

# ─────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value.strip()))

def is_domain(value: str) -> bool:
    return bool(re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", value.strip()))

def is_hash(value: str) -> str | None:
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32}$", v):  return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", v):  return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", v):  return "sha256"
    return None

def is_url(value: str) -> bool:
    s = value.strip()
    return s.startswith("http://") or s.startswith("https://")

def is_email(value: str) -> bool:
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", value.strip()))

def classify_ioc(value: str) -> str:
    if is_ip(value):    return "IP"
    if is_email(value): return "Email"
    if is_url(value):   return "URL"
    if is_hash(value):  return "Hash"
    if is_domain(value): return "Domain"
    return "Unknown"

def severity_color(verdict: str) -> str:
    v = str(verdict).lower()
    if any(x in v for x in ("malicious", "phishing", "spam", "breached", "vulnerable")): return "malicious"
    if any(x in v for x in ("suspicious", "warn", "issues found", "noisy")):             return "suspicious"
    if any(x in v for x in ("clean", "harmless", "safe", "not found", "benign", "passed")): return "clean"
    return "unknown"

def ts() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def key(name: str) -> str:
    """Shorthand to read from session_state."""
    return st.session_state.get(name, "")

# ─────────────────────────────────────────────────────────────
# API INTEGRATIONS
# ─────────────────────────────────────────────────────────────

def vt_check(ioc: str, api_key: str) -> dict:
    ioc = ioc.strip()
    headers = {"x-apikey": api_key}
    ioc_type = classify_ioc(ioc)
    try:
        if ioc_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type == "Hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "URL":
            ioc_b64 = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{ioc_b64}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) if stats else 0
            verdict    = "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean")
            return {
                "source": "VirusTotal", "ioc": ioc, "type": ioc_type, "verdict": verdict,
                "malicious_engines": malicious, "suspicious_engines": suspicious,
                "total_engines": total,
                "country": d.get("country", "N/A"), "asn": d.get("asn", "N/A"),
                "tags": ", ".join(d.get("tags", [])), "timestamp": ts(), "raw": json.dumps(stats),
            }
        return {"source": "VirusTotal", "ioc": ioc, "type": ioc_type,
                "verdict": f"Error {r.status_code}", "timestamp": ts(), "raw": r.text[:200]}
    except Exception as e:
        return {"source": "VirusTotal", "ioc": ioc, "type": ioc_type,
                "verdict": f"Exception: {e}", "timestamp": ts(), "raw": ""}


def abuseipdb_check(ip: str, api_key: str) -> dict:
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            verdict = "Malicious" if score >= 75 else ("Suspicious" if score >= 25 else "Clean")
            return {
                "source": "AbuseIPDB", "ioc": ip, "type": "IP", "verdict": verdict,
                "abuse_score": score, "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "N/A"), "isp": d.get("isp", "N/A"),
                "usage_type": d.get("usageType", "N/A"), "domain": d.get("domain", "N/A"),
                "is_tor": d.get("isTor", False), "timestamp": ts(), "raw": "",
            }
        return {"source": "AbuseIPDB", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "AbuseIPDB", "ioc": ip, "verdict": f"Exception: {e}", "timestamp": ts()}


def shodan_check(query: str, api_key: str) -> dict:
    try:
        if is_ip(query):
            r = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={api_key}", timeout=15)
        else:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                             params={"key": api_key, "query": query, "minify": True}, timeout=15)
        if r.status_code == 200:
            d = r.json()
            if is_ip(query):
                ports = d.get("ports", [])
                vulns = list(d.get("vulns", {}).keys())
                return {
                    "source": "Shodan", "ioc": query, "type": "IP",
                    "verdict": "Vulnerable" if vulns else "Active Host",
                    "open_ports": ", ".join(str(p) for p in ports[:10]),
                    "vulns": ", ".join(vulns[:5]), "org": d.get("org", "N/A"),
                    "os": d.get("os", "N/A"), "country": d.get("country_name", "N/A"),
                    "hostnames": ", ".join(d.get("hostnames", [])[:3]),
                    "timestamp": ts(), "raw": json.dumps(ports),
                }
            total = d.get("total", 0)
            return {"source": "Shodan", "ioc": query, "type": "Query",
                    "verdict": f"{total} results", "timestamp": ts()}
        return {"source": "Shodan", "ioc": query, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Shodan", "ioc": query, "verdict": f"Exception: {e}", "timestamp": ts()}


def otx_check(ioc: str, api_key: str) -> dict:
    ioc_type = classify_ioc(ioc)
    type_path = {"IP": "IPv4", "Domain": "domain", "URL": "url",
                 "Hash": "file", "Email": "hostname"}.get(ioc_type, "hostname")
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{ioc}/general",
            headers={"X-OTX-API-KEY": api_key}, timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            verdict = "Malicious" if pulse_count >= 3 else ("Suspicious" if pulse_count >= 1 else "Clean")
            return {
                "source": "AlienVault OTX", "ioc": ioc, "type": ioc_type, "verdict": verdict,
                "pulse_count": pulse_count, "reputation": d.get("reputation", 0),
                "country": d.get("country_name", "N/A"), "asn": d.get("asn", "N/A"),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "AlienVault OTX", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "AlienVault OTX", "ioc": ioc, "verdict": f"Exception: {e}", "timestamp": ts()}


def urlhaus_check(ioc: str) -> dict:
    try:
        if is_url(ioc):
            payload, endpoint = {"url": ioc}, "https://urlhaus-api.abuse.ch/v1/url/"
        else:
            payload, endpoint = {"host": ioc}, "https://urlhaus-api.abuse.ch/v1/host/"
        r = requests.post(endpoint, data=payload, timeout=15)
        if r.status_code == 200:
            d = r.json()
            status = d.get("query_status", "")
            urls   = d.get("urls", [])
            verdict = "Malicious" if status in ("is_host", "is_listed") or urls else "Clean"
            return {
                "source": "URLhaus", "ioc": ioc, "type": classify_ioc(ioc),
                "verdict": verdict, "status": status, "url_count": len(urls),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "URLhaus", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "URLhaus", "ioc": ioc, "verdict": f"Exception: {e}", "timestamp": ts()}


def greynoise_check(ip: str, api_key: str) -> dict:
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": api_key}, timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            noise          = d.get("noise", False)
            riot           = d.get("riot", False)
            classification = d.get("classification", "unknown")
            if classification == "malicious":
                verdict = "Malicious"
            elif riot or classification == "benign":
                verdict = "Benign"
            elif noise:
                verdict = "Noisy"
            else:
                verdict = "Unknown"
            return {
                "source": "GreyNoise", "ioc": ip, "type": "IP", "verdict": verdict,
                "classification": classification, "noise": noise, "riot": riot,
                "name": d.get("name", "N/A"), "timestamp": ts(), "raw": "",
            }
        return {"source": "GreyNoise", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "GreyNoise", "ioc": ip, "verdict": f"Exception: {e}", "timestamp": ts()}


def threatfox_check(ioc: str) -> dict:
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=json.dumps({"query": "search_ioc", "search_term": ioc}), timeout=15,
        )
        if r.status_code == 200:
            d    = r.json()
            iocs = d.get("data") or []
            verdict = "Malicious" if iocs else "Not Found"
            malware = iocs[0].get("malware", "N/A") if iocs else "N/A"
            return {
                "source": "ThreatFox", "ioc": ioc, "type": classify_ioc(ioc),
                "verdict": verdict, "malware_family": malware, "hits": len(iocs),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "ThreatFox", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "ThreatFox", "ioc": ioc, "verdict": f"Exception: {e}", "timestamp": ts()}


def ipinfo_check(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "IPInfo", "ioc": ip, "type": "IP", "verdict": "Info",
                "org": d.get("org", "N/A"), "city": d.get("city", "N/A"),
                "region": d.get("region", "N/A"), "country": d.get("country", "N/A"),
                "timezone": d.get("timezone", "N/A"), "hostname": d.get("hostname", "N/A"),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "IPInfo", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "IPInfo", "ioc": ip, "verdict": f"Exception: {e}", "timestamp": ts()}


def mxtoolbox_check(domain: str, api_key: str = "") -> dict:
    """
    Checks MX, SPF, DMARC, blacklist via MXToolbox API.
    BUG FIX: original made 4 sequential requests with no short-circuit on auth error;
    now we fail fast on the first non-200 that isn't a lookup result.
    """
    try:
        headers = {"Authorization": api_key} if api_key else {}
        results_map: dict[str, str] = {}
        for check_type in ("mx", "spf", "dmarc", "blacklist"):
            endpoint = f"https://api.mxtoolbox.com/api/v1/lookup/{check_type}/{domain}"
            r = requests.get(endpoint, headers=headers, timeout=15)
            if r.status_code == 401:
                return {"source": "MXToolbox", "ioc": domain, "verdict": "Auth Error — check API key", "timestamp": ts()}
            if r.status_code == 200:
                failed = r.json().get("Failed", [])
                results_map[check_type] = "FAIL" if failed else "PASS"
            else:
                results_map[check_type] = f"Error {r.status_code}"

        verdict = "Issues Found" if any(v == "FAIL" for v in results_map.values()) else "Passed"
        return {
            "source": "MXToolbox", "ioc": domain, "type": "Domain", "verdict": verdict,
            "mx": results_map.get("mx", "N/A"), "spf": results_map.get("spf", "N/A"),
            "dmarc": results_map.get("dmarc", "N/A"), "blacklist": results_map.get("blacklist", "N/A"),
            "timestamp": ts(), "raw": "",
        }
    except Exception as e:
        return {"source": "MXToolbox", "ioc": domain, "verdict": f"Exception: {e}", "timestamp": ts()}


def hibp_check(email: str, api_key: str) -> dict:
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "User-Agent": "CORVUS-Platform"},
            params={"truncateResponse": False}, timeout=15,
        )
        if r.status_code == 200:
            breaches     = r.json()
            breach_names = [b.get("Name", "") for b in breaches]
            verdict      = f"Breached ({len(breaches)} breaches)" if breaches else "Not Found"
            return {
                "source": "HaveIBeenPwned", "ioc": email, "type": "Email", "verdict": verdict,
                "breach_count": len(breaches), "breaches": ", ".join(breach_names[:5]),
                "timestamp": ts(), "raw": "",
            }
        if r.status_code == 404:
            return {"source": "HaveIBeenPwned", "ioc": email, "type": "Email",
                    "verdict": "Not Found", "breach_count": 0, "breaches": "", "timestamp": ts()}
        return {"source": "HaveIBeenPwned", "ioc": email, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "HaveIBeenPwned", "ioc": email, "verdict": f"Exception: {e}", "timestamp": ts()}


def censys_check(ip: str, api_id: str, api_secret: str) -> dict:
    try:
        r = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(api_id, api_secret), timeout=15,
        )
        if r.status_code == 200:
            d    = r.json().get("result", {})
            svcs = d.get("services", [])
            ports = [str(s.get("port", "")) for s in svcs]
            return {
                "source": "Censys", "ioc": ip, "type": "IP", "verdict": "Active Host",
                "open_ports": ", ".join(ports[:10]),
                "autonomous_system": d.get("autonomous_system", {}).get("name", "N/A"),
                "country": d.get("location", {}).get("country", "N/A"),
                "labels": ", ".join(d.get("labels", [])),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "Censys", "ioc": ip, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Censys", "ioc": ip, "verdict": f"Exception: {e}", "timestamp": ts()}


def pulsedive_check(ioc: str, api_key: str) -> dict:
    try:
        r = requests.get(
            "https://pulsedive.com/api/info.php",
            params={"indicator": ioc, "pretty": 1, "key": api_key}, timeout=15,
        )
        if r.status_code == 200:
            d    = r.json()
            risk = d.get("risk", "unknown")
            verdict = (
                "Malicious"  if risk in ("high", "critical") else
                "Suspicious" if risk == "medium" else
                "Clean"      if risk in ("low", "none") else
                "Unknown"
            )
            return {
                "source": "Pulsedive", "ioc": ioc, "type": classify_ioc(ioc), "verdict": verdict,
                "risk": risk,
                "threats": ", ".join(t.get("name", "") for t in d.get("threats", [])[:3]),
                "feeds":   ", ".join(f.get("name", "") for f in d.get("feeds",   [])[:3]),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "Pulsedive", "ioc": ioc, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "Pulsedive", "ioc": ioc, "verdict": f"Exception: {e}", "timestamp": ts()}


def intelx_check(query: str, api_key: str) -> dict:
    """
    BUG FIX: original used time.sleep(2) then fetched results in same request cycle.
    Now uses a configurable short poll to avoid blocking the Streamlit main thread too long.
    """
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": api_key, "Content-Type": "application/json"},
            json={"term": query, "maxresults": 20, "media": 0, "sort": 4, "terminate": []},
            timeout=15,
        )
        if r.status_code != 200:
            return {"source": "IntelligenceX", "ioc": query,
                    "verdict": f"Search Error {r.status_code}", "timestamp": ts()}

        search_id = r.json().get("id", "")
        if not search_id:
            return {"source": "IntelligenceX", "ioc": query,
                    "verdict": "No search ID returned", "timestamp": ts()}

        # Poll with a shorter sleep — still blocking but less egregious
        time.sleep(1)
        r2 = requests.get(
            f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10&offset=0",
            headers={"x-key": api_key}, timeout=15,
        )
        if r2.status_code == 200:
            records = r2.json().get("records") or []
            return {
                "source": "IntelligenceX", "ioc": query, "type": classify_ioc(query),
                "verdict": f"{len(records)} Records Found" if records else "Not Found",
                "record_count": len(records), "timestamp": ts(), "raw": "",
            }
        return {"source": "IntelligenceX", "ioc": query,
                "verdict": f"Result Error {r2.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "IntelligenceX", "ioc": query,
                "verdict": f"Exception: {e}", "timestamp": ts()}


def whois_lookup(domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15)
        if r.status_code == 200:
            d = r.json()
            events      = {e.get("eventAction", ""): e.get("eventDate", "") for e in d.get("events", [])}
            nameservers = [ns.get("ldhName", "") for ns in d.get("nameservers", [])]
            return {
                "source": "RDAP/WHOIS", "ioc": domain, "type": "Domain", "verdict": "Registered",
                "registered":   events.get("registration", "N/A"),
                "expiry":       events.get("expiration", "N/A"),
                "last_changed": events.get("last changed", "N/A"),
                "nameservers":  ", ".join(nameservers[:4]),
                "status":       ", ".join(d.get("status", [])),
                "timestamp": ts(), "raw": "",
            }
        return {"source": "RDAP/WHOIS", "ioc": domain, "verdict": f"Error {r.status_code}", "timestamp": ts()}
    except Exception as e:
        return {"source": "RDAP/WHOIS", "ioc": domain, "verdict": f"Exception: {e}", "timestamp": ts()}


def dns_lookup(domain: str) -> dict:
    try:
        r  = requests.get(f"https://dns.google/resolve?name={domain}&type=A",   timeout=10)
        r2 = requests.get(f"https://dns.google/resolve?name={domain}&type=MX",  timeout=10)
        r3 = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT", timeout=10)

        a_records   = [a.get("data", "") for a in r.json().get("Answer", [])]  if r.status_code  == 200 else []
        mx_records  = [m.get("data", "") for m in r2.json().get("Answer", [])] if r2.status_code == 200 else []
        txt_records = [t.get("data", "") for t in r3.json().get("Answer", [])] if r3.status_code == 200 else []

        spf = next((t for t in txt_records if "v=spf1" in t.lower()), "Not Found")

        dmarc_r    = requests.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT", timeout=10)
        dmarc_recs = [t.get("data", "") for t in dmarc_r.json().get("Answer", [])] if dmarc_r.status_code == 200 else []
        dmarc      = dmarc_recs[0] if dmarc_recs else "Not Found"

        return {
            "source": "DNS Lookup", "ioc": domain, "type": "Domain",
            "verdict": "Resolved" if a_records else "No A Record",
            "a_records":  ", ".join(a_records[:5]),
            "mx_records": ", ".join(mx_records[:3]),
            "spf":   spf[:80]   if len(spf)   > 80 else spf,
            "dmarc": dmarc[:80] if len(dmarc) > 80 else dmarc,
            "timestamp": ts(), "raw": "",
        }
    except Exception as e:
        return {"source": "DNS Lookup", "ioc": domain, "verdict": f"Exception: {e}", "timestamp": ts()}


# ─────────────────────────────────────────────────────────────
# SHARED UI HELPERS
# ─────────────────────────────────────────────────────────────

def render_result_cards(results: list[dict]) -> None:
    COLOR_MAP = {"malicious": "#ff3f00", "suspicious": "#d97706", "clean": "#16a34a", "unknown": "#888"}
    SKIP = {"source", "ioc", "type", "verdict", "timestamp", "raw", "session_ioc"}
    for r in results:
        verdict = r.get("verdict", "Unknown")
        sev     = severity_color(verdict)
        color   = COLOR_MAP.get(sev, "#888")
        details = " &nbsp;·&nbsp; ".join(
            f"<span style='color:#888;font-size:10px;'>{k}:</span> <span style='color:#111;'>{v}</span>"
            for k, v in r.items()
            if k not in SKIP and v and v != "N/A"
        )
        st.markdown(f"""
<div class='result-card {sev}'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;'>
    <span style='font-family:Space Mono,monospace;font-weight:700;font-size:13px;color:#111;letter-spacing:.05em;'>{r.get("source","").upper()}</span>
    <span style='font-family:Space Mono,monospace;font-weight:700;font-size:13px;color:{color};text-transform:uppercase;letter-spacing:.05em;'>{verdict}</span>
  </div>
  <div style='color:#555;font-size:11px;line-height:1.9;font-family:Space Mono,monospace;'>{details}</div>
</div>
""", unsafe_allow_html=True)


def run_checks(ioc: str, checks: list[tuple]) -> list[dict]:
    """Execute a list of (name, callable) checks with progress bar."""
    results: list[dict] = []
    if not checks:
        st.warning("⚠️ No sources selected or required API keys not configured. "
                   "URLhaus, ThreatFox, and IPInfo are free (no key needed).")
        return results

    progress     = st.progress(0)
    status_txt   = st.empty()
    for i, (name, fn) in enumerate(checks):
        status_txt.markdown(
            f"<span style='font-family:JetBrains Mono,monospace;font-size:13px;"
            f"color:#ff3f00;font-weight:700;text-transform:uppercase;'>↳ QUERYING {name}…</span>",
            unsafe_allow_html=True,
        )
        results.append(fn())
        progress.progress((i + 1) / len(checks))
        time.sleep(0.2)

    status_txt.empty()
    progress.empty()
    return results


# ─────────────────────────────────────────────────────────────
# HEADER  (replaces sidebar branding)
# ─────────────────────────────────────────────────────────────

st.markdown("""
<div class='corvus-header'>
  <div>
    <div class='corvus-logo'>CORV<span>US</span></div>
    <div class='corvus-tagline'>Unified Threat Intelligence Platform</div>
  </div>
  <div style='display:flex;gap:8px;align-items:center;'>
    <span class='corvus-pill' style='background:#ff3f00;color:#fff;'>IOC CHECK</span>
    <span class='corvus-pill' style='background:#fff;color:#111;border:1.5px solid #333;'>BULK</span>
    <span class='corvus-pill' style='background:#fff;color:#111;border:1.5px solid #333;'>MAIL</span>
    <span class='corvus-pill' style='background:#fff;color:#111;border:1.5px solid #333;'>HUNT</span>
    <span class='corvus-pill' style='background:#fff;color:#111;border:1.5px solid #333;'>OSINT</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# MAIN TABS  (Settings is now the 7th tab — replaces sidebar)
# ─────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "IOC CHECK",
    "BULK CHECK",
    "MAIL ANALYSIS",
    "IOC HUNTING",
    "OSINT",
    "RESULTS & EXPORT",
    "SETTINGS",
])

# ════════════════════════════════════════════════════════════════
# TAB 7 — SETTINGS  (API keys — moved from sidebar)
# ════════════════════════════════════════════════════════════════
with tab7:
    st.markdown("### API CONFIGURATION")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Keys are stored in Streamlit session state only — never written to disk from here.<br>"
        "Run <code>python setup_secrets.py</code> once to persist them across restarts via "
        "<code>~/.streamlit/secrets.toml</code>."
        "</div>",
        unsafe_allow_html=True,
    )

    col_s1, col_s2 = st.columns(2)

    with col_s1:
        with st.expander("🔬 VirusTotal", expanded=False):
            st.session_state["vt_key"] = st.text_input(
                "API Key", value=st.session_state.get("vt_key", ""),
                type="password", placeholder="VT API key…", key="_cfg_vt")

        with st.expander("🚨 AbuseIPDB", expanded=False):
            st.session_state["abuse_key"] = st.text_input(
                "API Key", value=st.session_state.get("abuse_key", ""),
                type="password", placeholder="AbuseIPDB key…", key="_cfg_abuse")

        with st.expander("🔍 Shodan", expanded=False):
            st.session_state["shodan_key"] = st.text_input(
                "API Key", value=st.session_state.get("shodan_key", ""),
                type="password", placeholder="Shodan key…", key="_cfg_shodan")

        with st.expander("👽 AlienVault OTX", expanded=False):
            st.session_state["otx_key"] = st.text_input(
                "API Key", value=st.session_state.get("otx_key", ""),
                type="password", placeholder="OTX key…", key="_cfg_otx")

        with st.expander("🌫️ GreyNoise", expanded=False):
            st.session_state["gn_key"] = st.text_input(
                "API Key", value=st.session_state.get("gn_key", ""),
                type="password", placeholder="GreyNoise key…", key="_cfg_gn")

    with col_s2:
        with st.expander("📡 Censys", expanded=False):
            st.session_state["censys_id"] = st.text_input(
                "API ID", value=st.session_state.get("censys_id", ""),
                type="password", key="_cfg_censys_id")
            st.session_state["censys_secret"] = st.text_input(
                "API Secret", value=st.session_state.get("censys_secret", ""),
                type="password", key="_cfg_censys_secret")

        with st.expander("💉 Pulsedive", expanded=False):
            st.session_state["pd_key"] = st.text_input(
                "API Key", value=st.session_state.get("pd_key", ""),
                type="password", placeholder="Pulsedive key…", key="_cfg_pd")

        with st.expander("🧠 IntelligenceX", expanded=False):
            st.session_state["intelx_key"] = st.text_input(
                "API Key", value=st.session_state.get("intelx_key", ""),
                type="password", placeholder="IntelX key…", key="_cfg_intelx")

        with st.expander("📧 HaveIBeenPwned", expanded=False):
            st.session_state["hibp_key"] = st.text_input(
                "API Key", value=st.session_state.get("hibp_key", ""),
                type="password", placeholder="HIBP key…", key="_cfg_hibp")

        with st.expander("📨 MXToolbox", expanded=False):
            st.session_state["mxtb_key"] = st.text_input(
                "API Key (optional)", value=st.session_state.get("mxtb_key", ""),
                type="password", placeholder="Optional…", key="_cfg_mxtb")

    st.markdown("---")

    # Active integrations summary
    active = [
        label for label, k in [
            ("VirusTotal", "vt_key"), ("AbuseIPDB", "abuse_key"), ("Shodan", "shodan_key"),
            ("OTX", "otx_key"), ("GreyNoise", "gn_key"), ("Censys", "censys_id"),
            ("Pulsedive", "pd_key"), ("IntelX", "intelx_key"), ("HIBP", "hibp_key"),
        ]
        if st.session_state.get(k)
    ]

    free_note = "**Free (no key):** URLhaus · ThreatFox · IPInfo · DNS · RDAP/WHOIS"
    if active:
        st.markdown(f"**Active integrations ({len(active)}):** {' · '.join(active)}\n\n{free_note}")
    else:
        st.info(f"No paid API keys configured yet.\n\n{free_note}")

    st.markdown("""
**To persist keys across restarts:**
```bash
python setup_secrets.py
```
This writes `~/.streamlit/secrets.toml` which Streamlit loads automatically on startup.
""")


# ════════════════════════════════════════════════════════════════
# TAB 1 — SINGLE IOC CHECK
# ════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### Single IOC Analysis")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Analyze a single IOC across multiple threat intelligence sources simultaneously."
        "</div>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        ioc_input = st.text_input(
            "Enter IOC (IP, Domain, URL, Hash, Email)",
            placeholder="e.g. 1.2.3.4 | evil.com | https://… | abc123… | user@domain.com",
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        auto_detect = st.checkbox("Auto-detect type", value=True)

    if ioc_input:
        ioc_type_detected = classify_ioc(ioc_input.strip())
        st.markdown(f"""
<div style='background:var(--bg-card);border:1px solid var(--border);border-radius:6px;
     padding:10px 16px;margin-bottom:12px;font-family:JetBrains Mono,monospace;font-size:13px;'>
  <span style='color:var(--text-muted);'>Detected Type:</span>
  <span style='color:var(--accent-cyan);font-weight:600;'> {ioc_type_detected}</span>
  <span style='color:var(--text-muted);margin-left:20px;'>IOC:</span>
  <span style='color:var(--text-primary);'> {ioc_input.strip()}</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("**Select Intelligence Sources:**")
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        use_vt       = st.checkbox("VirusTotal",    value=False, key="ioc_vt")
        use_otx      = st.checkbox("AlienVault OTX", value=False, key="ioc_otx")
    with c2:
        use_abuse    = st.checkbox("AbuseIPDB",     value=False, key="ioc_abuse")
        use_urlhaus  = st.checkbox("URLhaus",       value=False, key="ioc_urlhaus")
    with c3:
        use_shodan   = st.checkbox("Shodan",        value=False, key="ioc_shodan")
        use_threatfox = st.checkbox("ThreatFox",    value=False, key="ioc_threatfox")
    with c4:
        use_gn       = st.checkbox("GreyNoise",     value=False, key="ioc_gn")
        use_ipinfo   = st.checkbox("IPInfo (free)", value=False, key="ioc_ipinfo")
    with c5:
        use_pd       = st.checkbox("Pulsedive",     value=False, key="ioc_pd")
        use_censys   = st.checkbox("Censys",        value=False, key="ioc_censys")

    col_btn1, _ = st.columns([1, 4])
    with col_btn1:
        analyze_btn = st.button("⚡ ANALYZE IOC", use_container_width=True, key="btn_analyze_ioc")

    if analyze_btn:
        if not ioc_input:
            st.error("Please enter an IOC value to analyze.")
        else:
            ioc      = ioc_input.strip()
            ioc_type = classify_ioc(ioc)
            checks: list[tuple] = []

            # Build check list — capture loop variable correctly with default args
            if use_vt       and key("vt_key"):    checks.append(("VirusTotal",    lambda _i=ioc, _k=key("vt_key"):    vt_check(_i, _k)))
            if use_abuse    and key("abuse_key") and ioc_type == "IP":
                                                   checks.append(("AbuseIPDB",    lambda _i=ioc, _k=key("abuse_key"): abuseipdb_check(_i, _k)))
            if use_shodan   and key("shodan_key"): checks.append(("Shodan",       lambda _i=ioc, _k=key("shodan_key"): shodan_check(_i, _k)))
            if use_otx      and key("otx_key"):    checks.append(("OTX",          lambda _i=ioc, _k=key("otx_key"):   otx_check(_i, _k)))
            if use_urlhaus:                        checks.append(("URLhaus",       lambda _i=ioc:                       urlhaus_check(_i)))
            if use_gn       and key("gn_key") and ioc_type == "IP":
                                                   checks.append(("GreyNoise",    lambda _i=ioc, _k=key("gn_key"):    greynoise_check(_i, _k)))
            if use_threatfox:                      checks.append(("ThreatFox",    lambda _i=ioc:                       threatfox_check(_i)))
            if use_ipinfo   and ioc_type == "IP":  checks.append(("IPInfo",       lambda _i=ioc:                       ipinfo_check(_i)))
            if use_pd       and key("pd_key"):     checks.append(("Pulsedive",    lambda _i=ioc, _k=key("pd_key"):    pulsedive_check(_i, _k)))
            if use_censys   and key("censys_id"):  checks.append(("Censys",       lambda _i=ioc, _a=key("censys_id"), _s=key("censys_secret"): censys_check(_i, _a, _s)))

            results = run_checks(ioc, checks)
            if results:
                for r in results:
                    r["session_ioc"] = ioc
                st.session_state.results.extend(results)

                # Summary metrics
                mal = sum(1 for r in results if "malicious" in str(r.get("verdict", "")).lower())
                sus = sum(1 for r in results if "suspicious" in str(r.get("verdict", "")).lower())
                cln = sum(1 for r in results if any(x in str(r.get("verdict", "")).lower()
                                                    for x in ("clean", "safe", "harmless", "not found", "benign")))
                st.markdown("<br>", unsafe_allow_html=True)
                m1, m2, m3, m4 = st.columns(4)
                m1.markdown(f"<div class='metric-card'><div class='metric-value' style='color:var(--accent-red);'>{mal}</div><div class='metric-label'>Malicious Flags</div></div>", unsafe_allow_html=True)
                m2.markdown(f"<div class='metric-card'><div class='metric-value' style='color:var(--accent-orange);'>{sus}</div><div class='metric-label'>Suspicious Flags</div></div>", unsafe_allow_html=True)
                m3.markdown(f"<div class='metric-card'><div class='metric-value' style='color:var(--accent-green);'>{cln}</div><div class='metric-label'>Clean / Safe</div></div>", unsafe_allow_html=True)
                m4.markdown(f"<div class='metric-card'><div class='metric-value'>{len(results)}</div><div class='metric-label'>Sources Queried</div></div>", unsafe_allow_html=True)
                st.markdown("<br>", unsafe_allow_html=True)
                render_result_cards(results)


# ════════════════════════════════════════════════════════════════
# TAB 2 — BULK IOC CHECK
# ════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Bulk IOC Analysis")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Upload a file or paste multiple IOCs for batch processing.</div>",
        unsafe_allow_html=True,
    )

    col_in1, col_in2 = st.columns([2, 1])
    with col_in1:
        bulk_text = st.text_area(
            "Paste IOCs (one per line)", height=200,
            placeholder="1.2.3.4\nevil-domain.com\nhttps://malware-url.com/payload",
        )
    with col_in2:
        uploaded_file  = st.file_uploader("Or upload .txt / .csv", type=["txt", "csv"])
        delay_seconds  = st.slider("Delay between requests (s)", 0.0, 3.0, 0.5, 0.1,
                                   help="Reduce to speed up; increase to avoid rate-limiting")

    st.markdown("**Select Intelligence Sources:**")
    bc1, bc2, bc3, bc4 = st.columns(4)
    with bc1:
        bulk_vt    = st.checkbox("VirusTotal", value=False, key="bulk_vt")
        bulk_abuse = st.checkbox("AbuseIPDB",  value=False, key="bulk_abuse")
    with bc2:
        bulk_otx   = st.checkbox("OTX",        value=False, key="bulk_otx")
        bulk_tf    = st.checkbox("ThreatFox",  value=False, key="bulk_tf")
    with bc3:
        bulk_uh    = st.checkbox("URLhaus",    value=False, key="bulk_uh")
        bulk_gn    = st.checkbox("GreyNoise",  value=False, key="bulk_gn")
    with bc4:
        bulk_pd    = st.checkbox("Pulsedive",  value=False, key="bulk_pd")
        bulk_ipinfo = st.checkbox("IPInfo",    value=False, key="bulk_ipinfo")

    ioc_list: list[str] = []
    if uploaded_file:
        content  = uploaded_file.read().decode("utf-8", errors="ignore")
        ioc_list = [line.strip() for line in content.splitlines() if line.strip()]
    elif bulk_text:
        ioc_list = [line.strip() for line in bulk_text.splitlines() if line.strip()]

    if ioc_list:
        st.markdown(
            f"<div style='background:var(--bg-card);border:1px solid var(--border);border-radius:6px;"
            f"padding:10px 16px;margin-bottom:12px;font-family:JetBrains Mono,monospace;font-size:13px;'>"
            f"<span style='color:var(--text-muted);'>Loaded:</span> "
            f"<span style='color:var(--accent-cyan);font-weight:600;'>{len(ioc_list)} IOCs</span>"
            f"<span style='color:var(--text-muted);margin-left:20px;'>Types:</span> "
            f"<span style='color:var(--text-primary);'>{', '.join(set(classify_ioc(i) for i in ioc_list))}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    col_b1, _ = st.columns([1, 4])
    with col_b1:
        bulk_btn = st.button("⚡ RUN BULK CHECK", use_container_width=True, key="btn_bulk_check")

    if bulk_btn and ioc_list:
        all_results: list[dict] = []
        prog             = st.progress(0)
        status_ph        = st.empty()

        for idx, ioc in enumerate(ioc_list):
            ioc_type = classify_ioc(ioc)
            ioc_results: list[dict] = []

            if bulk_vt    and key("vt_key"):    ioc_results.append(vt_check(ioc, key("vt_key")))
            if bulk_abuse and key("abuse_key") and ioc_type == "IP":
                ioc_results.append(abuseipdb_check(ioc, key("abuse_key")))
            if bulk_otx   and key("otx_key"):   ioc_results.append(otx_check(ioc, key("otx_key")))
            if bulk_tf:                          ioc_results.append(threatfox_check(ioc))
            if bulk_uh:                          ioc_results.append(urlhaus_check(ioc))
            if bulk_gn    and key("gn_key") and ioc_type == "IP":
                ioc_results.append(greynoise_check(ioc, key("gn_key")))
            if bulk_pd    and key("pd_key"):     ioc_results.append(pulsedive_check(ioc, key("pd_key")))
            if bulk_ipinfo and ioc_type == "IP": ioc_results.append(ipinfo_check(ioc))

            for r in ioc_results:
                r["session_ioc"] = ioc
            all_results.extend(ioc_results)

            status_ph.markdown(
                f"<span style='font-family:JetBrains Mono;font-size:13px;color:var(--accent-cyan);'>"
                f"[{idx+1}/{len(ioc_list)}] {ioc}</span>",
                unsafe_allow_html=True,
            )
            prog.progress((idx + 1) / len(ioc_list))
            if delay_seconds > 0:
                time.sleep(delay_seconds)

        status_ph.empty()
        prog.empty()
        st.session_state.bulk_results.extend(all_results)
        st.success(f"✅ Completed: {len(all_results)} results from {len(ioc_list)} IOCs")

        if all_results:
            df = pd.DataFrame(all_results)
            st.dataframe(df, use_container_width=True)
    elif bulk_btn:
        st.warning("No IOCs loaded. Paste some above or upload a file.")


# ════════════════════════════════════════════════════════════════
# TAB 3 — MAIL ANALYSIS
# ════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### Mail Analysis")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Analyze email addresses, domains, or paste raw email headers for SPF/DKIM/DMARC inspection."
        "</div>",
        unsafe_allow_html=True,
    )

    mail_col1, mail_col2 = st.columns(2)
    with mail_col1:
        mail_target = st.text_input("Email address or sending domain",
                                    placeholder="user@example.com or example.com")
        st.markdown("**Select checks:**")
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            mail_vt    = st.checkbox("VirusTotal",    value=False, key="mail_vt")
            mail_abuse = st.checkbox("AbuseIPDB",     value=False, key="mail_abuse")
        with mc2:
            mail_hibp  = st.checkbox("HaveIBeenPwned", value=False, key="mail_hibp")
            mail_otx   = st.checkbox("AlienVault OTX", value=False, key="mail_otx")
        with mc3:
            mail_dns   = st.checkbox("DNS Lookup",    value=False, key="mail_dns")
            mail_mx    = st.checkbox("MXToolbox",     value=False, key="mail_mx")
            mail_whois = st.checkbox("WHOIS/RDAP",    value=False, key="mail_whois")

        col_mb, _ = st.columns([1, 3])
        with col_mb:
            mail_btn = st.button("⚡ ANALYZE", use_container_width=True, key="btn_mail_analyze")

    with mail_col2:
        header_text = st.text_area(
            "Paste raw email headers (optional)",
            height=260,
            placeholder="Received: from …\nFrom: …\nTo: …\n…",
        )

    if mail_btn and mail_target:
        target   = mail_target.strip()
        domain   = target.split("@")[-1] if "@" in target else target
        ioc_type = classify_ioc(target)
        checks: list[tuple] = []

        if mail_vt    and key("vt_key"):                     checks.append(("VirusTotal",    lambda _i=target, _k=key("vt_key"):   vt_check(_i, _k)))
        if mail_abuse and key("abuse_key") and is_ip(target): checks.append(("AbuseIPDB",    lambda _i=target, _k=key("abuse_key"): abuseipdb_check(_i, _k)))
        if mail_hibp  and key("hibp_key") and "@" in target:  checks.append(("HIBP",         lambda _i=target, _k=key("hibp_key"):  hibp_check(_i, _k)))
        if mail_otx   and key("otx_key"):                     checks.append(("OTX",          lambda _i=target, _k=key("otx_key"):   otx_check(_i, _k)))
        if mail_dns:                                          checks.append(("DNS",           lambda _d=domain: dns_lookup(_d)))
        if mail_mx:                                           checks.append(("MXToolbox",     lambda _d=domain, _k=key("mxtb_key"): mxtoolbox_check(_d, _k)))
        if mail_whois:                                        checks.append(("WHOIS",         lambda _d=domain: whois_lookup(_d)))

        results = run_checks(target, checks)
        if results:
            st.session_state.mail_results.extend(results)
            render_result_cards(results)

    # Header parsing
    if header_text:
        st.markdown("---")
        st.markdown("**Header Analysis**")
        received_lines = [l for l in header_text.splitlines() if l.lower().startswith("received")]
        auth_lines     = [l for l in header_text.splitlines() if "authentication-results" in l.lower()
                          or "dkim" in l.lower() or "spf" in l.lower()]
        from_lines     = [l for l in header_text.splitlines() if l.lower().startswith("from:")]
        to_lines       = [l for l in header_text.splitlines() if l.lower().startswith("to:")]
        subj_lines     = [l for l in header_text.splitlines() if l.lower().startswith("subject:")]

        hc1, hc2 = st.columns(2)
        with hc1:
            st.markdown(f"**From:** {from_lines[0] if from_lines else 'Not found'}")
            st.markdown(f"**To:** {to_lines[0] if to_lines else 'Not found'}")
            st.markdown(f"**Subject:** {subj_lines[0] if subj_lines else 'Not found'}")
            st.markdown(f"**Received hops:** {len(received_lines)}")
        with hc2:
            if auth_lines:
                st.markdown("**Auth results:**")
                for l in auth_lines[:5]:
                    st.code(l, language=None)
            else:
                st.info("No Authentication-Results header found.")

        # Extract IPs from Received headers
        ips_in_headers = list(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", header_text)))
        if ips_in_headers:
            st.markdown(f"**IPs found in headers:** `{'` · `'.join(ips_in_headers)}`")


# ════════════════════════════════════════════════════════════════
# TAB 4 — IOC HUNTING
# ════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### IOC Hunting")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Pivot and hunt for related infrastructure using Shodan, ThreatFox, and OTX."
        "</div>",
        unsafe_allow_html=True,
    )

    hunt_col1, hunt_col2 = st.columns([2, 1])
    with hunt_col1:
        hunt_query = st.text_input("Hunt query (IP, domain, hash, keyword, Shodan dork)",
                                   placeholder="org:'Evil Corp' port:445 product:Apache")
    with hunt_col2:
        hunt_type = st.selectbox("Query type", ["Auto-detect", "IP", "Domain", "Hash", "Shodan Dork"])

    st.markdown("**Select hunting sources:**")
    hc1, hc2, hc3 = st.columns(3)
    with hc1:
        hunt_shodan = st.checkbox("Shodan",     value=False, key="hunt_shodan")
        hunt_tf     = st.checkbox("ThreatFox",  value=False, key="hunt_tf")
    with hc2:
        hunt_otx    = st.checkbox("OTX Pulses", value=False, key="hunt_otx")
        hunt_vt     = st.checkbox("VirusTotal", value=False, key="hunt_vt")
    with hc3:
        hunt_uh     = st.checkbox("URLhaus",    value=False, key="hunt_uh")
        hunt_whois  = st.checkbox("WHOIS",      value=False, key="hunt_whois")

    col_hb, _ = st.columns([1, 4])
    with col_hb:
        hunt_btn = st.button("🕵️ START HUNT", use_container_width=True, key="btn_hunt")

    if hunt_btn and hunt_query:
        q = hunt_query.strip()
        checks: list[tuple] = []

        if hunt_shodan and key("shodan_key"): checks.append(("Shodan",    lambda _q=q, _k=key("shodan_key"): shodan_check(_q, _k)))
        if hunt_tf:                           checks.append(("ThreatFox", lambda _q=q: threatfox_check(_q)))
        if hunt_otx   and key("otx_key"):     checks.append(("OTX",       lambda _q=q, _k=key("otx_key"): otx_check(_q, _k)))
        if hunt_vt    and key("vt_key"):      checks.append(("VT",        lambda _q=q, _k=key("vt_key"): vt_check(_q, _k)))
        if hunt_uh:                           checks.append(("URLhaus",   lambda _q=q: urlhaus_check(_q)))
        if hunt_whois:                        checks.append(("WHOIS",     lambda _q=q: whois_lookup(_q)))

        results = run_checks(q, checks)
        if results:
            st.session_state.hunt_results.extend(results)
            st.markdown("---")
            st.markdown("**ATT&CK Technique Mapping:**")
            attck_col1, attck_col2 = st.columns(2)
            with attck_col1:
                st.markdown("""
- **T1046** — Network Service Discovery
- **T1595** — Active Scanning
- **T1590** — Gather Victim Network Info
""")
            with attck_col2:
                st.markdown("""
- **T1071** — C2 over HTTP/HTTPS
- **T1566** — Phishing
""")
            render_result_cards(results)
    elif hunt_btn:
        st.warning("Enter a hunt query first.")


# ════════════════════════════════════════════════════════════════
# TAB 5 — OSINT
# ════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### OSINT Investigation")
    st.markdown(
        "<div style='font-size:13px;color:var(--text-muted);margin-bottom:16px;'>"
        "Full intelligence profile pivot for a target entity."
        "</div>",
        unsafe_allow_html=True,
    )

    osint_col1, osint_col2 = st.columns([2, 1])
    with osint_col1:
        osint_target = st.text_input("Target (IP, domain, email, hash)",
                                     placeholder="target.com or 192.168.1.1")
    with osint_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        osint_deep = st.checkbox("Deep scan (slower, more sources)", value=False)

    st.markdown("**OSINT modules:**")
    oc1, oc2, oc3, oc4 = st.columns(4)
    with oc1:
        osint_whois = st.checkbox("WHOIS/RDAP",    value=False, key="osint_whois")
        osint_dns   = st.checkbox("DNS Lookup",    value=False, key="osint_dns")
    with oc2:
        osint_vt    = st.checkbox("VirusTotal",    value=False, key="osint_vt")
        osint_otx   = st.checkbox("AlienVault OTX",value=False, key="osint_otx")
    with oc3:
        osint_shodan = st.checkbox("Shodan",       value=False, key="osint_shodan")
        osint_censys = st.checkbox("Censys",       value=False, key="osint_censys")
    with oc4:
        osint_intelx = st.checkbox("IntelligenceX",value=False, key="osint_intelx")
        osint_hibp   = st.checkbox("HIBP",         value=False, key="osint_hibp")

    col_ob, _ = st.columns([1, 4])
    with col_ob:
        osint_btn = st.button("🌐 RUN OSINT", use_container_width=True, key="btn_osint")

    if osint_btn and osint_target:
        t = osint_target.strip()
        domain = t.split("@")[-1] if "@" in t else t
        checks: list[tuple] = []

        if osint_whois:                              checks.append(("WHOIS",    lambda _d=domain: whois_lookup(_d)))
        if osint_dns:                                checks.append(("DNS",      lambda _d=domain: dns_lookup(_d)))
        if osint_vt    and key("vt_key"):            checks.append(("VT",       lambda _i=t, _k=key("vt_key"): vt_check(_i, _k)))
        if osint_otx   and key("otx_key"):           checks.append(("OTX",      lambda _i=t, _k=key("otx_key"): otx_check(_i, _k)))
        if osint_shodan and key("shodan_key"):        checks.append(("Shodan",   lambda _i=t, _k=key("shodan_key"): shodan_check(_i, _k)))
        if osint_censys and key("censys_id"):         checks.append(("Censys",   lambda _i=t, _a=key("censys_id"), _s=key("censys_secret"): censys_check(_i, _a, _s)))
        if osint_intelx and key("intelx_key"):        checks.append(("IntelX",   lambda _i=t, _k=key("intelx_key"): intelx_check(_i, _k)))
        if osint_hibp   and key("hibp_key") and "@" in t:
            checks.append(("HIBP", lambda _i=t, _k=key("hibp_key"): hibp_check(_i, _k)))

        results = run_checks(t, checks)
        if results:
            st.session_state.osint_results.extend(results)
            render_result_cards(results)
    elif osint_btn:
        st.warning("Enter a target first.")


# ════════════════════════════════════════════════════════════════
# TAB 6 — RESULTS & EXPORT
# ════════════════════════════════════════════════════════════════
with tab6:
    st.markdown("### Results & Export")

    all_results: list[dict] = (
        st.session_state.results +
        st.session_state.bulk_results +
        st.session_state.mail_results +
        st.session_state.hunt_results +
        st.session_state.osint_results
    )

    if not all_results:
        st.info("No results yet. Run some checks in the other tabs.")
    else:
        df = pd.DataFrame(all_results)

        # Filters
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            source_filter = st.multiselect("Filter by source",
                                           options=sorted(df["source"].dropna().unique().tolist()),
                                           default=[])
        with fc2:
            verdict_filter = st.multiselect("Filter by verdict",
                                            options=sorted(df["verdict"].dropna().unique().tolist()),
                                            default=[])
        with fc3:
            ioc_search = st.text_input("Search IOC", placeholder="partial match…")

        filtered = df.copy()
        if source_filter:  filtered = filtered[filtered["source"].isin(source_filter)]
        if verdict_filter: filtered = filtered[filtered["verdict"].isin(verdict_filter)]
        if ioc_search:     filtered = filtered[filtered["ioc"].str.contains(ioc_search, case=False, na=False)]

        st.markdown(f"**{len(filtered)} result(s)**")
        st.dataframe(filtered.drop(columns=["raw"], errors="ignore"), use_container_width=True)

        # Export
        exp_col1, exp_col2, exp_col3 = st.columns(3)
        with exp_col1:
            csv_data = filtered.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download CSV", data=csv_data,
                               file_name=f"corvus_{datetime.utcnow():%Y%m%d_%H%M%S}.csv",
                               mime="text/csv")
        with exp_col2:
            json_data = filtered.to_json(orient="records", indent=2).encode("utf-8")
            st.download_button("⬇️ Download JSON", data=json_data,
                               file_name=f"corvus_{datetime.utcnow():%Y%m%d_%H%M%S}.json",
                               mime="application/json")
        with exp_col3:
            if st.button("🗑️ Clear all results", key="btn_clear_results"):
                for k in _RESULT_KEYS:
                    st.session_state[k] = []
                st.rerun()
