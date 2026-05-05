"""
classify_domains.py — Score all 3,835 domains from Dom/dom.txt into vulnerability tiers.

Scoring sources (in priority order):
  1. Existing latest.json results (fast, no network)
  2. Passive HTTP probes via Tor (for domains without reports)
  3. Shodan InternetDB (no API key, via Tor)

Tier thresholds:
  more_vulnerable  >= 50
  vulnerable       20-49
  less_vulnerable  < 20
"""
import os
import sys
import json
import socket
import time
import asyncio
import concurrent.futures
import re
from pathlib import Path
from typing import Any
from datetime import datetime

import requests

BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"
DOM_FILE = BASE_DIR / "Dom" / "dom.txt"
TIERS_DIR = BASE_DIR / "tiers"

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# Admin paths to probe
ADMIN_PATHS = [
    "/wp-login.php", "/wp-admin/", "/admin/", "/admin", "/administrator/",
    "/phpmyadmin/", "/phpmyadmin", "/pma/", "/db/", "/webmail/",
    "/cpanel/", "/cPanel/", "/panel/", "/login/", "/login",
    "/admin/login", "/backend/", "/manage/", "/cms/",
]

# Sensitive file paths
SENSITIVE_PATHS = [
    "/.env", "/config.php", "/wp-config.php", "/wp-config.php.bak",
    "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    "/.git/config", "/.git/HEAD", "/config.json", "/secrets.json",
    "/appsettings.json", "/phpinfo.php", "/.htpasswd",
]

WAF_SIGNATURES = [
    "cloudflare", "cf-ray", "cf-cache-status", "akamai", "akamaighost",
    "x-sucuri-id", "x-cache-suricuri", "incapsula", "x-iinfo",
    "x-cdn", "fastly", "x-served-by", "imperva", "barracuda",
]

DB_PORTS = [3306, 5432, 27017, 6379, 1433, 9200, 11211]

HEADERS_SESSION_TIMEOUT = 8
MAX_WORKERS = 30  # concurrent passive probes


# ──────────────────────────────────────────────────────────────────────
# Scoring from existing latest.json
# ──────────────────────────────────────────────────────────────────────

def score_from_report(domain: str, data: dict) -> tuple[int, list[str]]:
    """Score a domain from its existing latest.json data."""
    score = 0
    evidence = []

    # Web vulnerabilities dict
    wv = data.get("web_vulnerabilities", {})
    if isinstance(wv, dict):
        sqli = wv.get("sqli_findings", [])
        if isinstance(sqli, list) and sqli:
            score += 15
            evidence.append(f"SQLi findings: {len(sqli)}")

        xss = wv.get("xss_findings", [])
        if isinstance(xss, list) and xss:
            score += 8
            evidence.append(f"XSS findings: {len(xss)}")

        sensitive = wv.get("sensitive_files", [])
        if isinstance(sensitive, list):
            accessible = [f for f in sensitive if "200" in str(f.get("evidence", ""))]
            if accessible:
                score += 10
                evidence.append(f"Accessible sensitive files: {len(accessible)}")
            elif sensitive:
                score += 3
                evidence.append(f"Sensitive paths (403): {len(sensitive)}")

        headers = wv.get("security_headers", {})
        if isinstance(headers, dict):
            missing = [h for h, v in headers.items() if not v]
            if len(missing) >= 3:
                score += 5
                evidence.append(f"Missing headers: {', '.join(missing[:3])}")

        ssrf = wv.get("ssrf_findings", [])
        if isinstance(ssrf, list) and ssrf:
            score += 5
            evidence.append(f"SSRF findings: {len(ssrf)}")

    # Services — check for DB ports and WAF
    services = data.get("services_detail", [])
    waf_detected = False
    db_ports_found = []
    for svc in services:
        tech_str = " ".join(str(t).lower() for t in svc.get("technologies", []))
        svc_name = str(svc.get("service_name", "")).lower()
        port = svc.get("port", 0)

        for waf_sig in WAF_SIGNATURES:
            if waf_sig in tech_str or waf_sig in svc_name:
                waf_detected = True
                break

        if port in DB_PORTS:
            db_ports_found.append(port)

    if waf_detected:
        score -= 30
        evidence.append("WAF/CDN detected")
    else:
        score += 25
        evidence.append("No WAF detected")

    if db_ports_found:
        score += 20
        evidence.append(f"DB ports open: {db_ports_found}")

    # Attack surface
    atk = data.get("attack_surface", {})
    if isinstance(atk, dict):
        risk = atk.get("risk_score", 0)
        if risk and risk > 0:
            score += min(int(risk / 4), 10)
            evidence.append(f"Attack surface risk: {risk}")

    # Domain recon — tech stack
    domain_recon = data.get("domain_recon", {})
    if isinstance(domain_recon, dict):
        cms = str(domain_recon.get("cms", "")).lower()
        if cms and cms not in ("unknown", "none", ""):
            score += 5
            evidence.append(f"CMS: {cms}")

    # Directories discovered
    dirs = data.get("directories_discovered", [])
    if isinstance(dirs, list) and len(dirs) > 10:
        score += 5
        evidence.append(f"Directories found: {len(dirs)}")

    # Priority evidence / exploits
    pe = data.get("priority_evidence", [])
    if isinstance(pe, list) and pe:
        score += 10
        evidence.append(f"Priority evidence items: {len(pe)}")

    return max(0, score), evidence


# ──────────────────────────────────────────────────────────────────────
# Passive HTTP probing (for domains without reports)
# ──────────────────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    s = requests.Session()
    s.proxies = TOR_PROXIES
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (compatible; SecurityAudit/1.0)"
    return s


def resolve_domain(domain: str) -> str | None:
    """DNS A record lookup."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def http_probe(session: requests.Session, domain: str) -> dict:
    """Quick HTTP HEAD probe — grab headers, status, check admin/sensitive paths."""
    result = {
        "resolved": False,
        "ip": None,
        "waf_detected": False,
        "waf_name": None,
        "admin_panels": [],
        "sensitive_accessible": [],
        "technologies": [],
        "status_code": None,
        "server": None,
        "cms": None,
    }

    ip = resolve_domain(domain)
    if not ip:
        return result
    result["resolved"] = True
    result["ip"] = ip

    base_url = f"https://{domain}"
    try:
        resp = session.head(base_url, timeout=HEADERS_SESSION_TIMEOUT, allow_redirects=True)
        result["status_code"] = resp.status_code
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        # WAF detection
        for waf_sig in WAF_SIGNATURES:
            if any(waf_sig in k or waf_sig in v for k, v in headers_lower.items()):
                result["waf_detected"] = True
                result["waf_name"] = waf_sig
                break

        # Server header
        result["server"] = headers_lower.get("server", "")

        # Technology hints
        powered = headers_lower.get("x-powered-by", "")
        if powered:
            result["technologies"].append(powered)

        # Cloudflare specific
        if "cf-ray" in headers_lower or "cloudflare" in result.get("server", ""):
            result["waf_detected"] = True
            result["waf_name"] = "cloudflare"

    except Exception:
        # Try HTTP fallback
        try:
            base_url = f"http://{domain}"
            resp = session.head(base_url, timeout=HEADERS_SESSION_TIMEOUT, allow_redirects=True)
            result["status_code"] = resp.status_code
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            for waf_sig in WAF_SIGNATURES:
                if any(waf_sig in k or waf_sig in v for k, v in headers_lower.items()):
                    result["waf_detected"] = True
                    result["waf_name"] = waf_sig
                    break
        except Exception:
            return result

    # Probe admin paths (sample — check top 5 to keep fast)
    for path in ADMIN_PATHS[:6]:
        try:
            r = session.get(f"https://{domain}{path}", timeout=HEADERS_SESSION_TIMEOUT,
                           allow_redirects=False)
            if r.status_code in (200, 301, 302) and len(r.content) > 200:
                result["admin_panels"].append({"path": path, "status": r.status_code})
        except Exception:
            pass

    # Probe 3 sensitive paths
    for path in SENSITIVE_PATHS[:4]:
        try:
            r = session.get(f"https://{domain}{path}", timeout=HEADERS_SESSION_TIMEOUT,
                           allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 50:
                result["sensitive_accessible"].append({"path": path, "status": 200, "size": len(r.content)})
        except Exception:
            pass

    return result


def check_shodan_internetdb(ip: str, session: requests.Session) -> dict:
    """Query Shodan InternetDB (no API key) for open ports and vulns."""
    try:
        r = session.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def score_from_probe(probe: dict, shodan: dict) -> tuple[int, list[str]]:
    """Score a domain from passive HTTP probe and Shodan data."""
    score = 0
    evidence = []

    if not probe.get("resolved"):
        return 0, ["DNS resolution failed"]

    if probe.get("waf_detected"):
        score -= 30
        evidence.append(f"WAF detected: {probe.get('waf_name', 'unknown')}")
    else:
        score += 25
        evidence.append("No WAF detected")

    if probe.get("admin_panels"):
        score += 20
        for ap in probe["admin_panels"]:
            evidence.append(f"Admin panel accessible: {ap['path']} ({ap['status']})")

    if probe.get("sensitive_accessible"):
        score += 10
        for sf in probe["sensitive_accessible"]:
            evidence.append(f"Sensitive file accessible: {sf['path']} ({sf['size']} bytes)")

    # Shodan ports
    ports = shodan.get("ports", [])
    db_found = [p for p in ports if p in DB_PORTS]
    if db_found:
        score += 20
        evidence.append(f"DB ports (Shodan): {db_found}")

    # Shodan vulns
    vulns = shodan.get("vulns", [])
    if vulns:
        score += min(len(vulns) * 5, 15)
        evidence.append(f"Shodan CVEs: {vulns[:3]}")

    # Tags indicating exposure
    tags = shodan.get("tags", [])
    for tag in ["self-signed", "eol-product", "default-login"]:
        if tag in tags:
            score += 5
            evidence.append(f"Shodan tag: {tag}")

    server = probe.get("server", "")
    if server and any(x in server.lower() for x in ["apache", "nginx", "iis", "php"]):
        evidence.append(f"Server: {server}")

    return max(0, score), evidence


# ──────────────────────────────────────────────────────────────────────
# Main classification logic
# ──────────────────────────────────────────────────────────────────────

def classify_all(use_tor: bool = True) -> list[dict]:
    domains = [l.strip() for l in DOM_FILE.read_text().splitlines() if l.strip()]
    print(f"[*] {len(domains)} domains to classify")

    # Load existing reports
    existing: dict[str, dict] = {}
    for domain in domains:
        lf = RESULTS_DIR / domain / "latest.json"
        if lf.exists():
            try:
                existing[domain] = json.loads(lf.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    print(f"[*] {len(existing)} domains have existing reports")

    results = []
    no_report = [d for d in domains if d not in existing]

    # --- Score domains with existing reports (fast, no network) ---
    print(f"[*] Scoring {len(existing)} domains from existing reports ...")
    for domain, data in existing.items():
        score, evidence = score_from_report(domain, data)
        results.append({
            "domain": domain,
            "score": score,
            "evidence": evidence,
            "source": "existing_report",
            "tier": tier_name(score),
        })

    # --- Passive probe remaining domains (via Tor) ---
    print(f"[*] Probing {len(no_report)} domains passively (via Tor, {MAX_WORKERS} workers) ...")
    session = make_session() if use_tor else requests.Session()

    def probe_domain(domain: str) -> dict:
        try:
            probe = http_probe(session, domain)
            ip = probe.get("ip")
            shodan = check_shodan_internetdb(ip, session) if ip else {}
            score, evidence = score_from_probe(probe, shodan)
            return {
                "domain": domain,
                "score": score,
                "evidence": evidence,
                "source": "passive_probe",
                "tier": tier_name(score),
                "probe": probe,
                "shodan": shodan,
            }
        except Exception as exc:
            return {
                "domain": domain,
                "score": 0,
                "evidence": [f"probe_error: {exc}"],
                "source": "passive_probe",
                "tier": "less_vulnerable",
            }

    completed = 0
    total = len(no_report)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(probe_domain, d): d for d in no_report}
        for fut in concurrent.futures.as_completed(futs):
            completed += 1
            if completed % 100 == 0 or completed == total:
                print(f"    Progress: {completed}/{total}", flush=True)
            results.append(fut.result())

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def tier_name(score: int) -> str:
    if score >= 50:
        return "more_vulnerable"
    if score >= 20:
        return "vulnerable"
    return "less_vulnerable"


def write_outputs(results: list[dict]) -> None:
    TIERS_DIR.mkdir(exist_ok=True)

    more_v = [r for r in results if r["tier"] == "more_vulnerable"]
    vuln = [r for r in results if r["tier"] == "vulnerable"]
    less_v = [r for r in results if r["tier"] == "less_vulnerable"]

    (TIERS_DIR / "more_vulnerable.txt").write_text(
        "\n".join(r["domain"] for r in more_v), encoding="utf-8"
    )
    (TIERS_DIR / "vulnerable.txt").write_text(
        "\n".join(r["domain"] for r in vuln), encoding="utf-8"
    )
    (TIERS_DIR / "less_vulnerable.txt").write_text(
        "\n".join(r["domain"] for r in less_v), encoding="utf-8"
    )

    # Full classification report
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total": len(results),
        "tier_counts": {
            "more_vulnerable": len(more_v),
            "vulnerable": len(vuln),
            "less_vulnerable": len(less_v),
        },
        "domains": results,
    }
    (TIERS_DIR / "classification_report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    print("\n" + "=" * 60)
    print(f"  Classification Complete")
    print("=" * 60)
    print(f"  More Vulnerable  (score >= 50): {len(more_v):>5}")
    print(f"  Vulnerable       (score 20-49): {len(vuln):>5}")
    print(f"  Less Vulnerable  (score  < 20): {len(less_v):>5}")
    print(f"  Total:                         {len(results):>5}")
    print()
    print("  Top 25 most vulnerable:")
    print(f"  {'Domain':<45} {'Score':>6}  Evidence")
    print("  " + "-" * 80)
    for r in results[:25]:
        ev_short = "; ".join(r["evidence"][:2])
        print(f"  {r['domain']:<45} {r['score']:>6}  {ev_short}")
    print()
    print(f"  Output: {TIERS_DIR}/")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # Check Tor availability
    use_tor = True
    try:
        import socket as _s
        _s.create_connection(("127.0.0.1", 9050), timeout=2).close()
        print("[+] Tor SOCKS proxy detected on :9050")
    except OSError:
        print("[!] Tor not running on :9050 — probing directly (no anonymization)")
        use_tor = False

    results = classify_all(use_tor=use_tor)
    write_outputs(results)
    print("\n[*] Next step: python exploit_top20.py")
