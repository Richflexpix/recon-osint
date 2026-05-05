"""
score_domains.py — Priority scoring and tier classification.

Reads triage_raw.json from a batch directory, scores each domain,
writes priority_list.md + triage_scores.json, and appends to the
master cumulative files.

Scoring rubric
--------------
+40  DB port open (unauthenticated accessible)
+30  Exposed .env / wp-config / credentials file
+25  CVSS 9.0+ CVE confirmed by nuclei
+20  SQLi confirmed
+15  phpMyAdmin / Adminer accessible
+10  WP users enumerated AND xmlrpc reachable
+10  Default admin creds work (from exploit phase)
+10  High-severity CVE confirmed (CVSS 7-9)
 -5  Cloudflare detected
-15  WAF detected (non-Cloudflare)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

CVSS_CRITICAL_RE = re.compile(r"9\.[0-9]|10\.0", re.IGNORECASE)
CVSS_HIGH_RE = re.compile(r"[78]\.[0-9]", re.IGNORECASE)


def _cvss_from_finding(f: dict) -> float:
    """Extract CVSS score from a nuclei finding dict."""
    for key in ("cvss_score", "cvss", "severity_score"):
        v = f.get(key)
        if v is not None:
            try:
                return float(v)
            except (ValueError, TypeError):
                pass
    # Derive from severity string
    sev = (f.get("severity") or f.get("info", {}).get("severity", "")).lower()
    return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.0}.get(sev, 0.0)


@dataclass
class ScoredDomain:
    domain: str
    score: int = 0
    tier: str = "HARD"
    reasons: list[str] = field(default_factory=list)
    open_db_ports: list[int] = field(default_factory=list)
    db_labels: list[str] = field(default_factory=list)
    sensitive_files: list[str] = field(default_factory=list)
    wp_users: list[str] = field(default_factory=list)
    admin_panels: list[str] = field(default_factory=list)
    nuclei_findings: list[dict] = field(default_factory=list)
    js_secrets_count: int = 0
    sqli_count: int = 0
    cms: str = ""
    server: str = ""
    waf: str = ""
    live: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


_DB_PORT_LABELS: dict[int, str] = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch-transport",
    1433: "MSSQL",
    5984: "CouchDB",
    8086: "InfluxDB",
    7474: "Neo4j",
}


def score_domain(triage: dict) -> ScoredDomain:
    domain = triage.get("domain", "")
    sd = ScoredDomain(domain=domain)

    if not triage.get("live"):
        sd.tier = "DEAD"
        return sd

    sd.live = True
    sd.cms = triage.get("cms", "")
    sd.server = triage.get("server_banner", "")
    sd.waf = triage.get("waf", "")
    sd.wp_users = triage.get("wp_users", [])
    sd.admin_panels = triage.get("admin_panels", [])
    sd.nuclei_findings = triage.get("nuclei_findings", [])
    sd.js_secrets_count = len(triage.get("js_secrets", []))
    sd.sqli_count = len(triage.get("sqli_findings", []))

    # DB ports
    open_ports: list[int] = triage.get("open_db_ports", [])
    sd.open_db_ports = open_ports
    sd.db_labels = [_DB_PORT_LABELS.get(p, str(p)) for p in open_ports]
    if open_ports:
        sd.score += 40
        sd.reasons.append(f"Open DB ports: {sd.db_labels}")

    # Sensitive files
    sf = triage.get("sensitive_files_found", [])
    sd.sensitive_files = sf
    if sf:
        sd.score += 30
        sd.reasons.append(f"Exposed sensitive files: {sf[:3]}")

    # Nuclei CVEs
    for f in sd.nuclei_findings:
        cvss = _cvss_from_finding(f)
        if cvss >= 9.0:
            sd.score += 25
            name = f.get("template_id") or f.get("name") or "CVE"
            sd.reasons.append(f"Critical CVE ({name}, CVSS {cvss})")
            break  # count once per tier
    for f in sd.nuclei_findings:
        cvss = _cvss_from_finding(f)
        if 7.0 <= cvss < 9.0:
            sd.score += 10
            sd.reasons.append(f"High CVE (CVSS {cvss})")
            break

    # SQLi
    if sd.sqli_count:
        sd.score += 20
        sd.reasons.append(f"SQLi confirmed ({sd.sqli_count} param(s))")

    # Admin panels (phpMyAdmin / Adminer)
    pma_panels = [p for p in sd.admin_panels if any(k in p for k in ["phpmyadmin", "adminer", "pma"])]
    if pma_panels:
        sd.score += 15
        sd.reasons.append(f"DB management panel: {pma_panels}")

    # WordPress users
    if sd.wp_users:
        sd.score += 10
        sd.reasons.append(f"WP users exposed: {sd.wp_users}")

    # JS secrets
    if sd.js_secrets_count:
        sd.score += min(sd.js_secrets_count * 5, 20)
        sd.reasons.append(f"JS secrets found: {sd.js_secrets_count}")

    # WAF / Cloudflare penalty
    waf_lower = sd.waf.lower()
    if "cloudflare" in waf_lower:
        sd.score -= 5
        sd.reasons.append("Cloudflare WAF (-5)")
    elif sd.waf:
        sd.score -= 15
        sd.reasons.append(f"WAF detected: {sd.waf} (-15)")

    # Tier assignment
    if sd.score >= 80:
        sd.tier = "EASY"
    elif sd.score >= 50:
        sd.tier = "EXPLOITABLE-HIGH"
    elif sd.score >= 20:
        sd.tier = "EXPLOITABLE"
    else:
        sd.tier = "HARD"

    return sd


# ---------------------------------------------------------------------------
# Batch scoring
# ---------------------------------------------------------------------------

def score_batch(batch_dir: str, batch_num: int) -> list[ScoredDomain]:
    raw_path = os.path.join(batch_dir, "triage_raw.json")
    if not os.path.exists(raw_path):
        print(f"[score] No triage_raw.json in {batch_dir}")
        return []

    with open(raw_path, encoding="utf-8") as fh:
        raw = json.load(fh)

    scored = [score_domain(t) for t in raw]
    scored.sort(key=lambda s: s.score, reverse=True)

    # Write scores JSON
    scores_path = os.path.join(batch_dir, "triage_scores.json")
    with open(scores_path, "w", encoding="utf-8") as fh:
        json.dump([s.to_dict() for s in scored], fh, indent=2)

    # Write priority markdown
    _write_priority_md(scored, batch_dir, batch_num)

    # Append to master files
    _update_master(scored, batch_num)

    easy = [s for s in scored if s.tier == "EASY"]
    exp = [s for s in scored if s.tier.startswith("EXPLOITABLE")]
    hard = [s for s in scored if s.tier == "HARD"]
    dead = [s for s in scored if s.tier == "DEAD"]
    print(f"[score] Batch {batch_num}: EASY={len(easy)} EXPLOITABLE={len(exp)} HARD={len(hard)} DEAD={len(dead)}")
    return scored


def _write_priority_md(scored: list[ScoredDomain], batch_dir: str, batch_num: int) -> None:
    lines = [f"# Batch {batch_num} Priority List\n", f"_Generated: {datetime.utcnow().isoformat()}Z_\n\n"]

    for tier_label, tier_filter in [
        ("## EASY (score ≥ 80) — Direct DB/cred access likely", lambda s: s.tier == "EASY"),
        ("## EXPLOITABLE-HIGH (score 50-79) — Strong vuln chain", lambda s: s.tier == "EXPLOITABLE-HIGH"),
        ("## EXPLOITABLE (score 20-49) — Viable with effort", lambda s: s.tier == "EXPLOITABLE"),
        ("## HARD (score < 20) — Significant barriers", lambda s: s.tier == "HARD"),
    ]:
        tier_domains = [s for s in scored if tier_filter(s)]
        lines.append(f"{tier_label}\n\n")
        if not tier_domains:
            lines.append("_None in this batch._\n\n")
            continue
        lines.append("| Domain | Score | DB Ports | Key Findings |\n")
        lines.append("|--------|-------|----------|--------------|\n")
        for s in tier_domains:
            db = ", ".join(s.db_labels) if s.db_labels else "-"
            reasons = "; ".join(s.reasons[:3]) if s.reasons else "-"
            lines.append(f"| {s.domain} | {s.score} | {db} | {reasons} |\n")
        lines.append("\n")

    md_path = os.path.join(batch_dir, "priority_list.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def _update_master(scored: list[ScoredDomain], batch_num: int) -> None:
    os.makedirs("results", exist_ok=True)

    # Master priority list (append section per batch)
    master_md = os.path.join("results", "MASTER_PRIORITY_LIST.md")
    easy = [s for s in scored if s.tier == "EASY"]
    exp_high = [s for s in scored if s.tier == "EXPLOITABLE-HIGH"]
    exp = [s for s in scored if s.tier == "EXPLOITABLE"]

    with open(master_md, "a", encoding="utf-8") as fh:
        fh.write(f"\n## Batch {batch_num:04d} ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC)\n\n")
        for tier_label, tier_list in [("EASY", easy), ("EXPLOITABLE-HIGH", exp_high), ("EXPLOITABLE", exp)]:
            if tier_list:
                fh.write(f"**{tier_label}**: ")
                fh.write(", ".join(f"`{s.domain}` ({s.score})" for s in tier_list))
                fh.write("\n")

    # Master credentials
    master_creds = os.path.join("results", "MASTER_CREDENTIALS.json")
    existing_creds: list[dict] = []
    if os.path.exists(master_creds):
        with open(master_creds, encoding="utf-8") as fh:
            try:
                existing_creds = json.load(fh)
            except json.JSONDecodeError:
                existing_creds = []

    for s in scored:
        for sf in s.sensitive_files:
            existing_creds.append({
                "batch": batch_num,
                "domain": s.domain,
                "type": "sensitive_file",
                "url": sf,
                "score": s.score,
            })
        if s.wp_users:
            existing_creds.append({
                "batch": batch_num,
                "domain": s.domain,
                "type": "wp_users",
                "users": s.wp_users,
                "score": s.score,
            })
        for secret in (s.js_secrets_count and [] or []):
            existing_creds.append({"batch": batch_num, "domain": s.domain, "type": "js_secret", **secret})

    with open(master_creds, "w", encoding="utf-8") as fh:
        json.dump(existing_creds, fh, indent=2)

    # Master DB access
    master_db = os.path.join("results", "MASTER_DB_ACCESS.json")
    existing_db: list[dict] = []
    if os.path.exists(master_db):
        with open(master_db, encoding="utf-8") as fh:
            try:
                existing_db = json.load(fh)
            except json.JSONDecodeError:
                existing_db = []

    for s in scored:
        if s.open_db_ports:
            existing_db.append({
                "batch": batch_num,
                "domain": s.domain,
                "ports": s.open_db_ports,
                "labels": s.db_labels,
                "score": s.score,
                "tier": s.tier,
            })

    with open(master_db, "w", encoding="utf-8") as fh:
        json.dump(existing_db, fh, indent=2)


if __name__ == "__main__":
    import sys
    batch_n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    batch_dir = os.path.join("results", f"batch_{batch_n:04d}")
    results = score_batch(batch_dir, batch_n)
    for s in results[:10]:
        print(f"  [{s.tier:18s}] {s.score:>3} {s.domain}")
