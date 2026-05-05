# recon-osint

OSINT and asset discovery toolkit for external attack-surface assessments.

## Tools

| Script | Purpose |
|--------|---------|
| `score_domains.py` | 0–100 composite risk score (CVSS + EPSS + exposure + sensitivity) |
| `classify_domains.py` | Industry/sector classification + revenue estimation |
| `domain_revenue.py` | Domain-to-company correlation via free web APIs |
| `mx_lookup.py` | MX record + email server enumeration |

## Quick Start

```bash
pip install requests
python score_domains.py -l targets.txt --out scored.csv
python classify_domains.py -l domains.txt
```

## Risk Scoring Model

Factors: CVSS base score · EPSS exploitation probability · Public PoC availability ·
Internet exposure (direct IP vs CDN) · Data sensitivity (PHI/PCI/PII indicators) · WAF presence

## Authorization

For authorized external assessments only.
