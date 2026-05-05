import argparse
import csv
import html
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


USER_AGENT = "recon2exploit-domain-revenue/1.0 (+https://example.invalid; offline script)"


def http_get(url: str, timeout_s: float) -> bytes | None:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.read()
    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, ValueError):
        return None


def sniff_site_name_from_html(page: bytes) -> str | None:
    # best-effort: extract <title> and og:site_name
    try:
        text = page.decode("utf-8", errors="ignore")
    except Exception:
        return None

    og = re.search(
        r'<meta\s+property=["\']og:site_name["\']\s+content=["\']([^"\']+)["\']',
        text,
        flags=re.IGNORECASE,
    )
    if og:
        return html.unescape(og.group(1)).strip() or None

    title = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if title:
        t = re.sub(r"\s+", " ", html.unescape(title.group(1))).strip()
        # strip common suffixes
        t = re.sub(r"\s*[\-|–|—]\s*Home\s*$", "", t, flags=re.IGNORECASE).strip()
        t = re.sub(r"\s*[\-|–|—]\s*Official Site\s*$", "", t, flags=re.IGNORECASE).strip()
        return t or None

    return None


def wikipedia_search_hits(query: str, timeout_s: float, limit: int = 5) -> list[dict]:
    params = {
        "action": "query",
        "list": "search",
        "srsearch": query,
        "format": "json",
        "utf8": "1",
        "srlimit": str(max(1, min(10, limit))),
    }
    url = "https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode(params)
    data = http_get(url, timeout_s=timeout_s)
    if not data:
        return []
    try:
        payload = json.loads(data.decode("utf-8", errors="ignore"))
        return payload.get("query", {}).get("search", []) or []
    except json.JSONDecodeError:
        return []


def _normalize_for_match(s: str) -> str:
    s = s.lower()
    s = re.sub(r"<[^>]+>", " ", s)  # strip html tags from snippets
    s = html.unescape(s)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def pick_best_wikipedia_title(domain: str, company_query: str, timeout_s: float) -> tuple[str | None, str]:
    """
    Return (title, status). This is intentionally conservative to avoid wrong matches.
    """
    domain_norm = _normalize_for_match(domain.replace("www.", ""))
    domain_token = domain_norm.replace(" ", "")
    cq_norm = _normalize_for_match(company_query)

    # Prefer searches that include the domain explicitly.
    queries = [
        f"\"{domain}\"",
        f"{company_query} {domain}",
        company_query,
    ]

    best = None
    best_score = -1
    best_has_domain = False
    tried_any = False

    for q in queries:
        hits = wikipedia_search_hits(q, timeout_s=timeout_s, limit=5)
        tried_any = tried_any or bool(hits)
        for h in hits:
            title = h.get("title") or ""
            snippet = h.get("snippet") or ""
            hay = _normalize_for_match(f"{title} {snippet}")

            score = 0
            has_domain = False
            if domain_token and domain_token in hay.replace(" ", ""):
                score += 10
                has_domain = True
            if domain_norm and domain_norm in hay:
                score += 8
                has_domain = True

            # Mild signal: company query terms present
            if cq_norm:
                cq_terms = [t for t in cq_norm.split(" ") if len(t) >= 4][:6]
                score += sum(1 for t in cq_terms if t in hay)

            # Penalize disambiguation-ish titles
            if "(disambiguation)" in title.lower():
                score -= 5

            if score > best_score:
                best_score = score
                best = title
                best_has_domain = has_domain

        # If we found a strong match using explicit domain query, stop early.
        if best_score >= 10:
            break

    if not tried_any:
        return None, "WIKIPEDIA_SEARCH_FAILED"
    if not best:
        return None, "NO_WIKIPEDIA_MATCH"

    # Be conservative: only accept when the domain appeared in snippet/title.
    if not best_has_domain:
        return None, "NO_CONFIDENT_WIKIPEDIA_MATCH"

    return best, "OK"


def wikipedia_wikitext(title: str, timeout_s: float) -> str | None:
    params = {
        "action": "query",
        "prop": "revisions",
        "rvprop": "content",
        "rvslots": "main",
        "titles": title,
        "format": "json",
        "utf8": "1",
        "formatversion": "2",
        "redirects": "1",
    }
    url = "https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode(params)
    data = http_get(url, timeout_s=timeout_s)
    if not data:
        return None
    try:
        payload = json.loads(data.decode("utf-8", errors="ignore"))
        pages = payload.get("query", {}).get("pages", [])
        if not pages or "missing" in pages[0]:
            return None
        revs = pages[0].get("revisions", [])
        if not revs:
            return None
        slots = revs[0].get("slots", {})
        main = slots.get("main", {})
        return main.get("content") or None
    except json.JSONDecodeError:
        return None


REVENUE_LINE = re.compile(r"^\s*\|\s*revenue\s*=\s*(.+?)\s*$", flags=re.IGNORECASE | re.MULTILINE)
REVENUE_YEAR = re.compile(r"\((?:FY\s*)?(\d{4})\)", flags=re.IGNORECASE)


def parse_revenue_from_wikitext(wikitext: str) -> tuple[str | None, str | None]:
    m = REVENUE_LINE.search(wikitext)
    if not m:
        return None, None

    raw = m.group(1).strip()
    if not raw or raw.startswith("|"):
        return None, None
    # cleanup common templates/refs crudely (still keep original meaning)
    raw = re.sub(r"<ref[^>]*>.*?</ref>", "", raw, flags=re.IGNORECASE | re.DOTALL).strip()
    raw = re.sub(r"\{\{cite[^}]+\}\}", "", raw, flags=re.IGNORECASE | re.DOTALL).strip()
    raw = re.sub(r"\{\{nowrap\|([^}]+)\}\}", r"\1", raw, flags=re.IGNORECASE).strip()
    raw = re.sub(r"\{\{[^}]+\}\}", "", raw, flags=re.IGNORECASE | re.DOTALL).strip()
    raw = raw.replace("}}", "").strip()
    raw = raw.replace("&nbsp;", " ")
    raw = re.sub(r"\s+", " ", raw).strip()

    y = None
    ym = REVENUE_YEAR.search(raw)
    if ym:
        y = ym.group(1)

    return raw or None, y


def domain_to_candidates(domain: str) -> list[str]:
    base = domain.strip()
    if not base:
        return []
    return [
        f"https://{base}/",
        f"http://{base}/",
    ]


def best_effort_company_query(domain: str, timeout_s: float) -> str:
    # 1) try homepage title/og:site_name
    for url in domain_to_candidates(domain):
        page = http_get(url, timeout_s=timeout_s)
        if not page:
            continue
        name = sniff_site_name_from_html(page)
        if name:
            return name

    # 2) fallback: domain without tld pieces
    left = domain.split(".")[0]
    return left.replace("-", " ").strip() or domain


def iter_domains(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]


def main() -> int:
    ap = argparse.ArgumentParser(description="Best-effort company revenue from free web sources (Wikipedia).")
    ap.add_argument("--domains", default="domains.txt", help="Path to domains.txt")
    ap.add_argument("--out", default="domain_revenue.csv", help="Output CSV path")
    ap.add_argument("--limit", type=int, default=0, help="Only process first N domains (0=all)")
    ap.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout seconds")
    ap.add_argument("--sleep", type=float, default=0.25, help="Sleep seconds between Wikipedia requests")
    args = ap.parse_args()

    domains = iter_domains(args.domains)
    if args.limit and args.limit > 0:
        domains = domains[: args.limit]

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "domain",
                "company_query",
                "wikipedia_title",
                "revenue_raw",
                "revenue_year",
                "source",
                "status",
            ],
        )
        w.writeheader()

        for i, domain in enumerate(domains, start=1):
            company_query = best_effort_company_query(domain, timeout_s=args.timeout)

            title, search_status = pick_best_wikipedia_title(domain, company_query, timeout_s=args.timeout)
            time.sleep(args.sleep)
            revenue_raw = None
            revenue_year = None
            status = search_status

            if title and status in ("OK",):
                wt = wikipedia_wikitext(title, timeout_s=args.timeout)
                time.sleep(args.sleep)
                if wt:
                    revenue_raw, revenue_year = parse_revenue_from_wikitext(wt)
                    status = "OK" if revenue_raw else "NO_REVENUE_FIELD"
                else:
                    status = "WIKIPEDIA_FETCH_FAILED"

            w.writerow(
                {
                    "domain": domain,
                    "company_query": company_query,
                    "wikipedia_title": title or "",
                    "revenue_raw": revenue_raw or "",
                    "revenue_year": revenue_year or "",
                    "source": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ', '_'))}" if title else "",
                    "status": status,
                }
            )

            if i % 50 == 0:
                print(f"processed {i}/{len(domains)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

