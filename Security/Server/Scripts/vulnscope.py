#!/usr/bin/env python3
"""
VulnScope — Vulnerability Intelligence Tool
============================================
Gathers everything known about a technology's security posture:
  • Technology fingerprint  (what it is, what it does, latest version)
  • CVE inventory           (NVD, date-filtered, severity-sorted)
  • Public exploits         (Exploit-DB via searchsploit + Sploitus API)
  • GitHub PoC repos        (per-CVE, star-sorted)
  • Google Dork harvest     (targeted dorks across 6 security databases)
  • EPSS scores             (exploitation probability from FIRST.org)
  • HTML + JSON reports     (open in browser, or pipe JSON into other tools)

Quick start:
    python vulnscope.py nginx
    python vulnscope.py "apache struts" -v 2.5.33
    python vulnscope.py plesk -v 0.9 --year-from 2020
    python vulnscope.py wordpress --top 30 --github-token ghp_xxx
    python vulnscope.py openssh --skip-dorks --json-only
"""

from __future__ import annotations

import argparse
import csv
import html as html_lib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, RetryError

try:
    from ddgs import DDGS
    _HAS_DDG = True
except ImportError:
    try:
        from duckduckgo_search import DDGS
        _HAS_DDG = True
    except ImportError:
        DDGS = None
        _HAS_DDG = False

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("VulnScope")


# ─────────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────────
@dataclass
class TechProfile:
    name: str
    version: str
    description: str = ""
    vendor: str = ""
    category: str = ""
    latest_version: str = ""
    homepage: str = ""
    cpe: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CVERecord:
    cve_id: str
    published: str
    modified: str
    description: str
    cvss_v3: float
    cvss_v2: float
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    vector: str
    cwe: str
    references: list[str] = field(default_factory=list)
    pocs: list[dict] = field(default_factory=list)   # {url, stars, author}
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    exploitdb_ids: list[str] = field(default_factory=list)


@dataclass
class ExploitRecord:
    title: str
    source: str
    link: str
    exploit_type: str
    platform: str = ""
    date: str = ""


@dataclass
class DorkResult:
    dork: str
    category: str
    url: str


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "VulnScope/2.0 (security-research; contact@example.com)"
})

# Optional NVD API key (can be provided via env NVD_API_KEY or CLI)
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

_GOOGLE_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

def sanitize(name: str) -> str:
    return re.sub(r'[\\/*?:"<>|\s]', "_", name)

def severity_from_score(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"

def _get(url: str, *, timeout: int = 15, **kwargs) -> requests.Response:
    """Thin wrapper — retries on transient errors."""
    return SESSION.get(url, timeout=timeout, **kwargs)


# ─────────────────────────────────────────────
#  PHASE 0 — TECHNOLOGY PROFILE
# ─────────────────────────────────────────────
def build_tech_profile(technology: str, version: str) -> TechProfile:
    """
    Pull a short description + metadata from multiple sources:
      1. DuckDuckGo Instant Answer API  (fast, no scraping)
      2. Wikipedia REST summary API
      3. Wikidata simple query for CPE / vendor
    Falls back to a bare-minimum profile if everything fails.
    """
    log.info(f"Building technology profile for '{technology}'...")
    profile = TechProfile(name=technology, version=version)

    # ── DuckDuckGo Instant Answer ─────────────────────────────────────────
    try:
        r = _get(
            "https://api.duckduckgo.com/",
            params={"q": technology, "format": "json", "no_html": "1", "skip_disambig": "1"},
        )
        d = r.json()
        abstract = d.get("Abstract", "").strip()
        if abstract:
            profile.description = abstract
        if d.get("AbstractURL"):
            profile.homepage = d["AbstractURL"]
        # Entity type
        itype = d.get("Type", "")
        if itype == "A":
            profile.category = "Article / Software"
        # Related topics → tags
        for t in d.get("RelatedTopics", [])[:6]:
            if isinstance(t, dict) and t.get("Text"):
                words = t["Text"].split()[:4]
                profile.tags.append(" ".join(words))
    except Exception as e:
        log.debug(f"DDG instant answer failed: {e}")

    # ── Wikipedia REST ────────────────────────────────────────────────────
    if not profile.description:
        try:
            slug = technology.replace(" ", "_")
            r = _get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote_plus(slug)}")
            if r.status_code == 200:
                w = r.json()
                profile.description = w.get("extract", "")[:500]
                if not profile.homepage:
                    profile.homepage = w.get("content_urls", {}).get("desktop", {}).get("page", "")
                profile.category = w.get("type", "").replace("-", " ").title()
        except Exception as e:
            log.debug(f"Wikipedia lookup failed: {e}")

    # ── CPE guess (NVD CPE match) ─────────────────────────────────────────
    try:
        r = _get(
            "https://services.nvd.nist.gov/rest/json/cpes/2.0",
            params={"keywordSearch": technology, "resultsPerPage": 1},
        )
        if r.status_code == 200:
            items = r.json().get("products", [])
            if items:
                cpe_name = items[0].get("cpe", {}).get("cpeName", "")
                profile.cpe = cpe_name
                # cpeName: cpe:2.3:a:vendor:product:version:…
                parts = cpe_name.split(":")
                if len(parts) > 4:
                    profile.vendor = parts[3].replace("_", " ").title()
                if len(parts) > 5 and parts[5] not in ("*", "-", ""):
                    profile.latest_version = parts[5]
    except Exception as e:
        log.debug(f"CPE lookup failed: {e}")

    log.info(f"  Profile ready — vendor: '{profile.vendor}' | cpe: '{profile.cpe}'")
    return profile


# ─────────────────────────────────────────────
#  PHASE 1 — NVD CVE FETCH
# ─────────────────────────────────────────────
@retry(
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=6, max=30),
    retry=retry_if_exception_type(requests.HTTPError),
)
def _nvd_page(params: dict) -> dict:
    # Attach API key header when available to increase rate limits
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
    if r.status_code == 403:
        log.warning("NVD rate-limit (403). Sleeping 15 s…")
        time.sleep(15)
        r.raise_for_status()
    r.raise_for_status()
    return r.json()


def fetch_cves(
    technology: str,
    version: str,
    year_from: int,
    year_to: int,
    max_cves: int,
    profile: TechProfile,
) -> list[CVERecord]:
    """Fetch CVEs from NVD, sorted by CVSS score descending."""
    log.info(f"Fetching CVEs from NVD ({year_from}–{year_to}, max {max_cves})…")

    # Build the most specific search term we can
    search_term = technology
    if version:
        search_term = f"{technology} {version}"
    elif profile.cpe:
        # Use CPE vendor:product for better NVD matching
        parts = profile.cpe.split(":")
        if len(parts) > 5:
            search_term = f"{parts[3]} {parts[4]}".replace("_", " ")

    start_date = f"{year_from}-01-01T00:00:00.000"
    end_date   = f"{year_to}-12-31T23:59:59.999"
    page_size  = 20
    start_idx  = 0
    raw: list[dict] = []

    while len(raw) < max_cves:
        params = {
            "keywordSearch":  search_term,
            "pubStartDate":   start_date,
            "pubEndDate":     end_date,
            "resultsPerPage": page_size,
            "startIndex":     start_idx,
        }
        try:
            data  = _nvd_page(params)
            batch = data.get("vulnerabilities", [])
            if not batch:
                break
            raw.extend(batch)
            start_idx += page_size
            total = data.get("totalResults", 0)
            log.info(f"  NVD: fetched {len(raw)}/{min(total, max_cves)} CVEs…")
            if start_idx >= total or len(raw) >= max_cves:
                break
            time.sleep(6)   # NVD rate limit: 5 req/30 s without API key
        except RetryError as e:
            log.error("NVD fetch error: retry attempts exhausted (possible rate limit or network error).")
            log.debug(f"NVD RetryError: {e}")
            break
        except Exception as e:
            log.error(f"NVD fetch error: {e}")
            break

    raw = raw[:max_cves]
    records: list[CVERecord] = []

    for item in raw:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        # Description (prefer English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS scores
        v3_score = 0.0
        v3_vector = ""
        v2_score = 0.0
        metrics = cve.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            mlist = metrics.get(key, [])
            if mlist:
                cv = mlist[0].get("cvssData", {})
                v3_score  = float(cv.get("baseScore", 0))
                v3_vector = cv.get("vectorString", "")
                break

        for key in ("cvssMetricV2",):
            mlist = metrics.get(key, [])
            if mlist:
                cv = mlist[0].get("cvssData", {})
                v2_score = float(cv.get("baseScore", 0))
                break

        score = v3_score if v3_score else v2_score

        # CWE
        cwe = ""
        for w in cve.get("weaknesses", []):
            for wd in w.get("description", []):
                if wd.get("lang") == "en":
                    cwe = wd.get("value", "")
                    break
            if cwe:
                break

        # References
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        records.append(CVERecord(
            cve_id=cve_id,
            published=cve.get("published", ""),
            modified=cve.get("lastModified", ""),
            description=desc,
            cvss_v3=v3_score,
            cvss_v2=v2_score,
            severity=severity_from_score(score),
            vector=v3_vector,
            cwe=cwe,
            references=refs[:8],
        ))

    # Sort: severity first, then date
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    records.sort(key=lambda r: (sev_order.get(r.severity, 5), r.published), reverse=False)
    records.sort(key=lambda r: sev_order.get(r.severity, 5))

    log.info(f"  {len(records)} CVEs parsed. Critical: {sum(1 for r in records if r.severity=='CRITICAL')}, High: {sum(1 for r in records if r.severity=='HIGH')}")
    return records


# ─────────────────────────────────────────────
#  PHASE 2 — EPSS SCORES (FIRST.org)
# ─────────────────────────────────────────────
def enrich_epss(cves: list[CVERecord]) -> None:
    """
    EPSS = Exploit Prediction Scoring System.
    Fetches exploitation probability (0–1) for each CVE from FIRST.org.
    Batched in groups of 30 to stay well within rate limits.
    """
    if not cves:
        return
    log.info("Fetching EPSS scores from FIRST.org…")
    ids = [c.cve_id for c in cves]
    id_map = {c.cve_id: c for c in cves}
    batch_size = 30

    for i in range(0, len(ids), batch_size):
        batch = ids[i:i + batch_size]
        params = {"cve": ",".join(batch), "scope": "time-series"}
        try:
            r = _get("https://api.first.org/data/v1/epss", params=params, timeout=20)
            if r.status_code != 200:
                continue
            for item in r.json().get("data", []):
                cid = item.get("cve")
                if cid in id_map:
                    id_map[cid].epss_score      = float(item.get("epss", 0))
                    id_map[cid].epss_percentile = float(item.get("percentile", 0))
        except Exception as e:
            log.debug(f"EPSS batch failed: {e}")
        time.sleep(1)
    scored = sum(1 for c in cves if c.epss_score > 0)
    log.info(f"  EPSS: {scored}/{len(cves)} CVEs scored")


# ─────────────────────────────────────────────
#  PHASE 3 — GITHUB PoC SEARCH
# ─────────────────────────────────────────────
def search_github_pocs(cve_id: str, token: str = "") -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    query = f"{cve_id} poc exploit"
    url   = f"https://api.github.com/search/repositories?q={quote_plus(query)}&sort=stars&order=desc&per_page=5"
    try:
        r = SESSION.get(url, headers=headers, timeout=12)
        if r.status_code == 403:
            log.warning(f"GitHub rate limit for {cve_id}. Skipping PoC search.")
            return []
        r.raise_for_status()
        pocs = []
        for repo in r.json().get("items", [])[:5]:
            pocs.append({
                "url":    repo.get("html_url", ""),
                "author": repo.get("owner", {}).get("login", ""),
                "stars":  repo.get("stargazers_count", 0),
                "desc":   repo.get("description", "") or "",
            })
        return pocs
    except Exception as e:
        log.debug(f"GitHub PoC search failed for {cve_id}: {e}")
        return []


def enrich_pocs(cves: list[CVERecord], token: str = "") -> None:
    """Attach GitHub PoC repos to each CVE record. Only searches HIGH+ severity."""
    log.info("Searching GitHub for PoC repositories…")
    targets = [c for c in cves if c.severity in ("CRITICAL", "HIGH")]
    log.info(f"  Searching PoCs for {len(targets)} CRITICAL/HIGH CVEs…")
    for cve in targets:
        pocs = search_github_pocs(cve.cve_id, token)
        if pocs:
            cve.pocs = pocs
            log.info(f"  {cve.cve_id}: {len(pocs)} PoC(s) found (top stars: {pocs[0]['stars']})")
        time.sleep(1.2)   # GitHub: 10 req/min unauthenticated


# ─────────────────────────────────────────────
#  PHASE 4 — SPLOITUS
# ─────────────────────────────────────────────
@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
def fetch_sploitus(technology: str, version: str = "") -> list[ExploitRecord]:
    q = f"{technology} {version}".strip() if version else technology
    url = f"https://sploitus.com/search#exploits"   # actual API below
    api = f"https://sploitus.com/search?q={quote_plus(q)}&type=exploits&sort=default&title=false"
    headers = {"Accept": "application/json", "Referer": "https://sploitus.com/"}
    r = SESSION.get(api, headers=headers, timeout=15)
    r.raise_for_status()
    out = []
    for item in r.json().get("exploits", []):
        out.append(ExploitRecord(
            title=item.get("title", ""),
            source=item.get("source", ""),
            link=item.get("href", "") or item.get("vhref", ""),
            exploit_type=item.get("type", ""),
            date=item.get("published", ""),
        ))
    return out


def run_sploitus(technology: str, version: str) -> list[ExploitRecord]:
    log.info("Querying Sploitus aggregated exploit database…")
    try:
        results = fetch_sploitus(technology, version)
        log.info(f"  Sploitus: {len(results)} exploits found")
        return results
    except RetryError as e:
        log.warning("Sploitus query failed: retry attempts exhausted (possible rate limit or network error).")
        log.debug(f"Sploitus RetryError: {e}")
        return []
    except Exception as e:
        log.warning(f"Sploitus query failed: {e}")
        return []


# ─────────────────────────────────────────────
#  PHASE 5 — SEARCHSPLOIT (local Exploit-DB)
# ─────────────────────────────────────────────
def run_searchsploit(technology: str, version: str) -> list[ExploitRecord]:
    if not shutil.which("searchsploit"):
        log.warning("searchsploit not found. Install: sudo apt install exploitdb")
        return []
    q = f"{technology} {version}".strip() if version else technology
    log.info(f"Running searchsploit for '{q}'…")
    try:
        r = subprocess.run(
            ["searchsploit", "--json", q],
            capture_output=True, text=True, timeout=30, check=False,
        )
        data = json.loads(r.stdout)
        results = []
        for e in data.get("RESULTS_EXPLOIT", []):
            results.append(ExploitRecord(
                title=e.get("Title", ""),
                source="Exploit-DB (local)",
                link=f"https://www.exploit-db.com/exploits/{e.get('EDB-ID','')}",
                exploit_type=e.get("Type", ""),
                platform=e.get("Platform", ""),
                date=e.get("Date", ""),
            ))
        log.info(f"  searchsploit: {len(results)} exploits")
        return results
    except json.JSONDecodeError:
        # Fallback: parse plain text output
        r2 = subprocess.run(
            ["searchsploit", q],
            capture_output=True, text=True, timeout=30, check=False,
        )
        results = []
        for line in r2.stdout.splitlines():
            if "|" in line and "Title" not in line and "---" not in line and line.strip():
                parts = line.split("|")
                if len(parts) >= 2:
                    results.append(ExploitRecord(
                        title=parts[0].strip(),
                        source="Exploit-DB (local)",
                        link=parts[1].strip(),
                        exploit_type="",
                    ))
        log.info(f"  searchsploit (text parse): {len(results)} exploits")
        return results
    except Exception as e:
        log.error(f"searchsploit error: {e}")
        return []


# ─────────────────────────────────────────────
#  PHASE 6 — GOOGLE DORK HARVEST
# ─────────────────────────────────────────────
DORK_CATALOG: list[tuple[str, str]] = [
    # (category, dork_template)
    ("CVE Database",    'site:cve.mitre.org "{q}"'),
    ("NVD",             'site:nvd.nist.gov "{q}" vulnerability'),
    ("Exploit-DB",      'site:exploit-db.com "{q}"'),
    ("Packet Storm",    'site:packetstormsecurity.com "{q}"'),
    ("GitHub PoC",      'site:github.com "{q}" CVE poc exploit'),
    ("GitHub Advisory", 'site:github.com/advisories "{q}"'),
    ("Snyk",            'site:security.snyk.io/vuln "{q}"'),
    ("Huntr",           'site:huntr.dev "{q}"'),
    ("VulDB",           'site:vuldb.com "{q}"'),
    ("Rapid7 DB",       'site:rapid7.com/db "{q}"'),
    ("Offensive Sec",   'site:offensive-security.com "{q}"'),
    ("Security Focus",  'site:securityfocus.com "{q}"'),
    ("CVE Details",     'site:cvedetails.com "{q}"'),
    ("PoC Scripts",     '"{q}" exploit filetype:py OR filetype:rb OR filetype:sh'),
    ("RCE/SQLi",        '"{q}" "remote code execution" OR "SQL injection" CVE'),
    ("Advisories",      'inurl:advisory "{q}" vulnerability 2023 OR 2024 OR 2025'),
    ("Metasploit",      'site:github.com metasploit "{q}" module'),
    ("Nuclei Templates", 'site:github.com nuclei-templates "{q}"'),
]


def _google_fetch(dork: str, n: int = 10) -> list[str]:
    """Scrape one Google result page for URLs. Returns [] on block/CAPTCHA."""
    url = f"https://www.google.com/search?q={quote_plus(dork)}&num={n}&hl=en&gl=us"
    headers = {
        "User-Agent": random.choice(_GOOGLE_UAS),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "DNT": "1",
    }
    try:
        r = requests.get(url, headers=headers, timeout=14)
        if r.status_code == 429:
            log.warning("  Google 429 — rate limited")
            return []
        if r.status_code != 200:
            return []
        txt = r.text.lower()
        if "unusual traffic" in txt or "captcha" in txt or "recaptcha" in txt:
            log.warning("  Google CAPTCHA detected")
            return []
        found = re.findall(r'/url\?q=(https?://[^&"]+)', r.text)
        skip = {"google.com", "youtube.com", "webcache", "googleusercontent"}
        return list(dict.fromkeys(
            u for u in found if not any(s in u for s in skip)
        ))
    except Exception:
        return []


def _ddg_search(q: str, n: int = 8) -> list[str]:
    try:
        with DDGS() as d:
            results = list(d.text(q, max_results=n))
        return [r["href"] for r in results if r.get("href")]
    except Exception:
        return []


def run_dorks(technology: str, version: str, delay: float = 3.5) -> list[DorkResult]:
    """Run all dork templates, fall back to DDG on Google block."""
    q = f"{technology} {version}".strip() if version else technology
    log.info(f"Running {len(DORK_CATALOG)} Google dorks for '{q}'…")
    results: list[DorkResult] = []
    seen_urls: set[str] = set()
    google_ok = True

    for category, template in DORK_CATALOG:
        dork = template.replace("{q}", q)
        urls = []

        if google_ok:
            urls = _google_fetch(dork, n=8)
            if not urls and not results:  # first dork already empty → assume block
                log.info("  Google appears blocked — switching to DuckDuckGo")
                google_ok = False

        if not urls:
            urls = _ddg_search(dork, n=6)

        new = [u for u in urls if u not in seen_urls]
        seen_urls.update(new)
        for u in new:
            results.append(DorkResult(dork=dork, category=category, url=u))

        log.info(f"  [{category}] +{len(new)} URLs (total: {len(results)})")
        time.sleep(delay + random.uniform(0, 1.2))

    log.info(f"  Dork harvest complete: {len(results)} unique URLs")
    return results


# ─────────────────────────────────────────────
#  HTML REPORT
# ─────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#34c759",
    "NONE":     "#636366",
}

def _severity_badge(sev: str) -> str:
    col = SEV_COLOR.get(sev, "#636366")
    return f'<span class="badge" style="background:{col}">{sev}</span>'

def _epss_bar(score: float) -> str:
    pct = round(score * 100, 1)
    col = "#ff2d55" if pct > 50 else "#ff6b35" if pct > 20 else "#ffd60a" if pct > 5 else "#34c759"
    return (
        f'<div class="epss-wrap" title="EPSS: {pct}% exploitation probability">'
        f'<div class="epss-bar" style="width:{min(pct,100)}%;background:{col}"></div>'
        f'<span class="epss-label">{pct}%</span></div>'
    )

def generate_html(
    profile: TechProfile,
    cves: list[CVERecord],
    exploits: list[ExploitRecord],
    dorks: list[DorkResult],
    output_path: Path,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tech_display = html_lib.escape(f"{profile.name} {profile.version}".strip())
    tech_name    = html_lib.escape(profile.name)

    # ── Stats ─────────────────────────────────────────────────────────────
    sev_counts = {s: 0 for s in ("CRITICAL","HIGH","MEDIUM","LOW","NONE")}
    for c in cves:
        sev_counts[c.severity] = sev_counts.get(c.severity, 0) + 1
    cves_with_pocs  = sum(1 for c in cves if c.pocs)
    avg_epss        = (sum(c.epss_score for c in cves) / len(cves) * 100) if cves else 0

    # ── CVE table rows ────────────────────────────────────────────────────
    cve_rows = ""
    for c in cves:
        score  = c.cvss_v3 or c.cvss_v2
        poc_links = ""
        for p in c.pocs[:3]:
            stars = p.get("stars", 0)
            url   = html_lib.escape(p["url"])
            author= html_lib.escape(p.get("author",""))
            poc_links += f'<a href="{url}" target="_blank" class="poc-link">⭐{stars} {author}</a> '
        if not poc_links:
            poc_links = '<span class="no-poc">—</span>'
        epss_cell = _epss_bar(c.epss_score) if c.epss_score else "—"
        refs_html = ""
        for ref in c.references[:3]:
            r_esc = html_lib.escape(ref)
            host  = re.sub(r"https?://(www\.)?", "", ref).split("/")[0]
            refs_html += f'<a href="{r_esc}" target="_blank" class="ref-link">{html_lib.escape(host)}</a> '

        cve_rows += f"""
        <tr data-sev="{c.severity}">
          <td><a href="https://nvd.nist.gov/vuln/detail/{c.cve_id}" target="_blank" class="cve-id">{c.cve_id}</a></td>
          <td>{_severity_badge(c.severity)}</td>
          <td class="score-cell">{score:.1f}</td>
          <td class="desc-cell">{html_lib.escape(c.description[:180])}{'…' if len(c.description)>180 else ''}</td>
          <td>{html_lib.escape(c.cwe or '—')}</td>
          <td>{epss_cell}</td>
          <td>{poc_links}</td>
          <td class="ref-cell">{refs_html}</td>
          <td>{c.published[:10]}</td>
        </tr>"""

    # ── Exploit rows ──────────────────────────────────────────────────────
    exploit_rows = ""
    for e in exploits:
        link = html_lib.escape(e.link or "")
        exploit_rows += f"""
        <tr>
          <td>{html_lib.escape(e.title)}</td>
          <td><span class="tag">{html_lib.escape(e.source)}</span></td>
          <td><span class="tag">{html_lib.escape(e.exploit_type)}</span></td>
          <td>{html_lib.escape(e.platform or '—')}</td>
          <td>{html_lib.escape(e.date or '—')}</td>
          <td>{'<a href="'+link+'" target="_blank" class="ref-link">Link</a>' if link else '—'}</td>
        </tr>"""

    # ── Dork results grouped by category ─────────────────────────────────
    dork_cats: dict[str, list[DorkResult]] = {}
    for d in dorks:
        dork_cats.setdefault(d.category, []).append(d)

    dork_sections = ""
    for cat, items in dork_cats.items():
        links_html = "".join(
            f'<li><a href="{html_lib.escape(i.url)}" target="_blank">{html_lib.escape(i.url[:90])}{"…" if len(i.url)>90 else ""}</a></li>'
            for i in items
        )
        dork_sections += f"""
        <details class="dork-group">
          <summary><span class="cat-badge">{html_lib.escape(cat)}</span> &nbsp; {len(items)} result(s)</summary>
          <ul class="dork-list">{links_html}</ul>
        </details>"""

    # ── Filter buttons ────────────────────────────────────────────────────
    filter_btns = "".join(
        f'<button class="filter-btn" data-sev="{s}" onclick="filterBySev(\'{s}\')">'
        f'{_severity_badge(s)} {sev_counts[s]}</button>'
        for s in ("CRITICAL","HIGH","MEDIUM","LOW")
    )

    # ── Profile block ─────────────────────────────────────────────────────
    profile_html = ""
    if profile.description:
        profile_html += f'<p class="profile-desc">{html_lib.escape(profile.description[:400])}</p>'
    if profile.vendor:
        profile_html += f'<p><strong>Vendor:</strong> {html_lib.escape(profile.vendor)}</p>'
    if profile.cpe:
        profile_html += f'<p><strong>CPE:</strong> <code>{html_lib.escape(profile.cpe)}</code></p>'
    if profile.homepage:
        profile_html += f'<p><strong>Homepage:</strong> <a href="{html_lib.escape(profile.homepage)}" target="_blank">{html_lib.escape(profile.homepage)}</a></p>'
    if profile.tags:
        tag_html = "".join(f'<span class="tag">{html_lib.escape(t)}</span>' for t in profile.tags[:6])
        profile_html += f'<p class="tags">{tag_html}</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScope — {tech_display}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600&display=swap');

  :root {{
    --bg:      #0a0d12;
    --surface: #111520;
    --card:    #161b27;
    --border:  #252d3d;
    --text:    #c9d1e0;
    --dim:     #5a6478;
    --accent:  #3b82f6;
    --green:   #34c759;
    --red:     #ff2d55;
    --orange:  #ff6b35;
    --yellow:  #ffd60a;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'DM Sans', sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0d1626 0%, #101825 50%, #0a1120 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px 28px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 70% 50%, rgba(59,130,246,0.07) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-inner {{ max-width: 1400px; margin: 0 auto; position: relative; }}
  .header-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; flex-wrap: wrap; }}
  .brand {{ font-family: var(--mono); font-size: 11px; color: var(--accent); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 6px; }}
  .tech-title {{ font-family: var(--mono); font-size: 32px; font-weight: 700; color: #e8edf7; letter-spacing: -1px; }}
  .tech-title .version-tag {{ color: var(--accent); font-size: 20px; }}
  .generated {{ font-size: 11px; color: var(--dim); margin-top: 6px; font-family: var(--mono); }}
  .stat-row {{ display: flex; gap: 16px; margin-top: 24px; flex-wrap: wrap; }}
  .stat-card {{
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 20px;
    min-width: 100px;
    text-align: center;
    backdrop-filter: blur(4px);
  }}
  .stat-num {{ font-family: var(--mono); font-size: 26px; font-weight: 700; line-height: 1; }}
  .stat-lbl {{ font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .stat-card.critical .stat-num {{ color: var(--red); }}
  .stat-card.high     .stat-num {{ color: var(--orange); }}
  .stat-card.medium   .stat-num {{ color: var(--yellow); }}
  .stat-card.low      .stat-num {{ color: var(--green); }}
  .stat-card.total    .stat-num {{ color: var(--accent); }}

  /* ── Layout ── */
  .main {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
  .section {{ margin-bottom: 40px; }}
  .section-title {{
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-title .count {{ color: var(--dim); font-size: 10px; }}

  /* ── Profile ── */
  .profile-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
  }}
  .profile-desc {{ color: var(--text); margin-bottom: 10px; line-height: 1.7; }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}

  /* ── Filter bar ── */
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
  .filter-bar span {{ font-size: 11px; color: var(--dim); margin-right: 4px; }}
  .filter-btn {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    cursor: pointer;
    font-size: 12px;
    padding: 5px 12px;
    font-family: var(--sans);
    transition: border-color 0.15s;
    display: inline-flex; align-items: center; gap: 6px;
  }}
  .filter-btn:hover {{ border-color: var(--accent); }}
  .filter-btn.active {{ border-color: var(--accent); background: rgba(59,130,246,0.1); }}
  #clear-btn {{
    background: transparent; border: 1px dashed var(--border);
    border-radius: 6px; color: var(--dim); cursor: pointer;
    font-size: 11px; padding: 5px 10px; font-family: var(--sans);
  }}
  #clear-btn:hover {{ color: var(--text); border-color: var(--dim); }}

  /* ── Table ── */
  .tbl-wrap {{ overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); }}
  thead th {{
    background: var(--surface);
    color: var(--dim);
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    padding: 12px 14px;
    text-align: left;
    white-space: nowrap;
    position: sticky; top: 0; z-index: 2;
  }}
  tbody tr {{ border-top: 1px solid var(--border); transition: background 0.12s; }}
  tbody tr:hover {{ background: rgba(59,130,246,0.05); }}
  tbody tr[data-sev="CRITICAL"] {{ border-left: 3px solid var(--red); }}
  tbody tr[data-sev="HIGH"]     {{ border-left: 3px solid var(--orange); }}
  tbody tr[data-sev="MEDIUM"]   {{ border-left: 3px solid var(--yellow); }}
  tbody tr[data-sev="LOW"]      {{ border-left: 3px solid var(--green); }}
  td {{ padding: 10px 14px; vertical-align: top; }}
  td.desc-cell {{ max-width: 320px; font-size: 12px; color: #9aa3b8; }}
  td.score-cell {{ font-family: var(--mono); font-weight: 600; font-size: 15px; color: #e8edf7; text-align: center; }}
  td.ref-cell {{ font-size: 11px; }}

  /* ── Badges / tags ── */
  .badge {{
    display: inline-block;
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 2px 7px;
    border-radius: 4px;
    color: #fff;
    white-space: nowrap;
  }}
  .tag {{
    display: inline-block;
    background: rgba(255,255,255,0.06);
    border: 1px solid var(--border);
    border-radius: 5px;
    font-size: 11px;
    padding: 2px 8px;
    color: var(--dim);
  }}

  /* ── Links ── */
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .cve-id {{ font-family: var(--mono); font-weight: 600; font-size: 12px; white-space: nowrap; }}
  .poc-link {{
    display: inline-block;
    background: rgba(52,199,89,0.1);
    border: 1px solid rgba(52,199,89,0.3);
    border-radius: 5px;
    color: var(--green) !important;
    font-size: 10px;
    font-family: var(--mono);
    padding: 2px 7px;
    margin: 1px;
    white-space: nowrap;
  }}
  .no-poc {{ color: var(--dim); font-size: 11px; }}
  .ref-link {{ font-size: 11px; color: #6c9af5; }}
  code {{ font-family: var(--mono); font-size: 12px; color: #7dd3fc; }}

  /* ── EPSS bar ── */
  .epss-wrap {{
    display: flex; align-items: center; gap: 6px;
    min-width: 80px;
  }}
  .epss-bar {{
    height: 5px; border-radius: 3px; flex-shrink: 0;
    min-width: 2px; transition: width 0.3s;
  }}
  .epss-label {{ font-family: var(--mono); font-size: 10px; color: var(--dim); white-space: nowrap; }}

  /* ── Dork accordion ── */
  .dork-group {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 6px;
    overflow: hidden;
  }}
  .dork-group summary {{
    padding: 10px 16px;
    cursor: pointer;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--text);
    user-select: none;
  }}
  .dork-group summary::-webkit-details-marker {{ display: none; }}
  .dork-group summary:hover {{ background: rgba(59,130,246,0.05); }}
  .dork-group[open] summary {{ border-bottom: 1px solid var(--border); }}
  .cat-badge {{
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(59,130,246,0.15);
    border: 1px solid rgba(59,130,246,0.3);
    color: #6cb4ff;
    text-transform: uppercase;
  }}
  .dork-list {{ padding: 10px 16px 12px; list-style: none; }}
  .dork-list li {{ padding: 3px 0; font-size: 12px; word-break: break-all; }}

  /* ── No results ── */
  .empty-msg {{
    text-align: center;
    color: var(--dim);
    padding: 40px;
    font-family: var(--mono);
    font-size: 12px;
  }}

  /* ── Responsive ── */
  @media (max-width: 768px) {{
    .header, .main {{ padding: 20px; }}
    .tech-title {{ font-size: 22px; }}
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-inner">
    <div class="header-top">
      <div>
        <div class="brand">◈ VulnScope Intelligence Report</div>
        <h1 class="tech-title">
          {html_lib.escape(profile.name)}
          {'<span class="version-tag"> v' + html_lib.escape(profile.version) + '</span>' if profile.version else ''}
        </h1>
        <div class="generated">Generated {now}</div>
      </div>
    </div>
    <div class="stat-row">
      <div class="stat-card total">
        <div class="stat-num">{len(cves)}</div>
        <div class="stat-lbl">Total CVEs</div>
      </div>
      <div class="stat-card critical">
        <div class="stat-num">{sev_counts['CRITICAL']}</div>
        <div class="stat-lbl">Critical</div>
      </div>
      <div class="stat-card high">
        <div class="stat-num">{sev_counts['HIGH']}</div>
        <div class="stat-lbl">High</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-num">{sev_counts['MEDIUM']}</div>
        <div class="stat-lbl">Medium</div>
      </div>
      <div class="stat-card low">
        <div class="stat-num">{sev_counts['LOW']}</div>
        <div class="stat-lbl">Low</div>
      </div>
      <div class="stat-card" style="min-width:120px">
        <div class="stat-num" style="color:#a78bfa">{len(exploits)}</div>
        <div class="stat-lbl">Exploits</div>
      </div>
      <div class="stat-card" style="min-width:120px">
        <div class="stat-num" style="color:var(--green)">{cves_with_pocs}</div>
        <div class="stat-lbl">CVEs w/ PoC</div>
      </div>
      <div class="stat-card" style="min-width:120px">
        <div class="stat-num" style="color:var(--orange)">{avg_epss:.1f}%</div>
        <div class="stat-lbl">Avg EPSS</div>
      </div>
      <div class="stat-card" style="min-width:120px">
        <div class="stat-num" style="color:#67e8f9">{len(dorks)}</div>
        <div class="stat-lbl">Dork Results</div>
      </div>
    </div>
  </div>
</header>

<main class="main">

  <!-- PROFILE -->
  {'<section class="section"><div class="section-title">◈ Technology Profile</div><div class="profile-card">' + profile_html + '</div></section>' if profile_html else ''}

  <!-- CVE TABLE -->
  <section class="section">
    <div class="section-title">◈ CVE Inventory <span class="count">({len(cves)} records)</span></div>
    <div class="filter-bar">
      <span>Filter:</span>
      {filter_btns}
      <button id="clear-btn" onclick="clearFilter()">✕ All</button>
    </div>
    {'<div class="tbl-wrap"><table><thead><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Description</th><th>CWE</th><th>EPSS</th><th>PoC Repos</th><th>References</th><th>Published</th></tr></thead><tbody>' + cve_rows + '</tbody></table></div>' if cves else '<div class="empty-msg">No CVEs found for this query.</div>'}
  </section>

  <!-- EXPLOITS -->
  <section class="section">
    <div class="section-title">◈ Known Exploits <span class="count">({len(exploits)} records)</span></div>
    {'<div class="tbl-wrap"><table><thead><tr><th>Title</th><th>Source</th><th>Type</th><th>Platform</th><th>Date</th><th>Link</th></tr></thead><tbody>' + exploit_rows + '</tbody></table></div>' if exploits else '<div class="empty-msg">No exploit records found (searchsploit / Sploitus).</div>'}
  </section>

  <!-- DORK RESULTS -->
  <section class="section">
    <div class="section-title">◈ Web Intelligence (Google Dorks) <span class="count">({len(dorks)} URLs across {len(dork_cats)} categories)</span></div>
    {dork_sections if dork_sections else '<div class="empty-msg">No dork results collected.</div>'}
  </section>

</main>

<script>
  let activeFilter = null;

  function filterBySev(sev) {{
    const rows = document.querySelectorAll('tbody tr[data-sev]');
    const btns = document.querySelectorAll('.filter-btn');
    if (activeFilter === sev) {{ clearFilter(); return; }}
    activeFilter = sev;
    rows.forEach(r => r.style.display = r.dataset.sev === sev ? '' : 'none');
    btns.forEach(b => b.classList.toggle('active', b.dataset.sev === sev));
  }}

  function clearFilter() {{
    activeFilter = null;
    document.querySelectorAll('tbody tr[data-sev]').forEach(r => r.style.display = '');
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  }}
</script>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    log.info(f"HTML report → {output_path}")


# ─────────────────────────────────────────────
#  JSON EXPORT
# ─────────────────────────────────────────────
def export_json(
    profile: TechProfile,
    cves: list[CVERecord],
    exploits: list[ExploitRecord],
    dorks: list[DorkResult],
    output_path: Path,
) -> None:
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "profile":   asdict(profile),
        "stats": {
            "total_cves":    len(cves),
            "critical":      sum(1 for c in cves if c.severity == "CRITICAL"),
            "high":          sum(1 for c in cves if c.severity == "HIGH"),
            "medium":        sum(1 for c in cves if c.severity == "MEDIUM"),
            "low":           sum(1 for c in cves if c.severity == "LOW"),
            "cves_with_pocs":sum(1 for c in cves if c.pocs),
            "exploits":      len(exploits),
            "dork_results":  len(dorks),
        },
        "cves":     [asdict(c) for c in cves],
        "exploits": [asdict(e) for e in exploits],
        "dorks":    [asdict(d) for d in dorks],
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info(f"JSON export  → {output_path}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(
        description="VulnScope — Vulnerability Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("technology",     help="Technology / product name  (e.g. nginx, plesk, openssh)")
    p.add_argument("-v", "--version", default="", help="Specific version to focus on  (e.g. 0.9, 2.4.51)")
    p.add_argument("--year-from",    type=int, default=2018,  help="CVE publish year start (default: 2018)")
    p.add_argument("--year-to",      type=int, default=2026,  help="CVE publish year end   (default: 2026)")
    p.add_argument("--top",          type=int, default=100,   help="Max CVEs to fetch      (default: 100)")
    p.add_argument("--github-token", default="", help="GitHub PAT — increases PoC search rate limit")
    p.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY", ""), help="NVD API key (or set env NVD_API_KEY)")
    p.add_argument("--dork-delay",   type=float, default=3.5, help="Delay (s) between dork requests (default: 3.5)")
    p.add_argument("--skip-dorks",   action="store_true", help="Skip Google dork harvest")
    p.add_argument("--skip-pocs",    action="store_true", help="Skip GitHub PoC search")
    p.add_argument("--skip-epss",    action="store_true", help="Skip EPSS score enrichment")
    p.add_argument("--json-only",    action="store_true", help="Write only JSON report (no HTML)")
    p.add_argument("--html-only",    action="store_true", help="Write only HTML report (no JSON)")
    p.add_argument("-o", "--output", default="./vulnscope_output", help="Output directory (default: ./vulnscope_output)")
    args = p.parse_args()

    out_dir = Path(args.output) / sanitize(args.technology)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe   = sanitize(args.technology)
    vsufx  = f"_{sanitize(args.version)}" if args.version else ""

    log.info("=" * 60)
    log.info(f"  VulnScope  —  {args.technology} {args.version}".strip())
    log.info("=" * 60)

    # Apply NVD API key from CLI if provided
    global NVD_API_KEY
    if args.nvd_api_key:
        NVD_API_KEY = args.nvd_api_key

    # ── Phase 0: Profile ──────────────────────────────────────────────────
    profile = build_tech_profile(args.technology, args.version)

    # ── Phase 1: CVEs ─────────────────────────────────────────────────────
    cves = fetch_cves(
        args.technology, args.version,
        args.year_from, args.year_to,
        args.top, profile,
    )

    # ── Phase 2: EPSS ─────────────────────────────────────────────────────
    if cves and not args.skip_epss:
        enrich_epss(cves)

    # ── Phase 3: PoCs ─────────────────────────────────────────────────────
    if cves and not args.skip_pocs:
        enrich_pocs(cves, args.github_token)

    # ── Phase 4: Sploitus ─────────────────────────────────────────────────
    exploits = run_sploitus(args.technology, args.version)

    # ── Phase 5: searchsploit ─────────────────────────────────────────────
    local_exploits = run_searchsploit(args.technology, args.version)
    exploits.extend(local_exploits)

    # ── Phase 6: Dorks ────────────────────────────────────────────────────
    dorks: list[DorkResult] = []
    if not args.skip_dorks:
        dorks = run_dorks(args.technology, args.version, args.dork_delay)

    # ── Output ────────────────────────────────────────────────────────────
    if not args.html_only:
        export_json(profile, cves, exploits, dorks, out_dir / f"{safe}{vsufx}_vulnscope.json")

    if not args.json_only:
        generate_html(profile, cves, exploits, dorks, out_dir / f"{safe}{vsufx}_vulnscope.html")

    # ── Summary ───────────────────────────────────────────────────────────
    crit = sum(1 for c in cves if c.severity == "CRITICAL")
    high = sum(1 for c in cves if c.severity == "HIGH")
    pocs = sum(1 for c in cves if c.pocs)

    log.info("")
    log.info("─" * 60)
    log.info(f"  Target    : {args.technology} {args.version}".rstrip())
    log.info(f"  CVEs      : {len(cves)}  (Critical: {crit}  High: {high})")
    log.info(f"  PoC repos : {pocs} CVEs have public PoCs")
    log.info(f"  Exploits  : {len(exploits)}")
    log.info(f"  Dork URLs : {len(dorks)}")
    log.info(f"  Output    : {out_dir}")
    log.info("─" * 60)


if __name__ == "__main__":
    main()
