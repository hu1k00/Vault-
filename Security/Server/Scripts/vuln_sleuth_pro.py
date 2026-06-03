#!/usr/bin/env python3
"""
VulnSleuth Professional - Automated Vulnerability Research Tool

Performs a complete security research pipeline:
1. Web search (DuckDuckGo) for top URLs
2. searchsploit (local Exploit-DB)
3. Sploitus.com API (aggregated exploits)
4. NVD CVE API + GitHub PoC search + automatic download

Usage examples:
    python vuln_sleuth_pro.py nginx
    python vuln_sleuth_pro.py wordpress --skip-web --safe
    python vuln_sleuth_pro.py apache --github-token YOUR_TOKEN --download-pocs
"""

import argparse
import sys
import subprocess
import json
import csv
import re
import os
import shutil
import io
import zipfile
import time
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.parse import quote_plus

import requests
from duckduckgo_search import DDGS
from tenacity import retry, stop_after_attempt, wait_exponential

# ===================== LOGGING SETUP =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("VulnSleuth")

# ===================== HELPER FUNCTIONS =====================
def sanitize_filename(name: str) -> str:
    """Remove unsafe characters from a string for use as a filename."""
    return re.sub(r'[\\/*?:"<>|\s]', '_', name)

def ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)

# ===================== PHASE 1: WEB SEARCH (DuckDuckGo) =====================
def web_search(technology: str, output_dir: Path, max_results: int = 20) -> Optional[Path]:
    """Search DuckDuckGo for the technology and save top URLs."""
    logger.info(f"Phase 1: Web searching for '{technology}' on DuckDuckGo...")
    safe_tech = sanitize_filename(technology)
    out_file = output_dir / f"{safe_tech}_web_results.txt"
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(technology, max_results=max_results))
        urls = [r['href'] for r in results if r.get('href')]
        with open(out_file, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(url + '\n')
        logger.info(f"Saved {len(urls)} URLs to {out_file}")
        return out_file
    except Exception as e:
        logger.error(f"Web search failed: {e}")
        return None

# ===================== PHASE 2: SEARCHSPLOIT =====================
def run_searchsploit(technology: str, output_dir: Path) -> Optional[Path]:
    """Execute searchsploit and save filtered output."""
    logger.info(f"Phase 2: Running searchsploit for '{technology}'...")
    safe_tech = sanitize_filename(technology)
    out_file = output_dir / f"{safe_tech}_searchsploit.txt"
    try:
        result = subprocess.run(
            ['searchsploit', technology],
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        lines = result.stdout.splitlines()
        filtered = [
            line for line in lines
            if "Exploit Title" not in line
            and "Shellcodes" not in line
            and "----" not in line
            and line.strip()
        ]
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered))
        logger.info(f"Saved searchsploit results to {out_file}")
        return out_file
    except FileNotFoundError:
        logger.warning("searchsploit not found. Install with: sudo apt install exploitdb")
        return None
    except Exception as e:
        logger.error(f"searchsploit error: {e}")
        return None

# ===================== PHASE 3: SPLOITUS API =====================
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def fetch_sploitus(technology: str) -> List[Dict]:
    """Fetch exploits from Sploitus API with retries."""
    url = f"https://sploitus.com/api/search?q={quote_plus(technology)}"
    headers = {"Accept": "application/json"}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    exploits = []
    for item in data.get("results", []):
        exploits.append({
            "title": item.get("title", "N/A"),
            "link": item.get("link", "N/A"),
            "source": item.get("source", "N/A"),
            "type": item.get("type", "N/A")
        })
    return exploits

def sploitus_search(technology: str, output_dir: Path) -> Optional[Path]:
    """Query Sploitus API and save results."""
    logger.info(f"Phase 3: Searching Sploitus for '{technology}'...")
    safe_tech = sanitize_filename(technology)
    out_file = output_dir / f"{safe_tech}_sploitus.json"
    try:
        exploits = fetch_sploitus(technology)
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(exploits, f, indent=2)
        logger.info(f"Found {len(exploits)} exploits. Saved to {out_file}")
        return out_file
    except Exception as e:
        logger.error(f"Sploitus search failed: {e}")
        return None

# ===================== PHASE 4: NVD + GITHUB + DOWNLOAD =====================
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=6, max=30))
def fetch_nvd_cves(technology: str, max_cves: int = 50) -> List[Dict]:
    """Fetch CVEs from NVD API with pagination and rate-limit handling."""
    cves = []
    start_index = 0
    page_size = 20
    while len(cves) < max_cves:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={quote_plus(technology)}"
            f"&resultsPerPage={page_size}"
            f"&startIndex={start_index}"
        )
        resp = requests.get(url, timeout=15)
        if resp.status_code == 403:
            logger.warning("NVD rate limit hit. Sleeping 10 seconds...")
            time.sleep(10)
            continue
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        cves.extend(vulns)
        start_index += page_size
        # NVD allows 60 requests per minute; sleep 6 seconds between pages
        if len(vulns) == page_size:
            time.sleep(6)
        if len(cves) >= max_cves:
            break
    return cves[:max_cves]

def search_github_pocs(cve_id: str, github_token: str = "") -> List[Tuple[str, str]]:
    """Search GitHub for PoC repositories related to a CVE ID."""
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    # Better query: cve_id + "poc" OR "PoC" OR "exploit"
    query = f"{cve_id} poc"
    api_url = f"https://api.github.com/search/repositories?q={quote_plus(query)}&sort=stars&order=desc"
    try:
        resp = requests.get(api_url, headers=headers, timeout=10)
        if resp.status_code == 403 and "rate limit" in resp.text:
            logger.warning(f"GitHub rate limit reached for {cve_id}. Skipping.")
            return []
        resp.raise_for_status()
        data = resp.json()
        pocs = []
        for repo in data.get("items", [])[:5]:
            html_url = repo.get("html_url")
            author = repo.get("owner", {}).get("login")
            if html_url:
                pocs.append((html_url, author))
        return pocs
    except Exception as e:
        logger.debug(f"GitHub search failed for {cve_id}: {e}")
        return []

def download_poc_repo(repo_url: str, cve_id: str, target_dir: Path) -> Optional[Path]:
    """Clone or download a GitHub PoC repository. Returns the local path."""
    # Build target path: target_dir / CVE-ID_repo-name
    repo_name = repo_url.rstrip('/').split('/')[-1]
    if not repo_name:
        repo_name = cve_id
    target_path = target_dir / f"{cve_id}_{sanitize_filename(repo_name)}"
    if target_path.exists():
        logger.debug(f"PoC already exists: {target_path}")
        return target_path
    # Try git clone first
    if shutil.which("git"):
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(target_path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=True
            )
            logger.info(f"Cloned PoC into {target_path}")
            return target_path
        except subprocess.CalledProcessError:
            logger.debug(f"Git clone failed for {repo_url}, trying ZIP...")
        except Exception as e:
            logger.debug(f"Git clone error: {e}")
    # Fallback: download ZIP archive
    for branch in ["main", "master"]:
        zip_url = f"{repo_url.rstrip('/')}/archive/refs/heads/{branch}.zip"
        try:
            resp = requests.get(zip_url, timeout=30)
            if resp.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    # Extract to a temporary directory then move the top folder
                    temp_extract = target_path.with_suffix(".temp")
                    zf.extractall(temp_extract)
                    # The archive contains one top-level folder; move its contents
                    items = list(temp_extract.iterdir())
                    if items and items[0].is_dir():
                        shutil.move(str(items[0]), str(target_path))
                        shutil.rmtree(temp_extract)
                    else:
                        # If no folder, move everything
                        shutil.move(str(temp_extract), str(target_path))
                logger.info(f"Downloaded ZIP PoC into {target_path}")
                return target_path
        except Exception:
            continue
    logger.warning(f"Failed to download PoC from {repo_url}")
    return None

def cve_and_poc_phase(technology: str, output_dir: Path, github_token: str, download_pocs: bool, safe_mode: bool) -> Optional[Path]:
    """Fetch CVEs, search GitHub for PoCs, optionally download them."""
    logger.info(f"Phase 4: Fetching CVEs and PoCs for '{technology}'...")
    safe_tech = sanitize_filename(technology)
    csv_file = output_dir / f"{safe_tech}_cves.csv"
    poc_base_dir = output_dir / "downloaded_pocs" / safe_tech
    if download_pocs and not safe_mode:
        ensure_dir(poc_base_dir)
    else:
        if download_pocs and safe_mode:
            logger.info("Safe mode enabled: PoCs will not be downloaded.")
        poc_base_dir = None

    try:
        cve_items = fetch_nvd_cves(technology, max_cves=50)
        if not cve_items:
            logger.warning("No CVEs found for this technology.")
            return None
        logger.info(f"Found {len(cve_items)} CVEs. Searching GitHub for PoCs...")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["CVE ID", "GitHub PoC URL", "Author", "Local Path"])
            for item in cve_items:
                cve_id = item['cve']['id']
                logger.info(f"  Processing {cve_id}...")
                pocs = search_github_pocs(cve_id, github_token)
                if pocs:
                    for poc_url, author in pocs:
                        local_path = ""
                        if download_pocs and not safe_mode and poc_base_dir:
                            local_path = str(download_poc_repo(poc_url, cve_id, poc_base_dir) or "")
                        writer.writerow([cve_id, poc_url, author, local_path])
                else:
                    writer.writerow([cve_id, "No PoC found", "N/A", ""])
                # Be gentle with GitHub API
                time.sleep(1)
        logger.info(f"CVE/PoC results saved to {csv_file}")
        return csv_file
    except Exception as e:
        logger.error(f"CVE phase failed: {e}")
        return None

# ===================== MERGE REPORTS =====================
def generate_html_report(technology: str, output_dir: Path, files: Dict[str, Optional[Path]]) -> None:
    """Create a single HTML report with all findings."""
    safe_tech = sanitize_filename(technology)
    html_file = output_dir / f"{safe_tech}_report.html"
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>VulnSleuth Report: {technology}</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #16a085; border-bottom: 1px solid #ccc; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
    </style>
    </head>
    <body>
    <h1>Vulnerability Research Report for {technology}</h1>
    <p>Generated by VulnSleuth Professional</p>
    """

    # Web results
    if files.get("web"):
        html_content += f"<h2>Top Web Search Results</h2><pre>{files['web'].read_text(encoding='utf-8')}</pre>"
    else:
        html_content += "<h2>Web Search</h2><p>No results or phase skipped.</p>"

    # searchsploit
    if files.get("searchsploit"):
        html_content += f"<h2>searchsploit Output</h2><pre>{files['searchsploit'].read_text(encoding='utf-8')}</pre>"
    else:
        html_content += "<h2>searchsploit</h2><p>No results or phase skipped.</p>"

    # Sploitus
    sploitus_file = files.get("sploitus")
    if sploitus_file and sploitus_file.exists():
        import json
        data = json.loads(sploitus_file.read_text(encoding='utf-8'))
        if data:
            html_content += "<h2>Sploitus Exploits</h2><table><tr><th>Title</th><th>Source</th><th>Type</th><th>Link</th></tr>"
            for e in data:
                html_content += f"<tr><td>{e['title']}</td><td>{e['source']}</td><td>{e['type']}</td><td><a href='{e['link']}' target='_blank'>Link</a></td></tr>"
            html_content += "</table>"
        else:
            html_content += "<h2>Sploitus</h2><p>No exploits found.</p>"
    else:
        html_content += "<h2>Sploitus</h2><p>No results or phase skipped.</p>"

    # CVEs CSV
    csv_file = files.get("cve")
    if csv_file and csv_file.exists():
        html_content += "<h2>CVEs & GitHub PoCs</h2>"
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)
            html_content += "<table><tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"
            for row in reader:
                html_content += "<tr>"
                for cell in row:
                    if cell.startswith("http"):
                        html_content += f"<td><a href='{cell}' target='_blank'>{cell}</a></td>"
                    else:
                        html_content += f"<td>{cell}</td>"
                html_content += "</tr>"
            html_content += "</table>"
    else:
        html_content += "<h2>CVEs & PoCs</h2><p>No data available.</p>"

    html_content += "</body></html>"
    html_file.write_text(html_content, encoding='utf-8')
    logger.info(f"HTML report generated: {html_file}")

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="VulnSleuth Professional - Automated vulnerability research")
    parser.add_argument("technology", help="Service or technology to analyze (e.g., nginx, wordpress)")
    parser.add_argument("--output-dir", "-o", default="./vuln_output", help="Output directory (default: ./vuln_output)")
    parser.add_argument("--github-token", help="GitHub personal access token (increases API limit)")
    parser.add_argument("--skip-web", action="store_true", help="Skip web search phase")
    parser.add_argument("--skip-searchsploit", action="store_true", help="Skip searchsploit phase")
    parser.add_argument("--skip-sploitus", action="store_true", help="Skip Sploitus phase")
    parser.add_argument("--skip-cve", action="store_true", help="Skip CVE/GitHub phase")
    parser.add_argument("--download-pocs", action="store_true", help="Automatically download PoC repositories")
    parser.add_argument("--safe", action="store_true", help="Safe mode: list PoC URLs without downloading (overrides --download-pocs)")
    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir) / sanitize_filename(args.technology)
    ensure_dir(output_dir)

    logger.info(f"Target: {args.technology}")
    logger.info(f"Output directory: {output_dir}")

    files = {}

    # Phase 1: Web search
    if not args.skip_web:
        files["web"] = web_search(args.technology, output_dir)
    else:
        logger.info("Skipping web search.")

    # Phase 2: searchsploit
    if not args.skip_searchsploit:
        files["searchsploit"] = run_searchsploit(args.technology, output_dir)
    else:
        logger.info("Skipping searchsploit.")

    # Phase 3: Sploitus
    if not args.skip_sploitus:
        files["sploitus"] = sploitus_search(args.technology, output_dir)
    else:
        logger.info("Skipping Sploitus.")

    # Phase 4: CVE + PoC
    if not args.skip_cve:
        download = args.download_pocs
        safe = args.safe
        if safe and download:
            logger.warning("Safe mode overrides --download-pocs. No PoCs will be downloaded.")
            download = False
        files["cve"] = cve_and_poc_phase(args.technology, output_dir, args.github_token, download, safe)
    else:
        logger.info("Skipping CVE/GitHub phase.")

    # Generate HTML report
    generate_html_report(args.technology, output_dir, files)
    logger.info(f"All done! Results are in {output_dir}")

if __name__ == "__main__":
    main()