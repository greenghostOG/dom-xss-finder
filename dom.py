#!/usr/bin/env python3
import argparse
import requests
import re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# DOM XSS sinks grouped by severity (with tightened regex)
DOM_XSS_SINKS = {
    "HIGH": [
        r'\binnerHTML\b', r'\bouterHTML\b',
        r'document\.write\s*\(', r'document\.writeln\s*\(', r'insertAdjacentHTML\s*\(',
        r'eval\s*\(', r'new\s+Function\s*\(',   # tightened: only new Function()
        r'\.html\s*\(', r'\.append\s*\(', r'\.prepend\s*\(', r'\.after\s*\(', r'\.before\s*\('
    ],
    "MEDIUM": [
        r'setTimeout\s*\(', r'setInterval\s*\(',
        r'\blocation\s*=', r'\blocation\.href\b', r'\bdocument\.location\b',
        r'\bwindow\.location\b', r'\btop\.location\b', r'\bparent\.location\b'
    ],
    "LOW": [
        r'\.src\s*='  # assigning .src dynamically
    ]
}

session = requests.Session()
session.headers.update({"User-Agent": "DOMXSS-Scanner"})

def fetch_url(url):
    """Fetches URL using GET, falls back to POST if needed."""
    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code in [401, 403]:
            resp = session.post(url, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
    return ""

def find_dom_xss(url, content):
    """Scans page content for dangerous DOM sinks."""
    vulnerable = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for severity, sinks in DOM_XSS_SINKS.items():
        for sink in sinks:
            for match in re.finditer(sink + r'.{0,80}', content, re.IGNORECASE | re.DOTALL):
                snippet = match.group(0).strip()
                if params:
                    for param in params.keys():
                        if param in snippet:
                            vulnerable.append(f"[{severity}] {url} -> {sink} with param {param} :: {snippet}")
                else:
                    vulnerable.append(f"[{severity}] {url} -> {sink} :: {snippet}")
    return vulnerable

def scan_url(url, output_file):
    """Scans a single URL and writes results immediately."""
    print(f"[+] Scanning {url}")
    content = fetch_url(url)
    if not content:
        return []

    vulns = find_dom_xss(url, content)
    if vulns:
        for v in vulns:
            print(f"[VULN] {v}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(v + "\n")
    return vulns

def main():
    parser = argparse.ArgumentParser(description="Tightened DOM XSS Finder")
    parser.add_argument("-l", "--list", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=False, help="Save output to file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default 10)")
    args = parser.parse_args()

    with open(args.list, "r") as f:
        urls = [line.strip() for line in f.readlines() if line.strip()]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url, url, args.output) for url in urls]
        for _ in as_completed(futures):
            pass

    if args.output:
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()

