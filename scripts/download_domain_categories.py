#!/usr/bin/env python3
"""Download and build domain->category CSV from open-source blocklists.

Default source: blocklistproject/Lists (adguard format, MIT License repo).
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import urllib.request
from pathlib import Path

SOURCES = {
    "adult": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/porn-ags.txt",
    "gambling": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/gambling-ags.txt",
    "social": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/facebook-ags.txt",
    "social_alt": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tiktok-ags.txt",
    "shopping": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt",
    "crypto": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/crypto-ags.txt",
    "malware": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt",
    "tracking": "https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt",
}

CATEGORY_MAP = {
    "adult": "adult",
    "gambling": "gambling",
    "social": "social",
    "social_alt": "social",
    "shopping": "suspicious",
    "crypto": "finance",
    "malware": "suspicious",
    "tracking": "other",
}

RULE_RE = re.compile(r"^\|\|([^\^/$]+)")
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


def parse_domain(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("!") or line.startswith("#"):
        return None
    m = RULE_RE.match(line)
    if not m:
        return None
    domain = m.group(1).lower().strip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if not DOMAIN_RE.match(domain) or "." not in domain:
        return None
    return domain


def download_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "OpenScanProxy/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="configs/domain_categories.csv")
    args = ap.parse_args()

    merged: dict[str, str] = {}
    for src_key, url in SOURCES.items():
        category = CATEGORY_MAP[src_key]
        try:
            text = download_text(url)
        except Exception as ex:
            print(f"WARN: failed downloading {src_key} from {url}: {ex}", file=sys.stderr)
            continue
        for line in text.splitlines():
            domain = parse_domain(line)
            if not domain:
                continue
            merged.setdefault(domain, category)
        print(f"loaded {src_key}: {len(merged)} domains")

    if not merged:
        print("ERROR: no domains downloaded", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["# domain", "category"])
        for d, c in sorted(merged.items()):
            w.writerow([d, c])
    print(f"wrote {len(merged)} rows to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
