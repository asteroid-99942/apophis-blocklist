#!/usr/bin/env python3
"""
BlocklistBlaster (clean rewrite with Hybrid TLD Validation)

- Loads sources from a TOML config
- Downloads lists with ETag/Last-Modified caching
- Extracts domains from:
  - bare domains
  - hosts-format lines (0.0.0.0 example.com)
  - URLs anywhere in the line
  - wildcard patterns (*.example.com)
  - multiple domains per line
  - adblock syntax (||domain^)
- Validates domains using Hybrid TLD Validation:
  - Accept if PSL says valid OR TLD is alphabetic 2–10 chars
- Applies allowlist
- Writes blocklist, allowlist, regex list, and diff report
"""

import argparse
import concurrent.futures
import hashlib
import json
import logging
import random
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Iterable, Optional, Set

import idna
import requests
from publicsuffix2 import PublicSuffixList

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Python <3.11: pip install tomli


# -----------------------------
# CONFIG
# -----------------------------

CACHE_FILE = Path("cache/metadata.json")
PSL_PATH = Path("data/public_suffix_list.dat")

DEFAULT_BLOCK_OUT = Path("lists/blocklist.txt")
DEFAULT_ALLOW_OUT = Path("lists/allowlist.txt")
DEFAULT_REGEX_OUT = Path("lists/regexlist.txt")
DIFF_REPORT_OUT = Path("lists/diff_report.txt")
PREVIOUS_BLOCK_OUT = Path("lists/blocklist_previous.txt")

REQUEST_TIMEOUT = 15
MAX_RETRIES = 5
MAX_WORKERS_DEFAULT = 8

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

URL_RE = re.compile(
    r"(https?://[A-Za-z0-9\.-]+\.[A-Za-z]{2,63}(?:/[^\s]*)?)",
    re.IGNORECASE,
)

TOKEN_RE = re.compile(
    r"[A-Za-z0-9\.-]+\.[A-Za-z]{2,63}"
)


# -----------------------------
# LOGGING
# -----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("blocklistblaster")


# -----------------------------
# PSL
# -----------------------------

def load_psl(path: Path) -> PublicSuffixList:
    if not path.exists():
        raise FileNotFoundError(f"Public suffix list not found at {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    return PublicSuffixList(lines)


psl = load_psl(PSL_PATH)


# -----------------------------
# HYBRID TLD VALIDATION
# -----------------------------

def hybrid_tld_valid(domain: str) -> bool:
    """
    Hybrid TLD validation:
    - Accept if PSL says valid
    - Accept if TLD is alphabetic and 2–10 chars
    """
    suffix = psl.get_public_suffix(domain)

    # PSL says valid
    if "." in suffix:
        return True

    # Fallback: extract last label
    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]

    # Alphabetic TLD, 2–10 chars
    if tld.isalpha() and 2 <= len(tld) <= 10:
        return True

    return False


# -----------------------------
# CACHE HANDLING
# -----------------------------

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        log.warning("Cache file %s is corrupted (%s); resetting", CACHE_FILE, e)
        return {}
    except Exception as e:
        log.warning("Failed to read cache file %s: %s", CACHE_FILE, e)
        return {}


def save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    tmp.replace(CACHE_FILE)


# -----------------------------
# DOMAIN NORMALISATION
# -----------------------------

def normalise_domain(domain: str) -> Optional[str]:
    d = domain.strip().lower()

    if d.startswith("www."):
        d = d[4:]

    if d.startswith("*."):
        d = d[2:]

    d = d.rstrip("/")

    try:
        d = idna.encode(d).decode()
    except idna.IDNAError:
        return None

    return d


# -----------------------------
# LINE HELPERS
# -----------------------------

def is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#") or s.startswith("//") or s.startswith(";")


def is_ipv4(token: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", token))


def is_ipv6(token: str) -> bool:
    return ":" in token


# -----------------------------
# ENHANCED DOMAIN EXTRACTION
# -----------------------------

def extract_domains_from_line(line: str) -> Set[str]:
    out: Set[str] = set()
    s = line.strip()

    if is_comment_or_empty(s):
        return out

    # Strip inline comments
    for sep in ("#", ";", "//"):
        if sep in s:
            s = s.split(sep, 1)[0].strip()

    if not s:
        return out

    # Strip Adblock syntax
    if s.startswith("||"):
        s = s[2:]
    if s.endswith("^"):
        s = s[:-1]

    # 1. Extract domains from URLs
    for url in URL_RE.findall(s):
        try:
            host = urllib.parse.urlparse(url).hostname
            if host:
                out.add(host.lower())
        except Exception:
            continue

    # 2. Tokenise line
    parts = s.split()

    # Hosts format: drop leading IP
    if parts and (is_ipv4(parts[0]) or is_ipv6(parts[0])):
        parts = parts[1:]

    # 3. Extract domain-like tokens
    for token in parts:
        token = token.strip("[](){}<>,'\"")

        if token.startswith("*."):
            token = token[2:]

        if is_ipv4(token) or is_ipv6(token):
            continue

        if "_" in token:
            continue

        if TOKEN_RE.match(token):
            out.add(token.lower())

    # 4. Validate + normalise
    final: Set[str] = set()
    for d in out:
        if not DOMAIN_RE.match(d):
            continue
        if not hybrid_tld_valid(d):
            continue
        nd = normalise_domain(d)
        if nd:
            final.add(nd)

    return final


def process_lines(lines: Iterable[str]) -> Set[str]:
    domains: Set[str] = set()
    for line in lines:
        domains.update(extract_domains_from_line(line))
    return domains


# -----------------------------
# DOWNLOADING
# -----------------------------

def download_list(url: str, timeout: int = REQUEST_TIMEOUT, max_retries: int = MAX_RETRIES) -> list[str]:
    cache = load_cache()

    def has_cached() -> bool:
        return url in cache and "content" in cache[url]

    def cached_lines() -> list[str]:
        return cache[url]["content"].splitlines()

    backoff_base = 1.0

    for attempt in range(1, max_retries + 1):
        headers = {}

        if url in cache:
            meta = cache[url]
            etag = meta.get("etag")
            last_mod = meta.get("last_modified")
            if etag:
                headers["If-None-Match"] = etag
            if last_mod:
                headers["If-Modified-Since"] = last_mod

        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                allow_redirects=True,
            )

            if resp.status_code == 304 and has_cached():
                log.info("Not modified (304): %s", url)
                return cached_lines()

            resp.raise_for_status()
            text = resp.text.lstrip("\ufeff")

            stripped = text.strip()
            if not stripped:
                raise ValueError("empty response body")

            lower = stripped.lower()
            if "<html" in lower or lower.startswith("<!doctype html"):
                raise ValueError("HTML error page")
            if lower.startswith("{") or lower.startswith("["):
                raise ValueError("JSON error page")

            cache[url] = {
                "etag": resp.headers.get("ETag"),
                "last_modified": resp.headers.get("Last-Modified"),
                "hash": hash_text(text),
                "content": text,
            }
            save_cache(cache)

            return text.splitlines()

        except Exception as e:
            log.warning("Attempt %d/%d failed for %s: %s", attempt, max_retries, url, e)

            if attempt < max_retries:
                delay = backoff_base * (2 ** (attempt - 1))
                delay += random.uniform(0, delay * 0.5)
                log.info("Backing off %.2fs before retrying %s", delay, url)
                time.sleep(delay)
            else:
                log.error("Exhausted retries for %s", url)

    if has_cached():
        log.warning("Using cached content for %s after repeated failures", url)
        return cached_lines()

    raise RuntimeError(f"Failed to download {url} and no cached content is available")


def fetch_and_process(url: str) -> Set[str]:
    try:
        lines = download_list(url)
        domains = process_lines(lines)
        return domains
    except Exception as e:
        log.warning("Failed to process %s: %s", url, e)
        return set()


def merge_lists(urls: list[str], max_workers: int) -> Set[str]:
    if not urls:
        return set()

    merged: Set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(fetch_and_process, u): u for u in urls}
        for fut in concurrent.futures.as_completed(future_map):
            url = future_map[fut]
            try:
                result = fut.result()
                log.info("%s: %d valid domains", url, len(result))
                merged.update(result)
            except Exception as e:
                log.warning("Error merging %s: %s", url, e)
    return merged


# -----------------------------
# DIFF + OUTPUT
# -----------------------------

def load_previous_blocklist(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    return set(path.read_text(encoding="utf-8").splitlines())


def generate_diff_report(old: Set[str], new: Set[str]) -> str:
    added = new - old
    removed = old - new

    report = [
        f"Total domains: {len(new)}",
        f"Added: {len(added)}",
        f"Removed: {len(removed)}",
        "",
        "=== Added ===",
        *sorted(added),
        "",
        "=== Removed ===",
        *sorted(removed),
    ]
    return "\n".join(report)


def write_list(domains: Set[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    path.write_text("\n".join(sorted_domains), encoding="utf-8")
    log.info("Wrote %d domains to %s", len(sorted_domains), path)


# -----------------------------
# CONFIG LOADING
# -----------------------------

def load_config(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
        return tomllib.loads(text)
    except Exception as e:
        log.error("Failed to load config %s: %s", path, e)
        raise


# -----------------------------
# MAIN
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="BlocklistBlaster (clean) - merge and curate Pi-hole blocklists"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("blocklistblaster.toml"),
        help="Path to TOML config file",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=MAX_WORKERS_DEFAULT,
        help="Maximum parallel downloads",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)

    lists_cfg = cfg.get("lists", {})
    output_cfg = cfg.get("output", {})

    block_urls = lists_cfg.get("block", []) or []
    allow_urls = lists_cfg.get("allow", []) or []
    regex_urls = lists_cfg.get("regex", []) or []

    block_out = Path(output_cfg.get("block", str(DEFAULT_BLOCK_OUT)))
    allow_out = Path(output_cfg.get("allow", str(DEFAULT_ALLOW_OUT)))
    regex_out = Path(output_cfg.get("regex", str(DEFAULT_REGEX_OUT)))

    log.info("Starting merge")

    block_domains = merge_lists(block_urls, max_workers=args.max_workers)
    allow_domains = merge_lists(allow_urls, max_workers=args.max_workers)

    if allow_domains:
        before = len(block_domains)
        block_domains.difference_update(allow_domains)
        log.info("Removed %d domains due to allowlist", before - len(block_domains))

    regex_entries: Set[str] = set()
    for url in regex_urls:
        try:
            lines = download_list(url)
            for line in lines:
                s = line.strip()
                if not is_comment_or_empty(s):
                    regex_entries.add(s)
        except Exception as e:
            log.warning("Failed to fetch regex list %s: %s", url, e)

    previous = load_previous_blocklist(block_out)
    diff = generate_diff_report(previous, block_domains)
    DIFF_REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    DIFF_REPORT_OUT.write_text(diff, encoding="utf-8")

    PREVIOUS_BLOCK_OUT.parent.mkdir(parents=True, exist_ok=True)
    PREVIOUS_BLOCK_OUT.write_text(
        "\n".join(sorted(block_domains)), encoding="utf-8"
    )

    write_list(block_domains, block_out)
    if allow_domains:
        write_list(allow_domains, allow_out)
    if regex_entries:
        write_list(regex_entries, regex_out)

    log.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
