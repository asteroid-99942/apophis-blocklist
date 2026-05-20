#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import json
import random
import re
import sys
import time
import urllib.parse
from pathlib import Path

import idna
import requests
from publicsuffix2 import PublicSuffixList

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # pip install tomli for Python <3.11


# -----------------------------
# CONFIG
# -----------------------------

CACHE_FILE = Path("cache/metadata.json")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# NEW: URL + token regexes for enhanced extraction
URL_RE = re.compile(
    r"(https?://[A-Za-z0-9\.-]+\.[A-Za-z]{2,63}(?:/[^\s]*)?)",
    re.IGNORECASE
)

TOKEN_RE = re.compile(
    r"[A-Za-z0-9\.-]+\.[A-Za-z]{2,63}"
)

PSL_PATH = Path("data/public_suffix_list.dat")
psl = PublicSuffixList(PSL_PATH.read_text().splitlines())


# -----------------------------
# LOGGING
# -----------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# -----------------------------
# CACHE HANDLING (FIXED)
# -----------------------------

def load_cache() -> dict:
    """Load cache JSON safely, even if corrupted."""
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except json.JSONDecodeError as e:
        log(f"[WARN] Cache file corrupted ({e}); resetting cache")
        return {}
    except Exception as e:
        log(f"[WARN] Failed to read cache file: {e}")
        return {}


def save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2))
    tmp.replace(CACHE_FILE)


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# -----------------------------
# DOMAIN NORMALISATION
# -----------------------------

def normalise_domain(domain: str) -> str | None:
    domain = domain.strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    if domain.startswith("*."):
        domain = domain[2:]

    domain = domain.rstrip("/")

    try:
        domain = idna.encode(domain).decode()
    except idna.IDNAError:
        return None

    return domain


# -----------------------------
# PSL-BASED TLD VALIDATION
# -----------------------------

def is_valid_tld(domain: str) -> bool:
    suffix = psl.get_public_suffix(domain)
    return "." in suffix


# -----------------------------
# COMMENT CHECK
# -----------------------------

def is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#") or s.startswith("//") or s.startswith(";")


# -----------------------------
# **ENHANCED DOMAIN EXTRACTION**
# -----------------------------

def extract_all_domains(line: str) -> set[str]:
    """Extract as many valid domains as possible from a single line."""
    out = set()
    s = line.strip()

    if is_comment_or_empty(s):
        return out

    # Remove inline comments
    for sep in ("#", ";", "//"):
        if sep in s:
            s = s.split(sep, 1)[0].strip()

    if not s:
        return out

    # 1. Extract domains from URLs anywhere in the line
    for url in URL_RE.findall(s):
        try:
            host = urllib.parse.urlparse(url).hostname
            if host:
                out.add(host.lower())
        except Exception:
            pass

    # 2. Extract from hosts-format lines
    parts = s.split()
    if parts and (parts[0].startswith("0.0.0.0") or parts[0].startswith("127.0.0.1")):
        parts = parts[1:]

    # 3. Extract domain-like tokens
    for token in parts:
        token = token.strip("[](){}<>,'\"")

        if token.startswith("*."):
            token = token[2:]

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", token):
            continue
        if ":" in token:
            continue

        if TOKEN_RE.match(token):
            out.add(token.lower())

    # 4. Validate + normalise
    final = set()
    for d in out:
        if "_" in d:
            continue
        if not DOMAIN_RE.match(d):
            continue
        if not is_valid_tld(d):
            continue
        nd = normalise_domain(d)
        if nd:
            final.add(nd)

    return final


# -----------------------------
# RESILIENT DOWNLOADING
# -----------------------------

def download_list(url: str, timeout: int = 15, max_retries: int = 5) -> list[str]:
    cache = load_cache()

    def has_cached() -> bool:
        return url in cache and "content" in cache[url]

    def cached_lines() -> list[str]:
        return cache[url]["content"].splitlines()

    backoff_base = 1.0

    for attempt in range(1, max_retries + 1):
        headers = {}

        if url in cache:
            if "etag" in cache[url]:
                headers["If-None-Match"] = cache[url]["etag"]
            if "last_modified" in cache[url]:
                headers["If-Modified-Since"] = cache[url]["last_modified"]

        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                allow_redirects=True
            )

            if resp.status_code == 304 and has_cached():
                log(f"[INFO] Not modified (304): {url}")
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
            log(f"[WARN] Attempt {attempt}/{max_retries} failed for {url}: {e}")

            if attempt < max_retries:
                delay = backoff_base * (2 ** (attempt - 1))
                delay += random.uniform(0, delay * 0.5)
                log(f"[INFO] Backing off {delay:.2f}s before retrying {url}")
                time.sleep(delay)
            else:
                log(f"[ERROR] Exhausted retries for {url}")

    if has_cached():
        log(f"[WARN] Using cached content for {url} after repeated failures")
        return cached_lines()

    raise RuntimeError(f"Failed to download {url} and no cached content is available")


# -----------------------------
# PROCESSING (UPDATED)
# -----------------------------

def process_lines(lines: list[str]) -> set[str]:
    domains = set()
    for line in lines:
        for d in extract_all_domains(line):
            domains.add(d)
    return domains


def fetch_and_process(url: str) -> set[str]:
    try:
        lines = download_list(url)
        return process_lines(lines)
    except Exception as e:
        log(f"[WARN] Failed to process {url}: {e}")
        return set()


def merge_lists(urls: list[str], max_workers: int = 8) -> set[str]:
    if not urls:
        return set()

    merged = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(fetch_and_process, u): u for u in urls}
        for fut in concurrent.futures.as_completed(future_map):
            url = future_map[fut]
            try:
                result = fut.result()
                log(f"[INFO] {url}: {len(result)} valid domains")
                merged.update(result)
            except Exception as e:
                log(f"[WARN] Error merging {url}: {e}")
    return merged


# -----------------------------
# DIFF REPORT
# -----------------------------

def load_previous_blocklist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(path.read_text().splitlines())


def generate_diff_report(old: set[str], new: set[str]) -> str:
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


# -----------------------------
# OUTPUT
# -----------------------------

def write_list(domains: set[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    path.write_text("\n".join(sorted_domains))
    log(f"[INFO] Wrote {len(sorted_domains)} domains to {path}")


# -----------------------------
# MAIN
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="BlocklistBlaster (Python) - merge and curate Pi-hole blocklists"
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
        default=8,
        help="Maximum parallel downloads",
    )
    args = parser.parse_args()

    try:
        cfg = tomllib.loads(Path(args.config).read_text())
    except Exception as e:
        log(f"[ERROR] Failed to load config: {e}")
        return 1

    lists_cfg = cfg.get("lists", {})
    output_cfg = cfg.get("output", {})

    block_urls = lists_cfg.get("block", [])
    allow_urls = lists_cfg.get("allow", [])
    regex_urls = lists_cfg.get("regex", [])

    block_out = Path(output_cfg.get("block", "lists/blocklist.txt"))
    allow_out = Path(output_cfg.get("allow", "lists/allowlist.txt"))
    regex_out = Path(output_cfg.get("regex", "lists/regexlist.txt"))

    log("[INFO] Starting merge")

    block_domains = merge_lists(block_urls, max_workers=args.max_workers)
    allow_domains = merge_lists(allow_urls, max_workers=args.max_workers)

    if allow_domains:
        before = len(block_domains)
        block_domains.difference_update(allow_domains)
        log(f"[INFO] Removed {before - len(block_domains)} domains due to allowlist")

    regex_entries = set()
    for url in regex_urls:
        try:
            lines = download_list(url)
            for line in lines:
                s = line.strip()
                if not is_comment_or_empty(s):
                    regex_entries.add(s)
        except Exception as e:
            log(f"[WARN] Failed to fetch regex list {url}: {e}")

    previous = load_previous_blocklist(block_out)
    diff = generate_diff_report(previous, block_domains)
    Path("lists/diff_report.txt").write_text(diff)

    Path("lists/blocklist_previous.txt").write_text(
        "\n".join(sorted(block_domains))
    )

    write_list(block_domains, block_out)
    if allow_domains:
        write_list(allow_domains, allow_out)
    if regex_entries:
        write_list(regex_entries, regex_out)

    log("[INFO] Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
