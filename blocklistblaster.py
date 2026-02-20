#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import json
import re
import sys
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

# Load Public Suffix List (vendored)
PSL_PATH = Path("data/public_suffix_list.dat")
psl = PublicSuffixList(PSL_PATH.read_text().splitlines())


# -----------------------------
# LOGGING
# -----------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# -----------------------------
# CACHE HANDLING
# -----------------------------

def load_cache() -> dict:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {}


def save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2))


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
    """
    Validate domain using the Public Suffix List.
    Returns True if the domain has a recognised public suffix.
    """
    suffix = psl.get_public_suffix(domain)

    # If PSL returns the domain itself, it's not a valid public suffix
    # Example: "localhost" -> suffix == "localhost"
    if suffix == domain:
        return False

    # Must contain at least one dot (e.g., "example.com")
    return "." in suffix


# -----------------------------
# DOMAIN EXTRACTION
# -----------------------------

def is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#") or s.startswith("//") or s.startswith(";")


def extract_domain(line: str) -> str | None:
    s = line.strip()

    if is_comment_or_empty(s):
        return None

    # Remove inline comments
    for sep in ("#", ";", "//"):
        if sep in s:
            s = s.split(sep, 1)[0].strip()

    if not s:
        return None

    parts = s.split()
    candidate = parts[0] if len(parts) == 1 else parts[1]

    candidate = normalise_domain(candidate)
    if not candidate:
        return None

    # Reject IPs
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
        return None
    if ":" in candidate:
        return None

    # Reject underscores
    if "_" in candidate:
        return None

    # Validate structure
    if not DOMAIN_RE.match(candidate):
        return None

    # Validate TLD using PSL
    if not is_valid_tld(candidate):
        return None

    return candidate


# -----------------------------
# DOWNLOADING WITH CACHING
# -----------------------------

def download_list(url: str, timeout: int = 15) -> list[str]:
    cache = load_cache()
    headers = {}

    if url in cache:
        if "etag" in cache[url]:
            headers["If-None-Match"] = cache[url]["etag"]
        if "last_modified" in cache[url]:
            headers["If-Modified-Since"] = cache[url]["last_modified"]

    resp = requests.get(url, timeout=timeout, headers=headers)

    if resp.status_code == 304:
        log(f"[INFO] Not modified: {url}")
        return cache[url]["content"].splitlines()

    resp.raise_for_status()
    text = resp.text

    cache[url] = {
        "etag": resp.headers.get("ETag"),
        "last_modified": resp.headers.get("Last-Modified"),
        "hash": hash_text(text),
        "content": text,
    }
    save_cache(cache)

    return text.splitlines()


# -----------------------------
# PROCESSING
# -----------------------------

def process_lines(lines: list[str]) -> set[str]:
    domains = set()
    for line in lines:
        d = extract_domain(line)
        if d:
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

    # Blocklist
    block_domains = merge_lists(block_urls, max_workers=args.max_workers)

    # Allowlist
    allow_domains = merge_lists(allow_urls, max_workers=args.max_workers)

    # Apply allowlist
    if allow_domains:
        before = len(block_domains)
        block_domains.difference_update(allow_domains)
        log(f"[INFO] Removed {before - len(block_domains)} domains due to allowlist")

    # Regex list
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

    # Diff report
    previous = load_previous_blocklist(block_out)
    diff = generate_diff_report(previous, block_domains)
    Path("lists/diff_report.txt").write_text(diff)

    # Save previous for next run
    Path("lists/blocklist_previous.txt").write_text(
        "\n".join(sorted(block_domains))
    )

    # Write outputs
    write_list(block_domains, block_out)
    if allow_domains:
        write_list(allow_domains, allow_out)
    if regex_entries:
        write_list(regex_entries, regex_out)

    log("[INFO] Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

