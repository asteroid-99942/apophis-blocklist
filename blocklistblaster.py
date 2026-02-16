#!/usr/bin/env python3
import argparse
import concurrent.futures
import re
import sys
from pathlib import Path

import requests

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # pip install tomli for Python <3.11


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def load_config(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("rb") as f:
        return tomllib.load(f)


def download_list(url: str, timeout: int = 15) -> list[str]:
    log(f"[INFO] Fetching: {url}")
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    lines = resp.text.splitlines()
    log(f"[INFO] Fetched {len(lines)} lines from {url}")
    return lines


def is_comment_or_empty(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#") or s.startswith("//") or s.startswith(";")


def extract_domain(line: str) -> str | None:
    """
    Handle common formats:
    - plain.domain.com
    - 0.0.0.0 domain.com
    - 127.0.0.1 domain.com
    - :: domain.com
    """
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
    if len(parts) == 1:
        candidate = parts[0]
    else:
        # Assume first token is IP / keyword, second is domain
        candidate = parts[1]

    candidate = candidate.strip().lower().rstrip(".")

    # Skip obvious IPs
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
        return None
    if ":" in candidate:  # crude IPv6 skip
        return None

    if not DOMAIN_RE.match(candidate):
        return None

    return candidate


def process_lines(lines: list[str]) -> set[str]:
    domains: set[str] = set()
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

    merged: set[str] = set()
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


def write_list(domains: set[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    with path.open("w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(d + "\n")
    log(f"[INFO] Wrote {len(sorted_domains)} domains to {path}")


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
        cfg = load_config(args.config)
    except Exception as e:
        log(f"[ERROR] Failed to load config: {e}")
        return 1

    lists_cfg = cfg.get("lists", {})
    output_cfg = cfg.get("output", {})

    block_urls = lists_cfg.get("block", []) or []
    allow_urls = lists_cfg.get("allow", []) or []
    regex_urls = lists_cfg.get("regex", []) or []

    block_out = Path(output_cfg.get("block", "lists/blocklist.txt"))
    allow_out = Path(output_cfg.get("allow", "lists/allowlist.txt"))
    regex_out = Path(output_cfg.get("regex", "lists/regexlist.txt"))

    log("[INFO] Starting merge")

    # Blocklist
    block_domains = merge_lists(block_urls, max_workers=args.max_workers)

    # Allowlist
    allow_domains = merge_lists(allow_urls, max_workers=args.max_workers)

    # Remove allowed domains from blocklist
    if allow_domains:
        before = len(block_domains)
        block_domains.difference_update(allow_domains)
        log(
            f"[INFO] Removed {before - len(block_domains)} domains from blocklist due to allowlist"
        )

    # Regex list (kept raw, only basic cleaning)
    regex_entries: set[str] = set()
    if regex_urls:
        for url in regex_urls:
            try:
                lines = download_list(url)
                for line in lines:
                    s = line.strip()
                    if is_comment_or_empty(s):
                        continue
                    regex_entries.add(s)
            except Exception as e:
                log(f"[WARN] Failed to fetch regex list {url}: {e}")

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
