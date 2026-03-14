
📛 Apophis Blocklist — Resilient, Curated, Daily‑Updated Threat Intelligence <br>
Apophis Blocklist is a high‑quality, aggressively curated domain blocklist designed for Pi‑hole, Unbound, AdGuard Home, and other DNS‑based filtering systems.

It aggregates multiple reputable threat‑intelligence feeds, normalises and validates domains, removes false positives, and produces a clean, deduplicated blocklist updated automatically every day.

This project is engineered for reliability, safety, and zero‑regression behaviour — meaning the blocklist will never shrink due to upstream outages or malformed feeds.

While the focus is malware, scams / fraud and phishing third party blocklists may also incorporate advertising which have been previously abused to deliver malware or legitamate services that use computing resources which maybe hijacked to run without a users knowledge. There may also be instances of advertising blocking where a list manager feels the platform is over intrusive on a users privacy. 

<br>

✨ Key Features<br>
✔ Resilient Fetching
Each source list is downloaded with:

- Retry logic
- Exponential backoff + jitter
- Content validation (rejects empty/HTML/JSON/error pages)
- Automatic fallback to last‑known‑good cached content

This prevents upstream failures (e.g., TR‑CERT empty responses) from poisoning the blocklist.
<br>
<br>
✔ Domain Normalisation & Validation
Every entry is processed through:

- IDNA conversion
- Public Suffix List (PSL) validation
- Hostfile parsing (0.0.0.0 domain)
- URL parsing (OpenPhish, URLHaus, etc.)
- Strict domain regex validation
- Removal of IPs, invalid TLDs, and malformed entries
<br>

✔ Intelligent Caching <br>
The updater stores:

- ETag / Last‑Modified headers
- Last‑known‑good content
- Previous blocklist snapshot
<br>
This enables:
<br>
- Conditional GETs (faster, lighter updates) <br>
- Safe fallback when a source misbehaves <br>
- Accurate diff reports
<br>
<br>
✔ Parallel Processing
All lists are fetched and processed concurrently for speed.
<br>
<br>
✔ Allowlist & Regex Support
The updater supports:

- allow lists (remove domains from blocklist)
- regex lists (for Pi‑hole regex filtering)

<br>
✔ Daily Automated Updates
A GitHub Actions workflow:

- Restores cache
- Runs the updater
- Generates diff reports
- Commits only when changes exist
<br>

✔ Easy List Management
- Configurable sources via `blocklistblaster.toml`
  
<br>
📁 Repository Structure
<br>
.<br>
├── blocklistblaster.py        # Main updater script (resilient version)

├── blocklistblaster.toml      # Configuration file

├── cache/                     # ETag + content cache (persisted via Actions)

├── data/public_suffix_list.dat

├── lists/

│   ├── blocklist.txt          # Final merged blocklist

│   ├── allowlist.txt          # Allowlist output (if used)

│   ├── regexlist.txt          # Regex output (if used)

│   ├── blocklist_previous.txt # Snapshot for diffing

│   └── diff_report.txt        # Daily diff report

└── .github/workflows/update.yml


<br>
<br>

⚙ Configuration (blocklistblaster.toml)

```
[lists]
block = [
  "https://blocklistproject.github.io/Lists/malware.txt",
  "https://openphish.com/feed.txt",
  "https://raw.githubusercontent.com/cenk/trcert-malware/main/trcert-domains.txt",
  ...
]

allow = []
regex = []

[output]
block = "lists/blocklist.txt"
allow = "lists/allowlist.txt"
regex = "lists/regexlist.txt"
```

<br>
🚀 Running Locally

```
pip install requests publicsuffix2 idna tomli
python3 blocklistblaster.py -c blocklistblaster.toml
```
<br>

🤖 GitHub Actions Automation
The workflow:

-Restores cache
- Runs the updater
- Saves updated cache
- Commits only if blocklist changed

This ensures stable, predictable daily updates.

<br>
🛡 Reliability Guarantees 
<br>
Apophis Blocklist is designed so that:

- No upstream outage can shrink the blocklist
- No malformed feed can overwrite good data
- No empty or HTML/JSON error page is ever accepted
- Every domain is validated against the Public Suffix List
- Every update is diffed against the previous version

This makes it suitable for production Pi‑hole/Unbound deployments where stability matters.

