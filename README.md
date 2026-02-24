Apophis Blocklist is a fully automated, privacy‑respecting domain blocklist generator designed for Pi‑hole, Unbound, AdGuard Home, and other DNS filtering systems. It merges multiple high‑quality threat‑intelligence feeds, validates domains using the Public Suffix List (PSL), removes invalid entries, and outputs a clean, deduplicated blocklist every day. 

Apophis uses a curated selection of third‑party blocklists focused exclusively on malware, ransomware, phishing, scams, fraud, and other security‑critical threats. It does not target advertising, tracking, or general content blocking, although some third party lists may incorporate blocking of ad / tracking services they deem to be excessive. Users are responsible for reviewing the included sources, maintaining their own allowlists, and ensuring the blocklist fits their environment and risk tolerance.
 

The goal is simple: **maximum threat coverage with minimum noise**. 

✨ Features 
- **Daily automated updates** via GitHub Actions
- **Public Suffix List (PSL) validation**
- Rejects invalid TLDs
- Rejects malformed domains - Ensures only real, resolvable domains are included
- **Parallel downloading** for fast list aggregation
- **ETag/Last‑Modified caching** to reduce bandwidth
- **Automatic diff report** showing added/removed domains
- **Clean, deduplicated output** suitable for Pi‑hole, Unbound, AGH, and DNS servers
- **Configurable sources** via `blocklistblaster.toml`

📦 Output Files 
Generated daily into the `lists/` directory: 
| File | Description | 
|------|-------------|
| `blocklist.txt` | Final merged blocklist (domains only) |
| `allowlist.txt` | Allowlist (if configured) |
| `regexlist.txt` | Regex rules (if configured) |
| `diff_report.txt` | Daily diff showing added/removed domains |
| `blocklist_previous.txt` | Snapshot used for diffing | 

⚙️ How It Works 
1. Downloads all blocklist sources defined in `blocklistblaster.toml`
2. Normalises and validates each domain: - Removes comments, IPs, wildcards, invalid characters - Converts IDNA/Punycode - Validates TLD using the **Public Suffix List**
3. Deduplicates and merges all domains
4. Applies allowlist (optional)
5. Writes final lists to `lists/`
6. Commits changes automatically if the blocklist changed 

🛠 Configuration All sources are defined in:
blocklistblaster.toml

Example:

```toml
[lists]
block = [
  "https://example.com/malware.txt",
  "https://example.com/phishing.txt"
]

allow = []
regex = []

[output]
block = "lists/blocklist.txt"
allow = "lists/allowlist.txt"
regex = "lists/regexlist.txt"
```


🔄 Automation
.github/workflows/update-blocklist.yml

Runs daily at 03:00 UTC and:

- Installs dependencies
- Runs the blocklist generator
- Commits updated lists if changes are detected

🛡 Philosophy
This project prioritises:

Accuracy — only real domains with valid public suffixes

Coverage — multiple independent threat feeds

Stability — no ABP/Adblock syntax, no noise, no junk

Transparency — daily diff reports

Privacy — no external analytics, no telemetry
