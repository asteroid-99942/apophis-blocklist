
📛 Apophis Blocklist Blaster
<br>
A fast, resilient, and highly accurate blocklist aggregation engine designed for Pi‑hole, AdGuard Home, DNS sinkholes, and security tooling.
It merges dozens of third‑party blocklists, extracts valid domains from mixed formats, applies allowlists, and produces clean, deduplicated output.

While the focus is malware, scams / fraud and phishing, third party blocklists may also incorporate advertising blocking. These are generally ad programs / hosts which have been previously abused to deliver malware. These can be legitimate services that due to past abuse and potential for future abuse are deemed by list managers to be worth blocking as a precaution. There may also be instances of advertising / telemetry blocking where a list manager feels the advertising platform is over intrusive on a user's privacy or is not transparent enough or data collection is noneconsensual. General adblocking is not supported since controlling ad blocking locally is often better to ensure websites function correctly. 

At the time of writing the list has over 3 million entries compiled from third party blocklists. A big thank you to all those contributors who share their lists with the community.  

In PiHole add the following URL to your list manager.
https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/output/hosts.txt

Note: This is an A.I written project, which has been developed with human input on functions and script behaviour. The intention was to dedup and consolidate malware blocklists into one efficient list. 
<br>

✨ Features
-Hybrid TLD Validation  
Accepts domains if:
- The Public Suffix List (PSL) recognises the TLD or
- The TLD is alphabetic and 2–10 characters
  This captures malware domains using fake or newly‑created TLDs while still rejecting garbage.

-Advanced domain extraction  
Extracts domains from:
- Bare domain lists
- Hosts files (0.0.0.0 example.com)
- URLs anywhere in a line
- Adblock syntax (||domain^)
- Wildcards (*.example.com)
- Multi‑domain lines
- IDNA / punycode

-Resilient downloading
- ETag + Last‑Modified caching
- Exponential backoff
- Automatic fallback to cached content
- HTML/JSON error‑page detection

-Parallel processing  
- Downloads and parses lists concurrently for speed.

-Diff reporting  
Generates a daily report showing:
- Added domains
- Removed domains
- Total domain count

-Clean output  
Produces:
- blocklist.txt
- allowlist.txt
- regexlist.txt
- diff_report.txt
- blocklist_previous.txt

📦 Requirements
-Python 3.10+
-Dependencies:
- requests
- idna
- publicsuffix2
- tomli (Python <3.11)

Install dependencies:
```
bash
pip install requests idna publicsuffix2 tomli
```

📁 Directory Structure
Code
.
├── blocklistblaster.py <br>
├── blocklistblaster.toml <br>
├── data/ <br>
│   └── public_suffix_list.dat <br>
├── cache/ <br>
│   └── metadata.json   (auto‑generated) <br>
└── lists/ <br>
    ├── blocklist.txt <br>
    ├── allowlist.txt <br>
    ├── regexlist.txt <br>
    ├── diff_report.txt <br>
    └── blocklist_previous.txt <br>
    
⚙️ Configuration (TOML)
Your configuration file (blocklistblaster.toml) controls which lists are merged.

Example:
```
toml
[lists]
block = [
    "https://example.com/block1.txt",
    "https://example.com/block2.txt"
]

allow = [
    "https://example.com/allowlist.txt"
]

regex = [
    "https://example.com/regexlist.txt"
]

[output]
block = "lists/blocklist.txt"
allow = "lists/allowlist.txt"
regex = "lists/regexlist.txt"
```

🧠 Hybrid TLD Validation (Why It Matters)
Traditional PSL‑only validation rejects:
- Malware domains using fake TLDs
- Newly created TLDs not yet in the PSL
- Internal botnet C2 domains
- Typosquatted TLDs

Hybrid mode fixes this by allowing:
- Any PSL‑valid domain
- Any domain with a TLD matching:
-- Alphabetic
-- 2–10 characters

This means domains like:

```
||0-4-zoll-in-cm.klimafuechse.de^
```
are correctly extracted as:

```
0-4-zoll-in-cm.klimafuechse.de
```

🔍 How Domain Extraction Works
The extractor handles:

URLs  
https://malicious.com/path → malicious.com

Hosts format  
0.0.0.0 badsite.net → badsite.net

Adblock syntax  
||phishingsite.org^ → phishingsite.org

Wildcards  
*.tracker.com → tracker.com

Multiple domains per line  
0.0.0.0 a.com b.net c.org → all three extracted

IDNA / punycode  
xn--bcher-kva.example → normalised 
<br>

🚀 Running the Script
```
bash
python3 blocklistblaster.py -c blocklistblaster.toml
```

Optional:

```
bash
python3 blocklistblaster.py --max-workers 16
```

📤 Output Files
File	Description
lists/blocklist.txt	Final merged blocklist
lists/allowlist.txt	Combined allowlist
lists/regexlist.txt	Regex rules from sources
lists/diff_report.txt	Added/removed domains since last run
lists/blocklist_previous.txt	Snapshot of previous blocklist


🤖 GitHub Actions Integration
This script is CI‑friendly:
- Automatically creates missing directories
- Uses safe atomic writes
- Handles cold‑start cache states
- Works reliably on ephemeral runners


🛠️ Troubleshooting
Cache errors
If you ever see:

```
cache/metadata.json is corrupted
```

Just delete the file — it will be regenerated automatically.

PSL missing
Ensure:

```
data/public_suffix_list.dat
```
exists and is up to date.














