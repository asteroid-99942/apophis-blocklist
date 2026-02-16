Apophis Blocklist — Automated Daily DNS Blocklist Generator

This is a handsoff project.

Apophis Blocklist is a fast, reliable, and fully automated DNS blocklist generator designed for Pi‑hole, Unbound, AdGuard Home, and other DNS‑based filtering systems.

It aggregates multiple third‑party blocklists, cleans and validates entries, removes duplicates, applies allowlists, normalises domains, and publishes a single curated blocklist — updated **daily** via GitHub Actions.

The blocklist is not adblocking but curates lists for 
- malware
- phishing
- fake / scams

This project is built for stability, transparency, and long‑term maintainability.



🚀 Key Features

✔ Daily automatic updates
A GitHub Actions workflow regenerates the blocklist every day at 03:00 UTC and commits the results.

✔ Strong domain validation
The generator rejects:
- malformed domains  
- invalid TLDs  
- domains with underscores  
- IP addresses  
- single‑label hostnames  
- invalid punycode  

✔ Domain normalisation
All domains are normalised consistently:
- lowercase  
- IDN → punycode  
- strip `www.`  
- strip `*.`  
- remove trailing slashes  

✔ ETag / Last‑Modified caching
Upstream lists are only re‑downloaded when they change.  
This reduces bandwidth, speeds up updates, and avoids unnecessary failures.

✔ Diff reporting
Each update includes:
- domains added  
- domains removed  
- total domain count  
- full diff report in `lists/diff_report.txt`

✔ Allowlist & regex support
Allowlisted domains are removed from the final blocklist.  
Regex entries are kept in a separate file.



📦 How to Use This Blocklist

Pi‑hole users can subscribe directly using the raw URL:
https://github.com/asteroid-99942/apophis-blocklist/raw/refs/heads/main/lists/blocklist.txt

Add this URL in:

**Pi‑hole Admin → Group Management → Adlists → Add URL**

Then update gravity:


🛠 Configuration

The generator uses a TOML configuration file:

Example:

```toml
[lists]
block = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  ]

allow = [
  # Add allowlist URLs here
]

regex = [
  # Add regex list URLs here
]

[output]
block = "lists/blocklist.txt"
allow = "lists/allowlist.txt"
regex = "lists/regexlist.txt"
