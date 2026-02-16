BlocklistBlaster (Python Edition) BlocklistBlaster is a lightweight, fast, and fully automated blocklist aggregator designed for Pi-hole, Unbound, and other DNS-based filtering systems. It downloads multiple blocklists, cleans and validates entries, removes duplicates, applies allowlists, and publishes a single curated blocklist. 

This repository automatically updates **daily** using GitHub Actions, ensuring the blocklist is always fresh. 

🚀 Features 
- Merge multiple blocklists into one curated list
- Automatic deduplication
- Domain validation (filters out invalid entries, IPs, comments, garbage lines)
- Allowlist support
- Regex list support
- Parallel downloads for speed
- Daily automatic updates via GitHub Actions
- Clean TOML configuration
- Simple, readable Python code 

📦 How to Use This Blocklist Pi-hole users can subscribe directly using the raw URL:
https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist.txt
Add this URL in:

Pi-hole Admin → Group Management → Adlists → Add URL

Then run:
pihole -g

🛠 Configuration

The script uses a TOML config file
