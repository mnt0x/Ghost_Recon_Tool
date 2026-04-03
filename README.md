# Ghost Recon Tool v1.0

Passive domain intelligence platform for bug bounty hunters and penetration testers.

Ghost Recon Tool is a 100% passive reconnaissance toolkit focused on collecting public intelligence from third-party services and historical archives without ever touching the target directly. It is designed for researchers who want broad domain visibility, strong no-key baseline coverage, and structured output that can be shared, reviewed, and benchmarked over time.

## Features

- Subdomain enumeration (50+ passive sources, no direct contact)
- Web archive intelligence (Wayback, CommonCrawl, Arquivo.pt)
- Email discovery
- SSL/Certificate intelligence
- IP & ASN intelligence
- CVE enrichment
- Technology detection via CNAME
- Google Dorks generation
- Cloud asset detection
- Social footprint analysis
- Reputation scoring
- Zero direct contact with target (100% passive)

## Benchmark (no API keys)

| Domain | Subdomains | Archive URLs |
| --- | ---: | ---: |
| ginandjuice.shop | 3 | 174 |
| psoe.es | 1,336 | 659,842 |
| github.com | 3,809 | 532,827 |
| dgt.es | 108 | 77,485 |
| tesla.com | 3,634 | 620,980 |
| microsoft.com | 8,131 | 509,059 |
| paypal.com | 9,965 | 286,125 |
| amazon.com | 16,764 | 40,869 |
| cloudflare.com | 4,455 | 37,729 |
| hackerone.com | 1,947 | 344,149 |

## Benchmark (with API keys)

| Domain | Subdomains | Emails | Archive URLs |
| --- | ---: | ---: | ---: |
| ginandjuice.shop | 3 | 28 | 174 |
| psoe.es | 1,482 | 17 | 659,842 |
| github.com | 15,192 | 58 | 659,547 |
| dgt.es | 162 | 47 | 56,498 |
| tesla.com | 3,762 | 70 | 620,980 |
| microsoft.com | 25,000 | 108 | 599,843 |
| paypal.com | 10,492 | 77 | 258,676 |
| amazon.com | 25,000 | 129 | 54,888 |
| cloudflare.com | 20,345 | 145 | 286,255 |
| hackerone.com | 106 | 28 | 599,031 |

## Installation

```powershell
git clone https://github.com/mnt0x/Ghost_Recon_Tool.git
cd Ghost_Recon_Tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

```bash
git clone https://github.com/mnt0x/Ghost_Recon_Tool.git
cd Ghost_Recon_Tool
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python recon.py -d example.com

# Deep mode (maximum coverage)
python recon.py -d example.com --mode deep

# With API keys
cp config.example.env config.env
# edit config.env with your keys
python recon.py -d example.com --mode deep

# Output formats
python recon.py -d example.com --output json
python recon.py -d example.com --output zip
```

## Web UI

Run the Web UI with:

```bash
python recon.py --web
```

The interface opens at `http://localhost:5000` and provides:

- Scan launcher
- Real-time progress
- Results viewer
- API key settings at `/settings`

## Scan Modes

| Mode | Purpose | Typical runtime |
| --- | --- | --- |
| fast | Quick overview for triage and smoke testing | ~5 min |
| balanced | Default mode with solid coverage and moderate runtime | ~15 min |
| deep | Maximum passive coverage and historical expansion | ~45-60 min |

## API Keys (optional, increase coverage)

- `GRT_CHAOS`: enables ProjectDiscovery Chaos subdomain coverage.
- `GRT_VIRUSTOTAL`: unlocks VirusTotal domain, URL, and certificate intelligence.
- `GRT_GITHUB_TOKEN`: GitHub token for higher-rate code and public artifact searches.
- `GRT_BEVIGIL`: enables authenticated BeVigil subdomain coverage.
- `GRT_OTX`: enables AlienVault OTX authenticated enrichment.

## Passive Sources (no API key required)

The no-key baseline relies on public, third-party data sources such as `crt.sh`, `certspotter`, `anubisdb`, `jldc`, `rapiddns`, `subdomaincenter`, `hackertarget`, `urlscan`, AlienVault OTX, Wayback CDX, CommonCrawl, Arquivo.pt, public certificate transparency feeds, historical robots and sitemap archives, archive-derived host hints, and additional passive DNS and reputation datasets where anonymous access is available.

## Legal & Ethics

This tool only queries public third-party APIs, indexes, and archives. It never contacts the target directly, does not perform active probing, and is intended for passive reconnaissance workflows. Users are responsible for ensuring they have authorization to investigate any targets they choose to analyze and for complying with local law, platform terms, and bug bounty program rules.

## Author

mnt0x
