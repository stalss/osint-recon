<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1.0-blue" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"/>
  <img src="https://img.shields.io/badge/Platforms-50+-orange" alt="Platforms"/>
  <img src="https://img.shields.io/github/stars/stalss/osint-recon?style=social" alt="Stars"/>
</p>

<h1 align="center">OSINT Recon Tool</h1>

<p align="center">
  <strong>Full-spectrum person intelligence.</strong><br/>
  Find accounts, scrape profiles, discover hobbies, friends, connections — from just a name.
</p>

---

```
  ███████╗██╗███╗   ███╗██████╗ ██╗██████╗ ███████╗
  ██╔════╝██║████╗ ████║██╔══██╗██║██╔══██╗██╔════╝
  ███████╗██║██╔████╔██║██████╔╝██║██████╔╝█████╗  
  ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║██╔══██╗██╔══╝  
  ███████║██║██║ ╚═╝ ██║██║     ██║██║  ██║███████╗
  ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
```

<br/>

## What It Does

| Module | What It Finds |
|--------|---------------|
| **Name Intel** | Real accounts across 50 platforms, hobbies, skills, work, friends, connections |
| **Username** | Existence checks on 50+ sites with false positive detection |
| **Email** | Provider, MX records, breach status, SMTP verification |
| **Domain** | WHOIS, DNS, SSL, concurrent port scan, subdomains |
| **Phone** | Format detection, country, carrier, E.164 normalization |

<br/>

## Quick Start

```bash
git clone https://github.com/stalss/osint-recon.git
cd osint-recon
pip install .
```

<br/>

## Usage

```bash
# Deep person scan — find everything from a name
osint-recon -m name -t "John Doe" --deep -v -o results

# Username enumeration
osint-recon -m username -t johndoe

# Email intelligence
osint-recon -m email -t user@example.com

# Domain recon
osint-recon -m domain -t example.com

# Phone analysis
osint-recon -m phone -t +1234567890

# Full auto-detect
osint-recon -m full -t "John Doe" -o results
```

<br/>

## Deep Scan — What It Finds

```
osint-recon -m name -t "Mannat Raj" --deep
```

```
=================================================================
  COMPLETE PERSON PROFILE: Mannat Raj
=================================================================
  Accounts found:       15
  Platforms active:     12
  Emails discovered:    2
  Known hobbies:        photography, travel, music
  Skills / Tech:        python, javascript, rust, linux
  Locations:            Mumbai, India
  Work / Education:     IIT Bombay
  Connected accounts:   8 usernames
  Connected people:     5
  Web mentions:         12
=================================================================
```

<br/>

## Options

| Flag | Description |
|------|-------------|
| `-m, --mode` | `username` `email` `domain` `phone` `name` `full` |
| `-t, --target` | Target to investigate |
| `-o, --output` | Save results to JSON (timestamped) |
| `-v, --verbose` | Verbose output |
| `-r, --rate-limit` | Seconds between requests (default: 0.5) |
| `--deep` | Full scan: emails, web search, connections |
| `--check-fp` | False positive detection before username scan |

<br/>

## Architecture

- **Data-driven platforms** — add new sites without changing code
- **Thread-safe rate limiter** — concurrent requests without races
- **User-Agent rotation** — avoids bot detection
- **Concurrent scanning** — ports, subdomains, platforms in parallel
- **Modular design** — each module is independent and testable

```
osint-recon/
├── osint_recon/
│   ├── cli.py              # CLI entry point
│   ├── http_client.py      # Thread-safe HTTP with rate limiting
│   ├── platforms.py        # 50+ platform definitions
│   └── modules/
│       ├── name.py         # Deep person OSINT
│       ├── username.py     # Username enumeration
│       ├── email.py        # Email intelligence
│       ├── domain.py       # Domain recon (concurrent)
│       └── phone.py        # Phone analysis
├── tests/test_recon.py     # 43 tests
├── pyproject.toml
├── Makefile
├── LICENSE
└── README.md
```

<br/>

## Platform Coverage

| Category | Platforms |
|----------|-----------|
| Social | Twitter/X, Instagram, Facebook, TikTok, Reddit, YouTube, Telegram, Bluesky, Mastodon |
| Developer | GitHub, GitLab, Bitbucket, Dev.to, Medium, Replit, npm, PyPI, Docker Hub |
| Gaming | Steam, Twitch, Roblox, Discord, Minecraft |
| Professional | LinkedIn, Fiverr, Upwork, Behance, Dribbble |
| Security | HackerOne, Bugcrowd, TryHackMe, HackTheBox, RootMe |

<br/>

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

<br/>

## Building

```bash
make build          # Current OS
make build-linux    # Linux
make build-macos    # macOS
make build-windows  # Windows (.exe)
```

<br/>

## Disclaimer

For educational and authorized security testing only. Obtain proper authorization before scanning any target.

<br/>

## License

MIT License — see [LICENSE](LICENSE)
