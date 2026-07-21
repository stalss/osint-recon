# OSINT Recon Tool

A comprehensive Open Source Intelligence (OSINT) tool for gathering information about a target person, domain, email, or phone number.

**Version:** 2.1.0  
**Inspired by:** Sherlock, theHarvester, SpiderFoot, Recon-ng, Maltego

## Features

- **Username Enumeration** — Check 50+ platforms for username presence with false positive detection
- **Email Intelligence** — Provider detection, MX records, SPF/DMARC, breach checking
- **Domain Reconnaissance** — WHOIS, DNS records, IP geolocation, SSL certs, concurrent port scan, subdomain discovery
- **Phone Analysis** — Format detection, country identification, E.164 normalization
- **Name Intelligence** — Real person OSINT: find accounts, scrape profiles, discover hobbies, friends, connections
- **Full Recon Mode** — Automatic target type detection and comprehensive scanning

## Installation

### Option 1: Install as a command (recommended)

```bash
git clone https://github.com/stalss/osint-recon.git
cd osint-recon
pip install .
```

### Option 2: Development mode

```bash
pip install -e ".[dev]"
```

### Option 3: Build standalone binary

```bash
make build
# Binary: dist/osint-recon
```

## Usage

```bash
# Username enumeration across 50+ platforms
osint-recon -m username -t johndoe

# Email intelligence
osint-recon -m email -t user@example.com

# Domain reconnaissance
osint-recon -m domain -t example.com

# Phone number analysis
osint-recon -m phone -t +1234567890

# Name intelligence — find accounts, hobbies, connections
osint-recon -m name -t "John Doe"

# Deep scan — verify emails, search web, discover friends
osint-recon -m name -t "John Doe" --deep

# Full reconnaissance (auto-detects target type)
osint-recon -m full -t user@example.com
osint-recon -m full -t "John Doe" -o results

# With verbose output and rate limiting
osint-recon -m username -t johndoe -v -r 1.0

# Check for false positives before scanning
osint-recon -m username -t johndoe --check-fp
```

## Options

| Flag | Description |
|------|-------------|
| `-m, --mode` | Recon mode (username/email/domain/phone/name/full) |
| `-t, --target` | Target to investigate |
| `-o, --output` | Save results to JSON file (prefix) |
| `-v, --verbose` | Enable verbose output |
| `-r, --rate-limit` | Seconds between requests (default: 0.5) |
| `--check-fp` | Check for false positives before username scan |
| `--deep` | Deep scan: verify emails, search web, discover connections |
| `--version` | Show version |

## Name Intelligence — What It Finds

The `--deep` scan on a name like `"Mannat Raj"` will:

```
1. Generate ranked username variations (mannatraj, mannat.raj, mraj, etc.)
2. Check each across 50 platforms (social, dev, gaming, professional)
3. Scrape found profiles for:
   - Bio / description
   - Hobbies & interests (extracted from bio text)
   - Work & education
   - Skills & technologies
   - Connected accounts / friends
   - Public email addresses
4. Verify email patterns via SMTP
5. Search DuckDuckGo for public mentions
6. Discover connected people from profile pages
```

**Example output:**
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

## Architecture

The tool follows best practices from established OSINT tools:

- **Data-driven platform definitions** (like Sherlock's data.json)
- **Rate limiting with jitter** (prevents detection)
- **User-Agent rotation** (avoids bot detection)
- **False positive detection** (SpiderFoot-style random probe verification)
- **Concurrent requests** (ThreadPoolExecutor for speed)
- **Thread-safe rate limiter** (threading.Lock for concurrent safety)
- **Modular architecture** (easy to add new modules)

### Project Structure

```
osint-recon/
├── osint_recon/
│   ├── __init__.py         # Package metadata
│   ├── __main__.py         # python -m support
│   ├── cli.py              # CLI entry point
│   ├── banner.py           # ASCII art and headers
│   ├── colors.py           # Terminal colors
│   ├── http_client.py      # HTTP with rate limiting (thread-safe)
│   ├── platforms.py        # Platform definitions
│   └── modules/
│       ├── username.py     # Username enumeration
│       ├── email.py        # Email intelligence
│       ├── domain.py       # Domain recon (concurrent)
│       ├── phone.py        # Phone analysis
│       └── name.py         # Name intelligence (deep OSINT)
├── tests/
│   └── test_recon.py       # 43 tests
├── pyproject.toml          # Package config
├── Makefile                # Build automation
├── LICENSE                 # MIT License
└── README.md
```

## Platform Coverage

Username enumeration checks 50+ platforms across categories:

- **Social Media**: Twitter/X, Instagram, Facebook, TikTok, Reddit, YouTube, Telegram, Bluesky, Mastodon
- **Developer**: GitHub, GitLab, Bitbucket, Dev.to, Medium, Replit, npm, PyPI, Docker Hub
- **Gaming**: Steam, Twitch, Roblox, Discord, Minecraft
- **Professional**: LinkedIn, Fiverr, Upwork, Behance, Dribbble
- **Finance**: Venmo, CashApp
- **Security**: HackerOne, Bugcrowd, TryHackMe, HackTheBox, RootMe
- **Other**: Gravatar, Pastebin, Etsy, eBay, SoundCloud

## Building Binaries

```bash
make build          # Build for current OS
make build-linux    # Linux binary
make build-macos    # macOS binary
make build-windows  # Windows binary (.exe)
make clean          # Clean build artifacts
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run with Python directly
python -m osint_recon -m username -t testuser
```

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before performing reconnaissance on any target. The author is not responsible for any misuse of this tool.

## License

MIT License
