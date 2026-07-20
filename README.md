# OSINT Recon Tool

A comprehensive Open Source Intelligence (OSINT) reconnaissance tool for gathering information about a target person. Install it as a system-wide command or build standalone binaries.

## Features

- **Username Enumeration** - Check 40+ platforms for username presence
- **Email Intelligence** - Provider detection, MX records, breach checking
- **Domain Reconnaissance** - WHOIS, DNS records, IP geolocation, SSL certs
- **Phone Analysis** - Format detection and validation
- **Name Intelligence** - Name parsing and username variation generation
- **Full Recon Mode** - Automatic detection and comprehensive scanning

## Installation

### Option 1: Install as a command (recommended)

```bash
git clone https://github.com/stalss/osint-recon.git
cd osint-recon
pip install .
```

This installs `osint-recon` as a system-wide command.

### Option 2: Install in development mode

```bash
pip install -e ".[dev]"
```

### Option 3: Build a standalone binary

```bash
make build
# Binary will be at: dist/osint-recon
```

Or manually:
```bash
pip install pyinstaller
pyinstaller --onefile --name osint-recon osint_recon/cli.py
```

## Usage

After installation, use it directly as a command:

```bash
# Username enumeration
osint-recon -m username -t johndoe

# Email intelligence
osint-recon -m email -t user@example.com

# Domain reconnaissance
osint-recon -m domain -t example.com

# Phone number analysis
osint-recon -m phone -t +1234567890

# Name intelligence
osint-recon -m name -t "John Doe"

# Full reconnaissance (auto-detects target type)
osint-recon -m full -t user@example.com
osint-recon -m full -t "John Doe" -o results
```

## Options

| Flag | Description |
|------|-------------|
| `-m, --mode` | Recon mode (username/email/domain/phone/name/full) |
| `-t, --target` | Target to investigate |
| `-o, --output` | Save results to JSON file (prefix) |
| `-v, --verbose` | Enable verbose output |
| `--version` | Show version |

## Building Binaries

Use the Makefile for cross-platform builds:

```bash
make build          # Build for current OS
make build-linux    # Linux binary
make build-macos    # macOS binary
make build-windows  # Windows binary (.exe)
make clean          # Clean build artifacts
```

## Platform Coverage

The tool checks username presence across 40+ platforms including:

- **Social Media**: Twitter/X, Instagram, TikTok, Reddit, YouTube, Facebook, Mastodon, Bluesky
- **Developer**: GitHub, GitLab, Bitbucket, Dev.to, Medium, Replit, npm, PyPI
- **Gaming**: Steam, Twitch, Roblox, Discord
- **Professional**: LinkedIn, Fiverr, Upwork
- **Finance**: Venmo, CashApp
- **Security**: HackerOne, Bugcrowd, TryHackMe, HackTheBox
- **Other**: Telegram, Docker Hub, Pastebin, Gravatar

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before performing reconnaissance on any target. The author is not responsible for any misuse of this tool.

## License

MIT License
