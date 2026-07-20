# OSINT Recon Tool

A comprehensive Open Source Intelligence (OSINT) reconnaissance tool for gathering information about a target person.

## Features

- **Username Enumeration** - Check 30+ platforms for username presence
- **Email Intelligence** - Provider detection, MX records, breach checking
- **Domain Reconnaissance** - WHOIS, DNS records, IP geolocation, SSL certs
- **Phone Analysis** - Format detection and validation
- **Name Intelligence** - Name parsing and username variation generation
- **Full Recon Mode** - Automatic detection and comprehensive scanning

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/osint-recon.git
cd osint-recon
pip install -r requirements.txt
```

## Usage

### Username Enumeration
```bash
python3 recon.py -m username -t johndoe
```

### Email Intelligence
```bash
python3 recon.py -m email -t user@example.com
```

### Domain Reconnaissance
```bash
python3 recon.py -m domain -t example.com
```

### Phone Number Analysis
```bash
python3 recon.py -m phone -t +1234567890
```

### Name Intelligence
```bash
python3 recon.py -m name -t "John Doe"
```

### Full Reconnaissance
```bash
python3 recon.py -m full -t user@example.com
python3 recon.py -m full -t "John Doe" -o results
```

## Options

| Flag | Description |
|------|-------------|
| `-m, --mode` | Recon mode (username/email/domain/phone/name/full) |
| `-t, --target` | Target to investigate |
| `-o, --output` | Save results to JSON file |
| `-v, --verbose` | Enable verbose output |

## Platform Coverage

The tool checks username presence across 30+ platforms including:

- **Social Media**: Twitter, Instagram, TikTok, Reddit, YouTube
- **Developer**: GitHub, GitLab, Bitbucket, Dev.to, Medium
- **Gaming**: Steam, Twitch, Roblox, Discord
- **Professional**: LinkedIn, Fiverr, Upwork
- **Finance**: Venmo, CashApp
- **Security**: HackerOne, Bugcrowd, TryHackMe, HackTheBox

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before performing reconnaissance on any target. The author is not responsible for any misuse of this tool.

## License

MIT License
