#!/usr/bin/env python3
"""
OSINT Recon Tool - Full reconnaissance on a target person
Focuses on Open Source Intelligence gathering
"""

import argparse
import json
import sys
import os
import re
import hashlib
import socket
import ssl
import whois
import dns.resolver
import requests
import time
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

__version__ = "1.0.0"
__author__ = "OSINT Recon Tool"

class Colors:
    HEADER = Fore.BLUE if hasattr(Fore, 'BLUE') else ''
    OKGREEN = Fore.GREEN if hasattr(Fore, 'GREEN') else ''
    WARNING = Fore.YELLOW if hasattr(Fore, 'YELLOW') else ''
    FAIL = Fore.RED if hasattr(Fore, 'RED') else ''
    CYAN = Fore.CYAN if hasattr(Fore, 'CYAN') else ''
    ENDC = Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''
    BOLD = Style.BRIGHT if hasattr(Style, 'BRIGHT') else ''

def banner():
    print(f"""{Colors.HEADER}{Colors.BOLD}
    ███████╗██╗███╗   ███╗██████╗ ██╗██████╗ ███████╗
    ██╔════╝██║████╗ ████║██╔══██╗██║██╔══██╗██╔════╝
    ███████╗██║██╔████╔██║██████╔╝██║██████╔╝█████╗  
    ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║██╔══██╗██╔══╝  
    ███████║██║██║ ╚═╝ ██║██║     ██║██║  ██║███████╗
    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
    {Colors.ENDC}{Colors.WARNING}    OSINT Recon Tool v{__version__} - Full Person Recon
    {Colors.ENDC}""")


class UsernameEnumerator:
    """Enumerate usernames across various platforms"""

    PLATFORMS = {
        "github": "https://github.com/{}",
        "twitter": "https://twitter.com/{}",
        "instagram": "https://www.instagram.com/{}/",
        "linkedin": "https://www.linkedin.com/in/{}",
        "reddit": "https://www.reddit.com/user/{}",
        "youtube": "https://www.youtube.com/@{}",
        "tiktok": "https://www.tiktok.com/@{}",
        "pinterest": "https://www.pinterest.com/{}/",
        "tumblr": "https://{}.tumblr.com",
        "medium": "https://medium.com/@{}",
        "devto": "https://dev.to/{}",
        "gitlab": "https://gitlab.com/{}",
        "bitbucket": "https://bitbucket.org/{}/",
        "keybase": "https://keybase.io/{}",
        "hackerone": "https://hackerone.com/{}",
        "bugcrowd": "https://bugcrowd.com/{}",
        "tryhackme": "https://tryhackme.com/p/{}",
        "hackthebox": "https://app.hackthebox.com/profile/{}",
        "venmo": "https://venmo.com/{}",
        "cashapp": "https://cash.app/${}",
        "roblox": "https://www.roblox.com/user.aspx?username={}",
        "steam": "https://steamcommunity.com/id/{}",
        "twitch": "https://www.twitch.tv/{}",
        "soundcloud": "https://soundcloud.com/{}",
        "flickr": "https://www.flickr.com/people/{}",
        "behance": "https://www.behance.net/{}",
        "dribbble": "https://dribbble.com/{}",
        "etsy": "https://www.etsy.com/people/{}",
        "ebay": "https://www.ebay.com/usr/{}",
        "gravatar": "https://en.gravatar.com/{}",
        "aboutme": "https://about.me/{}",
        "fiverr": "https://www.fiverr.com/{}",
        "upwork": "https://www.upwork.com/freelancers/{}",
        "discord": "https://discord.com/users/{}",
    }

    def __init__(self, username, verbose=False):
        self.username = username
        self.verbose = verbose
        self.found = []
        self.errors = []

    def check_platform(self, platform, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                return (platform, url, True)
            elif response.status_code == 404:
                return (platform, url, False)
            else:
                return (platform, url, None)
        except requests.RequestException:
            return (platform, url, None)

    def enumerate(self):
        print(f"\n{Colors.OKGREEN}[*] Username Enumeration: {self.username}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Checking {len(self.PLATFORMS)} platforms...{Colors.ENDC}\n")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.check_platform, platform, url.format(self.username)): platform
                for platform, url in self.PLATFORMS.items()
            }
            for future in as_completed(futures):
                platform, url, exists = future.result()
                if exists is True:
                    self.found.append({"platform": platform, "url": url})
                    print(f"  {Colors.OKGREEN}[+] {platform:15s} : {url}{Colors.ENDC}")
                elif exists is None and self.verbose:
                    print(f"  {Colors.WARNING}[~] {platform:15s} : Unable to verify{Colors.ENDC}")

        return self.found


class EmailOSINT:
    """Gather intelligence from email addresses"""

    def __init__(self, email, verbose=False):
        self.email = email
        self.verbose = verbose
        self.results = {}

    def get_email_provider(self):
        domain = self.email.split('@')[1]
        providers = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'outlook.com': 'Microsoft Outlook',
            'hotmail.com': 'Microsoft Hotmail',
            'protonmail.com': 'ProtonMail (Encrypted)',
            'proton.me': 'ProtonMail (Encrypted)',
            'icloud.com': 'Apple iCloud',
            'aol.com': 'AOL Mail',
            'zoho.com': 'Zoho Mail',
            'yandex.com': 'Yandex Mail',
            'mail.com': 'Mail.com',
            'gmx.com': 'GMX Mail',
            'tutanota.com': 'Tutanota (Encrypted)',
            'tuta.io': 'Tutanota (Encrypted)',
            'fastmail.com': 'Fastmail',
            'hushmail.com': 'Hushmail (Encrypted)',
        }
        return providers.get(domain, f'Custom/Unknown ({domain})')

    def check_breach(self):
        try:
            sha1_hash = hashlib.sha1(self.email.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                hashes = {line.split(':')[0]: int(line.split(':')[1]) for line in response.text.splitlines()}
                suffix = sha1_hash[5:]
                if suffix in hashes:
                    return {"found": True, "count": hashes[suffix]}
        except Exception:
            pass
        return {"found": False, "count": 0}

    def validate_email(self):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, self.email))

    def check_mx_records(self):
        domain = self.email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(record.exchange) for record in mx_records]
        except Exception:
            return []

    def gather_intel(self):
        print(f"\n{Colors.OKGREEN}[*] Email Intelligence: {self.email}{Colors.ENDC}\n")

        if not self.validate_email():
            print(f"  {Colors.FAIL}[!] Invalid email format{Colors.ENDC}")
            return self.results

        provider = self.get_email_provider()
        print(f"  {Colors.CYAN}[*] Provider    : {provider}{Colors.ENDC}")

        mx_records = self.check_mx_records()
        if mx_records:
            print(f"  {Colors.CYAN}[*] MX Records  : {', '.join(mx_records[:3])}{Colors.ENDC}")
            self.results['mx_records'] = mx_records

        print(f"  {Colors.CYAN}[*] Checking breach databases...{Colors.ENDC}")
        breach = self.check_breach()
        if breach['found']:
            print(f"  {Colors.FAIL}[!] Found in breach: {breach['count']} times{Colors.ENDC}")
        else:
            print(f"  {Colors.OKGREEN}[+] Not found in known breach databases{Colors.ENDC}")
        self.results['breach'] = breach

        domain = self.email.split('@')[1]
        try:
            w = whois.whois(domain)
            if w.get('domain_name'):
                print(f"  {Colors.CYAN}[*] Domain Reg  : {w.get('registrar', 'Unknown')}{Colors.ENDC}")
                print(f"  {Colors.CYAN}[*] Created     : {w.get('creation_date', 'Unknown')}{Colors.ENDC}")
                self.results['domain_whois'] = {
                    'registrar': str(w.get('registrar', 'Unknown')),
                    'creation_date': str(w.get('creation_date', 'Unknown')),
                }
        except Exception:
            pass

        return self.results


class DomainRecon:
    """Domain and IP reconnaissance"""

    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = {}

    def get_whois(self):
        try:
            w = whois.whois(self.target)
            return {
                'domain_name': w.get('domain_name', 'N/A'),
                'registrar': w.get('registrar', 'N/A'),
                'creation_date': str(w.get('creation_date', 'N/A')),
                'expiration_date': str(w.get('expiration_date', 'N/A')),
                'name_servers': w.get('name_servers', []),
                'org': w.get('org', 'N/A'),
                'country': w.get('country', 'N/A'),
                'emails': w.get('emails', []),
            }
        except Exception as e:
            return {'error': str(e)}

    def get_dns_records(self):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.target, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        return records

    def get_ip_info(self):
        try:
            ip = socket.gethostbyname(self.target)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {}

    def get_ssl_cert(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'serial_number': cert.get('serial_number', 'N/A'),
                        'not_before': cert.get('notBefore', 'N/A'),
                        'not_after': cert.get('notAfter', 'N/A'),
                        'san': [x[1] for x in cert.get('subjectAltName', [])],
                    }
        except Exception:
            return {}

    def recon(self):
        print(f"\n{Colors.OKGREEN}[*] Domain Reconnaissance: {self.target}{Colors.ENDC}\n")

        print(f"  {Colors.CYAN}[*] Performing WHOIS lookup...{Colors.ENDC}")
        whois_data = self.get_whois()
        self.results['whois'] = whois_data
        if 'error' not in whois_data:
            print(f"      Registrar  : {whois_data.get('registrar', 'N/A')}")
            print(f"      Created    : {whois_data.get('creation_date', 'N/A')}")
            print(f"      Expires    : {whois_data.get('expiration_date', 'N/A')}")
            print(f"      Org        : {whois_data.get('org', 'N/A')}")
            print(f"      Country    : {whois_data.get('country', 'N/A')}")
            ns = whois_data.get('name_servers', [])
            if ns:
                print(f"      Name Svr  : {', '.join(ns[:3])}")

        print(f"\n  {Colors.CYAN}[*] DNS Records:{Colors.ENDC}")
        dns_records = self.get_dns_records()
        self.results['dns'] = dns_records
        for rtype, values in dns_records.items():
            print(f"      {rtype:8s}: {', '.join(values[:3])}")

        print(f"\n  {Colors.CYAN}[*] IP Geolocation:{Colors.ENDC}")
        ip_info = self.get_ip_info()
        self.results['ip_info'] = ip_info
        if ip_info:
            print(f"      IP        : {ip_info.get('query', 'N/A')}")
            print(f"      Location  : {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}")
            print(f"      ISP       : {ip_info.get('isp', 'N/A')}")
            print(f"      Org       : {ip_info.get('org', 'N/A')}")
            print(f"      AS        : {ip_info.get('as', 'N/A')}")

        print(f"\n  {Colors.CYAN}[*] SSL Certificate:{Colors.ENDC}")
        ssl_info = self.get_ssl_cert()
        self.results['ssl'] = ssl_info
        if ssl_info:
            issuer = ssl_info.get('issuer', {})
            print(f"      Issuer    : {issuer.get('organizationName', 'N/A')}")
            print(f"      Valid     : {ssl_info.get('not_before', 'N/A')} to {ssl_info.get('not_after', 'N/A')}")
            san = ssl_info.get('san', [])
            if san:
                print(f"      SANs      : {', '.join(san[:5])}")

        return self.results


class PhoneOSINT:
    """Phone number intelligence"""

    def __init__(self, phone, verbose=False):
        self.phone = phone
        self.verbose = verbose
        self.results = {}

    def analyze(self):
        print(f"\n{Colors.OKGREEN}[*] Phone Number Intelligence: {self.phone}{Colors.ENDC}\n")

        cleaned = re.sub(r'[^\d+]', '', self.phone)

        if cleaned.startswith('+'):
            print(f"  {Colors.CYAN}[*] International format detected{Colors.ENDC}")
            country_code = cleaned[1:3] if len(cleaned) > 3 else cleaned[1:]
            print(f"  {Colors.CYAN}[*] Country code: +{country_code}{Colors.ENDC}")
        else:
            print(f"  {Colors.CYAN}[*] Local format detected{Colors.ENDC}")

        number_digits = re.sub(r'[^\d]', '', self.phone)
        print(f"  {Colors.CYAN}[*] Digits only: {number_digits}{Colors.ENDC}")
        print(f"  {Colors.CYAN}[*] Length: {len(number_digits)} digits{Colors.ENDC}")

        if len(number_digits) == 10:
            print(f"  {Colors.CYAN}[*] Format: Likely US/Canada number{Colors.ENDC}")
        elif len(number_digits) == 11 and number_digits.startswith('1'):
            print(f"  {Colors.CYAN}[*] Format: US/Canada with country code{Colors.ENDC}")

        self.results = {
            'original': self.phone,
            'cleaned': cleaned,
            'digits': number_digits,
            'length': len(number_digits),
        }

        return self.results


class NameOSINT:
    """Name-based intelligence gathering"""

    def __init__(self, name, verbose=False):
        self.name = name
        self.verbose = verbose
        self.results = {}

    def analyze(self):
        print(f"\n{Colors.OKGREEN}[*] Name Intelligence: {self.name}{Colors.ENDC}\n")

        parts = self.name.strip().split()
        if len(parts) >= 2:
            first_name = parts[0]
            last_name = parts[-1]
            middle_names = parts[1:-1] if len(parts) > 2 else []

            print(f"  {Colors.CYAN}[*] First Name : {first_name}{Colors.ENDC}")
            if middle_names:
                print(f"  {Colors.CYAN}[*] Middle Name: {' '.join(middle_names)}{Colors.ENDC}")
            print(f"  {Colors.CYAN}[*] Last Name  : {last_name}{Colors.ENDC}")

            self.results['first_name'] = first_name
            self.results['last_name'] = last_name
            self.results['middle_names'] = middle_names

            username_variations = [
                f"{first_name.lower()}{last_name.lower()}",
                f"{first_name.lower()}.{last_name.lower()}",
                f"{first_name.lower()}_{last_name.lower()}",
                f"{first_name[0].lower()}{last_name.lower()}",
                f"{first_name.lower()}{last_name[0].lower()}",
                f"{last_name.lower()}{first_name.lower()}",
                f"{first_name.lower()}{last_name.lower()}1",
                f"{first_name.lower()}_{last_name.lower()}1",
            ]

            print(f"\n  {Colors.CYAN}[*] Suggested username variations:{Colors.ENDC}")
            for i, variation in enumerate(username_variations, 1):
                print(f"      {i}. {variation}")
            self.results['username_variations'] = username_variations

        else:
            print(f"  {Colors.WARNING}[*] Single name detected - limited analysis{Colors.ENDC}")
            self.results['single_name'] = self.name

        return self.results


class ReconTool:
    """Main reconnaissance orchestrator"""

    def __init__(self):
        self.results = {}
        self.verbose = False

    def save_results(self, filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{filename}_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"\n{Colors.OKGREEN}[+] Results saved to: {output_file}{Colors.ENDC}")
        return output_file

    def run(self, args):
        banner()

        if args.output:
            self.results['metadata'] = {
                'tool': 'OSINT Recon Tool',
                'version': __version__,
                'timestamp': datetime.now().isoformat(),
                'target': args.target,
            }

        if args.mode == 'username':
            enumerator = UsernameEnumerator(args.target, self.verbose)
            self.results['username_enum'] = enumerator.enumerate()

        elif args.mode == 'email':
            email_osint = EmailOSINT(args.target, self.verbose)
            self.results['email_intel'] = email_osint.gather_intel()

        elif args.mode == 'domain':
            domain_recon = DomainRecon(args.target, self.verbose)
            self.results['domain_recon'] = domain_recon.recon()

        elif args.mode == 'phone':
            phone_osint = PhoneOSINT(args.target, self.verbose)
            self.results['phone_intel'] = phone_osint.analyze()

        elif args.mode == 'name':
            name_osint = NameOSINT(args.target, self.verbose)
            self.results['name_intel'] = name_osint.analyze()

        elif args.mode == 'full':
            print(f"\n{Colors.WARNING}[*] Running Full Reconnaissance{Colors.ENDC}")

            if '@' in args.target:
                email_osint = EmailOSINT(args.target, self.verbose)
                self.results['email_intel'] = email_osint.gather_intel()

                username = args.target.split('@')[0]
                enumerator = UsernameEnumerator(username, self.verbose)
                self.results['username_enum'] = enumerator.enumerate()

            elif '.' in args.target and ' ' not in args.target:
                domain_recon = DomainRecon(args.target, self.verbose)
                self.results['domain_recon'] = domain_recon.recon()

            elif re.match(r'^[\+]?[\d\s\-\(\)]{7,15}$', args.target):
                phone_osint = PhoneOSINT(args.target, self.verbose)
                self.results['phone_intel'] = phone_osint.analyze()

            else:
                name_osint = NameOSINT(args.target, self.verbose)
                self.results['name_intel'] = name_osint.analyze()

                enumerator = UsernameEnumerator(args.target.replace(' ', ''), self.verbose)
                self.results['username_enum'] = enumerator.enumerate()

        if args.output:
            self.save_results(args.output)

        print(f"\n{Colors.OKGREEN}[*] Reconnaissance complete!{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='OSINT Recon Tool - Full person reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -m username -t johndoe
  %(prog)s -m email -t user@example.com
  %(prog)s -m domain -t example.com
  %(prog)s -m phone -t +1234567890
  %(prog)s -m name -t John Doe
  %(prog)s -m full -t user@example.com
  %(prog)s -m full -t John Doe -o results
        """
    )

    parser.add_argument('-m', '--mode', required=True,
                        choices=['username', 'email', 'domain', 'phone', 'name', 'full'],
                        help='Recon mode')
    parser.add_argument('-t', '--target', required=True,
                        help='Target (username, email, domain, phone, or name)')
    parser.add_argument('-o', '--output',
                        help='Save results to JSON file (prefix)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    tool = ReconTool()
    tool.verbose = args.verbose
    tool.run(args)


if __name__ == '__main__':
    main()
