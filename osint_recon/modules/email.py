"""Email intelligence gathering"""

import re
import hashlib
import requests
import whois
import dns.resolver
from osint_recon.colors import Colors


PROVIDERS = {
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


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_email_provider(email):
    domain = email.split('@')[1]
    return PROVIDERS.get(domain, f'Custom/Unknown ({domain})')


def check_mx_records(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange) for record in mx_records]
    except Exception:
        return []


def check_breach(email):
    try:
        sha1_hash = hashlib.sha1(email.encode()).hexdigest().upper()
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


def gather_email_intel(email, verbose=False):
    print(f"\n{Colors.OKGREEN}[*] Email Intelligence: {email}{Colors.ENDC}\n")
    results = {}

    if not validate_email(email):
        print(f"  {Colors.FAIL}[!] Invalid email format{Colors.ENDC}")
        return results

    provider = get_email_provider(email)
    print(f"  {Colors.CYAN}[*] Provider    : {provider}{Colors.ENDC}")
    results['provider'] = provider

    mx_records = check_mx_records(email)
    if mx_records:
        print(f"  {Colors.CYAN}[*] MX Records  : {', '.join(mx_records[:3])}{Colors.ENDC}")
        results['mx_records'] = mx_records

    print(f"  {Colors.CYAN}[*] Checking breach databases...{Colors.ENDC}")
    breach = check_breach(email)
    if breach['found']:
        print(f"  {Colors.FAIL}[!] Found in breach: {breach['count']} times{Colors.ENDC}")
    else:
        print(f"  {Colors.OKGREEN}[+] Not found in known breach databases{Colors.ENDC}")
    results['breach'] = breach

    domain = email.split('@')[1]
    try:
        w = whois.whois(domain)
        if w.get('domain_name'):
            print(f"  {Colors.CYAN}[*] Domain Reg  : {w.get('registrar', 'Unknown')}{Colors.ENDC}")
            print(f"  {Colors.CYAN}[*] Created     : {w.get('creation_date', 'Unknown')}{Colors.ENDC}")
            results['domain_whois'] = {
                'registrar': str(w.get('registrar', 'Unknown')),
                'creation_date': str(w.get('creation_date', 'Unknown')),
            }
    except Exception:
        pass

    return results
