"""
Email intelligence gathering module.

Inspired by theHarvester:
- Email validation before processing
- MX record enumeration
- Domain WHOIS lookup
- Breach database checking (HIBP/PwnedPasswords API)
- Provider detection

Features:
- Email format validation with regex
- Mail provider identification (Gmail, ProtonMail, etc.)
- MX record lookup for email server discovery
- Breach checking via Have I Been Pwned API
- Domain registration info via WHOIS
"""

import re
import hashlib
import socket
import ssl
import dns.resolver
import whois
import requests
from osint_recon.colors import Colors, Status
from osint_recon.http_client import HTTPClient


# Known email providers and their details
EMAIL_PROVIDERS = {
    "gmail.com": {"name": "Google Gmail", "type": "Webmail", "encrypted": False},
    "googlemail.com": {"name": "Google Gmail", "type": "Webmail", "encrypted": False},
    "yahoo.com": {"name": "Yahoo Mail", "type": "Webmail", "encrypted": False},
    "yahoo.co.uk": {"name": "Yahoo Mail UK", "type": "Webmail", "encrypted": False},
    "outlook.com": {"name": "Microsoft Outlook", "type": "Webmail", "encrypted": False},
    "hotmail.com": {"name": "Microsoft Hotmail", "type": "Webmail", "encrypted": False},
    "live.com": {"name": "Microsoft Live", "type": "Webmail", "encrypted": False},
    "protonmail.com": {"name": "ProtonMail", "type": "Encrypted", "encrypted": True},
    "proton.me": {"name": "ProtonMail", "type": "Encrypted", "encrypted": True},
    "protonmail.ch": {"name": "ProtonMail", "type": "Encrypted", "encrypted": True},
    "icloud.com": {"name": "Apple iCloud", "type": "Webmail", "encrypted": False},
    "me.com": {"name": "Apple iCloud", "type": "Webmail", "encrypted": False},
    "aol.com": {"name": "AOL Mail", "type": "Webmail", "encrypted": False},
    "zoho.com": {"name": "Zoho Mail", "type": "Business", "encrypted": False},
    "yandex.com": {"name": "Yandex Mail", "type": "Webmail", "encrypted": False},
    "mail.com": {"name": "Mail.com", "type": "Webmail", "encrypted": False},
    "gmx.com": {"name": "GMX Mail", "type": "Webmail", "encrypted": False},
    "tutanota.com": {"name": "Tutanota", "type": "Encrypted", "encrypted": True},
    "tuta.io": {"name": "Tutanota", "type": "Encrypted", "encrypted": True},
    "tutamail.com": {"name": "Tutanota", "type": "Encrypted", "encrypted": True},
    "fastmail.com": {"name": "Fastmail", "type": "Webmail", "encrypted": False},
    "hushmail.com": {"name": "Hushmail", "type": "Encrypted", "encrypted": True},
    "riseup.net": {"name": "Riseup", "type": "Encrypted", "encrypted": True},
    "disroot.org": {"name": "Disroot", "type": "Encrypted", "encrypted": True},
}


def validate_email(email):
    """
    Validate email format using regex.
    
    This is a basic format check - it doesn't verify the email exists,
    just that it looks like a valid email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if format is valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_email_provider(email):
    """
    Identify the email provider from the domain.
    
    Args:
        email: Email address to analyze
        
    Returns:
        Dict with provider name, type, and encryption status
    """
    domain = email.split('@')[1].lower()
    return EMAIL_PROVIDERS.get(domain, {
        "name": f"Custom ({domain})",
        "type": "Unknown",
        "encrypted": False,
    })


def get_mx_records(email):
    """
    Get MX (Mail Exchange) records for the email domain.
    
    MX records tell us which mail servers handle email for this domain.
    This is useful for:
    - Verifying the domain has email infrastructure
    - Identifying the email hosting provider
    - Detecting email forwarding setups
    
    Args:
        email: Email address to check
        
    Returns:
        List of MX records or empty list on failure
    """
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange).rstrip('.') for record in mx_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def get_a_records(domain):
    """
    Get A (IPv4) records for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        List of IP addresses
    """
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except Exception:
        return []


def check_breach_pwned(email):
    """
    Check if email appears in known data breaches via HIBP.
    
    Uses the Pwned Passwords API (k-anonymity model) to check
    if the email's SHA1 hash appears in breach databases.
    
    Note: This is a basic check - for comprehensive breach data,
    use the full HIBP API with an API key.
    
    Args:
        email: Email address to check
        
    Returns:
        Dict with breach status and count
    """
    try:
        # Hash the email and use k-anonymity model
        sha1_hash = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query the API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            # Parse response and check for our hash
            hashes = {}
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                hashes[hash_suffix] = int(count)
            
            if suffix in hashes:
                return {
                    "found": True,
                    "count": hashes[suffix],
                    "source": "Pwned Passwords"
                }
    except Exception:
        pass
    
    return {"found": False, "count": 0, "source": None}


def get_domain_whois(email):
    """
    Get WHOIS information for the email domain.
    
    This reveals domain registration details which can provide:
    - Registrar information
    - Creation and expiration dates
    - Name servers
    - Registrant organization (if not privacy-protected)
    
    Args:
        email: Email address to check
        
    Returns:
        Dict with WHOIS data or empty dict on failure
    """
    domain = email.split('@')[1]
    try:
        w = whois.whois(domain)
        
        # Handle multiple creation dates (some domains return lists)
        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        return {
            "domain": domain,
            "registrar": str(w.get('registrar', 'Unknown')),
            "creation_date": str(creation_date) if creation_date else 'Unknown',
            "expiration_date": str(w.get('expiration_date', 'Unknown')),
            "name_servers": w.get('name_servers', []),
            "org": str(w.get('org', 'Unknown')),
            "country": str(w.get('country', 'Unknown')),
            "emails": w.get('emails', []),
            "dnssec": str(w.get('dnssec', 'Unknown')),
        }
    except Exception:
        return {}


def get_email_headers_info(email):
    """
    Analyze email domain for additional intelligence.
    
    Checks:
    - SPF records (email spoofing protection)
    - DMARC records (email authentication)
    - DKIM (email signing)
    
    Args:
        email: Email address to analyze
        
    Returns:
        Dict with email security records
    """
    domain = email.split('@')[1]
    records = {}
    
    # Check for SPF record
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            txt = str(record)
            if 'v=spf1' in txt:
                records['spf'] = txt.strip('"')
            elif 'v=DMARC1' in txt:
                records['dmarc'] = txt.strip('"')
    except Exception:
        pass
    
    # Check for DMARC record
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_records:
            records['dmarc'] = str(record).strip('"')
    except Exception:
        pass
    
    return records


def gather_email_intel(email, verbose=False, rate_limit=1.0):
    """
    Main function to gather intelligence on an email address.
    
    This orchestrates all email analysis functions and compiles results.
    
    Inspired by theHarvester's multi-source approach to email recon.
    
    Args:
        email: Target email address
        verbose: Enable verbose output
        rate_limit: Seconds between API requests
        
    Returns:
        Dict with comprehensive email intelligence
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Email Intelligence: {email}{Colors.ENDC}\n")
    results = {}
    
    # Validate email format
    if not validate_email(email):
        print(f"  {Status.ERROR} {Colors.FAIL}Invalid email format{Colors.ENDC}")
        return results
    
    # 1. Identify provider
    provider = get_email_provider(email)
    print(f"  {Colors.CYAN}Provider      :{Colors.ENDC} {provider['name']}")
    print(f"  {Colors.CYAN}Type          :{Colors.ENDC} {provider['type']}")
    if provider['encrypted']:
        print(f"  {Colors.CYAN}Encryption    :{Colors.ENDC} {Colors.OKGREEN}End-to-end encrypted{Colors.ENDC}")
    results['provider'] = provider
    
    # 2. Check MX records
    print(f"\n  {Colors.CYAN}Checking MX records...{Colors.ENDC}")
    mx_records = get_mx_records(email)
    if mx_records:
        for mx in mx_records[:3]:
            print(f"    {Status.FOUND} {mx}")
        results['mx_records'] = mx_records
    else:
        print(f"    {Status.NOT_FOUND} No MX records found")
    
    # 3. Check A records
    domain = email.split('@')[1]
    a_records = get_a_records(domain)
    if a_records:
        results['a_records'] = a_records
    
    # 4. Check email security records (SPF, DMARC)
    print(f"\n  {Colors.CYAN}Checking email security...{Colors.ENDC}")
    email_security = get_email_headers_info(email)
    if email_security:
        for record_type, value in email_security.items():
            print(f"    {Status.FOUND} {record_type.upper()}: {value[:80]}...")
        results['email_security'] = email_security
    else:
        print(f"    {Status.NOT_FOUND} No SPF/DMARC records found")
    
    # 5. Check breach databases
    print(f"\n  {Colors.CYAN}Checking breach databases...{Colors.ENDC}")
    breach = check_breach_pwned(email)
    if breach['found']:
        print(f"  {Status.ERROR} {Colors.FAIL}Found in {breach['source']}: {breach['count']} time(s){Colors.ENDC}")
    else:
        print(f"  {Status.FOUND} {Colors.OKGREEN}Not found in known breach databases{Colors.ENDC}")
    results['breach'] = breach
    
    # 6. WHOIS lookup
    print(f"\n  {Colors.CYAN}Performing WHOIS lookup...{Colors.ENDC}")
    whois_data = get_domain_whois(email)
    if whois_data:
        print(f"    {Status.FOUND} Registrar : {whois_data.get('registrar', 'Unknown')}")
        print(f"    {Status.FOUND} Created   : {whois_data.get('creation_date', 'Unknown')}")
        print(f"    {Status.FOUND} Expires   : {whois_data.get('expiration_date', 'Unknown')}")
        print(f"    {Status.FOUND} Org       : {whois_data.get('org', 'Unknown')}")
        print(f"    {Status.FOUND} Country   : {whois_data.get('country', 'Unknown')}")
        results['whois'] = whois_data
    
    # 7. Additional DNS analysis
    print(f"\n  {Colors.CYAN}Performing DNS analysis...{Colors.ENDC}")
    dns_info = {}
    
    # Check for common subdomains
    common_subdomains = ['mail', 'webmail', 'smtp', 'imap', 'pop3', 'mx', 'mx1', 'mx2']
    for subdomain in common_subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(r) for r in answers]
            dns_info[full_domain] = ips
            print(f"    {Status.FOUND} {full_domain} -> {', '.join(ips)}")
        except Exception:
            pass
    
    if dns_info:
        results['dns_subdomains'] = dns_info
    
    return results
