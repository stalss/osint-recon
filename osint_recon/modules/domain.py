"""
Domain and IP reconnaissance module.

Inspired by theHarvester and Recon-ng:
- WHOIS lookup for domain registration info
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- IP geolocation via public API
- SSL certificate analysis
- Subdomain discovery
- Technology fingerprinting (basic)

Features:
- Comprehensive DNS record analysis
- IP to geolocation mapping
- SSL/TLS certificate inspection
- Domain age and registrar info
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import whois
import requests
from osint_recon.colors import Colors, Status
from osint_recon.http_client import HTTPClient


def get_whois(domain):
    """
    Perform WHOIS lookup on a domain.
    
    Returns registration details including:
    - Registrar name
    - Creation and expiration dates
    - Name servers
    - Registrant organization
    - Country
    
    Args:
        domain: Target domain
        
    Returns:
        Dict with WHOIS data
    """
    try:
        w = whois.whois(domain)
        
        # Handle multiple creation dates
        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = w.get('expiration_date')
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        return {
            "domain_name": str(w.get('domain_name', 'N/A')),
            "registrar": str(w.get('registrar', 'N/A')),
            "whois_server": str(w.get('whois_server', 'N/A')),
            "creation_date": str(creation_date) if creation_date else 'N/A',
            "expiration_date": str(expiration_date) if expiration_date else 'N/A',
            "updated_date": str(w.get('updated_date', 'N/A')),
            "name_servers": w.get('name_servers', []),
            "status": w.get('status', []),
            "emails": w.get('emails', []),
            "org": str(w.get('org', 'N/A')),
            "country": str(w.get('country', 'N/A')),
            "state": str(w.get('state', 'N/A')),
            "city": str(w.get('city', 'N/A')),
            "address": str(w.get('address', 'N/A')),
            "registrar_url": str(w.get('registrar_url', 'N/A')),
            "dnssec": str(w.get('dnssec', 'N/A')),
        }
    except Exception as e:
        return {"error": str(e)}


def get_dns_records(domain):
    """
    Enumerate all DNS records for a domain.
    
    Checks for:
    - A records (IPv4 addresses)
    - AAAA records (IPv6 addresses)
    - MX records (mail servers)
    - NS records (name servers)
    - TXT records (SPF, DKIM, DMARC, etc.)
    - CNAME records (aliases)
    - SOA records (start of authority)
    
    Args:
        domain: Target domain
        
    Returns:
        Dict with DNS records by type
    """
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
    
    return records


def get_ip_geolocation(ip):
    """
    Get geolocation information for an IP address.
    
    Uses the free ip-api.com API (limited to 45 requests/minute).
    
    Args:
        ip: IPv4 address to lookup
        
    Returns:
        Dict with location data
    """
    try:
        response = requests.get(
            f"https://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"},
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


def get_ssl_certificate(domain):
    """
    Retrieve and analyze SSL/TLS certificate for a domain.
    
    Provides:
    - Certificate subject and issuer
    - Validity period
    - Subject Alternative Names (SANs)
    - Serial number
    
    Args:
        domain: Target domain
        
    Returns:
        Dict with certificate info
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse subject
                subject = dict(x[0] for x in cert.get('subject', []))
                
                # Parse issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                # Parse SANs
                san_list = [x[1] for x in cert.get('subjectAltName', [])]
                
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": cert.get('serial_number', 'N/A'),
                    "not_before": cert.get('notBefore', 'N/A'),
                    "not_after": cert.get('notAfter', 'N/A'),
                    "san_count": len(san_list),
                    "sans": san_list[:10],  # Limit to first 10
                    "version": cert.get('version', 'N/A'),
                }
    except Exception:
        return {}


def check_common_ports(domain):
    """
    Check common ports for basic service discovery (concurrent).
    
    Tests ports commonly used by web services.
    This is a lightweight check - not a full port scan.
    
    Args:
        domain: Target domain or IP
        
    Returns:
        Dict with open ports and services
    """
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    
    open_ports = {}
    ip = socket.gethostbyname(domain)
    
    def check_port(port, service):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port, service
        except Exception:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, p, s): (p, s) for p, s in common_ports.items()}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports[result[0]] = result[1]
    
    return open_ports


def discover_subdomains(domain, verbose=False):
    """
    Discover subdomains using DNS bruteforce (concurrent).
    
    Tests common subdomain prefixes against the target domain.
    This is a basic bruteforce - for comprehensive discovery,
    use tools like Sublist3r or Amass.
    
    Args:
        domain: Target domain
        verbose: Enable verbose output
        
    Returns:
        Dict of found subdomains and their IPs
    """
    # Common subwordlist (abbreviated for speed)
    subdomains = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "mx3",
        "vpn", "remote", "gateway", "gateway2",
        "api", "dev", "staging", "test", "beta", "alpha",
        "admin", "portal", "panel", "dashboard",
        "blog", "forum", "shop", "store", "ecommerce",
        "cdn", "static", "media", "img", "images", "assets",
        "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
        "git", "gitlab", "jenkins", "ci", "cd", "jira", "confluence",
        "sso", "auth", "login", "accounts",
        "status", "monitor", "grafana", "kibana", "prometheus",
        "backup", "bak", "old", "archive",
        "intranet", "internal", "corp", "office",
    ]
    
    found = {}
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(r) for r in answers]
            return full_domain, ips
        except Exception:
            return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                full_domain, ips = result
                found[full_domain] = ips
                if verbose:
                    print(f"    {Status.FOUND} {full_domain} -> {', '.join(ips)}")
    
    return found


def recon_domain(domain, verbose=False, rate_limit=1.0):
    """
    Main function for domain reconnaissance.
    
    Orchestrates all domain analysis functions:
    1. WHOIS lookup
    2. DNS enumeration
    3. IP geolocation
    4. SSL certificate analysis
    5. Port check
    6. Subdomain discovery
    
    Inspired by theHarvester and Recon-ng's approach to domain recon.
    
    Args:
        domain: Target domain
        verbose: Enable verbose output
        rate_limit: Seconds between requests
        
    Returns:
        Dict with comprehensive domain intelligence
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Domain Reconnaissance: {domain}{Colors.ENDC}\n")
    results = {}
    
    # 1. WHOIS Lookup
    print(f"  {Colors.CYAN}[*] Performing WHOIS lookup...{Colors.ENDC}")
    whois_data = get_whois(domain)
    results['whois'] = whois_data
    
    if 'error' not in whois_data:
        print(f"      {Colors.CYAN}Registrar  :{Colors.ENDC} {whois_data.get('registrar', 'N/A')}")
        print(f"      {Colors.CYAN}Created    :{Colors.ENDC} {whois_data.get('creation_date', 'N/A')}")
        print(f"      {Colors.CYAN}Expires    :{Colors.ENDC} {whois_data.get('expiration_date', 'N/A')}")
        print(f"      {Colors.CYAN}Org        :{Colors.ENDC} {whois_data.get('org', 'N/A')}")
        print(f"      {Colors.CYAN}Country    :{Colors.ENDC} {whois_data.get('country', 'N/A')}")
        ns = whois_data.get('name_servers', [])
        if ns:
            print(f"      {Colors.CYAN}Name Svr   :{Colors.ENDC} {', '.join(ns[:3])}")
    else:
        print(f"      {Status.ERROR} WHOIS lookup failed: {whois_data.get('error', 'Unknown')}")
    
    # 2. DNS Records
    print(f"\n  {Colors.CYAN}[*] Enumerating DNS records...{Colors.ENDC}")
    dns_records = get_dns_records(domain)
    results['dns'] = dns_records
    
    for rtype, values in dns_records.items():
        print(f"      {Colors.CYAN}{rtype:8s}{Colors.ENDC} : {', '.join(values[:3])}")
    
    # 3. IP Geolocation
    print(f"\n  {Colors.CYAN}[*] Performing IP geolocation...{Colors.ENDC}")
    if 'A' in dns_records and dns_records['A']:
        ip = dns_records['A'][0]
        ip_info = get_ip_geolocation(ip)
        results['ip_info'] = ip_info
        
        if ip_info:
            print(f"      {Colors.CYAN}IP        :{Colors.ENDC} {ip_info.get('query', 'N/A')}")
            print(f"      {Colors.CYAN}Location  :{Colors.ENDC} {ip_info.get('city', 'N/A')}, {ip_info.get('regionName', 'N/A')}, {ip_info.get('country', 'N/A')}")
            print(f"      {Colors.CYAN}ISP       :{Colors.ENDC} {ip_info.get('isp', 'N/A')}")
            print(f"      {Colors.CYAN}Org       :{Colors.ENDC} {ip_info.get('org', 'N/A')}")
            print(f"      {Colors.CYAN}AS        :{Colors.ENDC} {ip_info.get('as', 'N/A')}")
            if ip_info.get('mobile'):
                print(f"      {Status.WARNING} Mobile network detected")
            if ip_info.get('proxy'):
                print(f"      {Status.WARNING} Proxy/VPN detected")
            if ip_info.get('hosting'):
                print(f"      {Status.INFO} Hosting/Datacenter IP")
    
    # 4. SSL Certificate
    print(f"\n  {Colors.CYAN}[*] Analyzing SSL certificate...{Colors.ENDC}")
    ssl_info = get_ssl_certificate(domain)
    results['ssl'] = ssl_info
    
    if ssl_info:
        issuer = ssl_info.get('issuer', {})
        print(f"      {Colors.CYAN}Issuer    :{Colors.ENDC} {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}")
        print(f"      {Colors.CYAN}Valid     :{Colors.ENDC} {ssl_info.get('not_before', 'N/A')} to {ssl_info.get('not_after', 'N/A')}")
        print(f"      {Colors.CYAN}SANs      :{Colors.ENDC} {ssl_info.get('san_count', 0)} domains")
        sans = ssl_info.get('sans', [])
        if sans and verbose:
            for san in sans[:5]:
                print(f"                  {san}")
    
    # 5. Common Ports
    print(f"\n  {Colors.CYAN}[*] Checking common ports...{Colors.ENDC}")
    ports = check_common_ports(domain)
    results['ports'] = ports
    
    if ports:
        for port, service in ports.items():
            print(f"      {Status.FOUND} {Colors.OKGREEN}Port {port:5d}{Colors.ENDC} : {service}")
    else:
        print(f"      {Status.NOT_FOUND} No common ports open")
    
    # 6. Subdomain Discovery
    print(f"\n  {Colors.CYAN}[*] Discovering subdomains...{Colors.ENDC}")
    subdomains = discover_subdomains(domain, verbose)
    results['subdomains'] = subdomains
    
    if subdomains:
        print(f"      {Status.FOUND} Found {len(subdomains)} subdomain(s)")
        for sub, ips in list(subdomains.items())[:5]:
            print(f"        {sub} -> {', '.join(ips)}")
    else:
        print(f"      {Status.NOT_FOUND} No subdomains found")
    
    return results
