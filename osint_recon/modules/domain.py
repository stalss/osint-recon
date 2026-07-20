"""Domain and IP reconnaissance"""

import socket
import ssl
import requests
import whois
import dns.resolver
from osint_recon.colors import Colors


def get_whois(target):
    try:
        w = whois.whois(target)
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


def get_dns_records(target):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        try:
            answers = dns.resolver.resolve(target, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return records


def get_ip_info(target):
    try:
        ip = socket.gethostbyname(target)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {}


def get_ssl_cert(target):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
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


def recon_domain(target, verbose=False):
    print(f"\n{Colors.OKGREEN}[*] Domain Reconnaissance: {target}{Colors.ENDC}\n")
    results = {}

    print(f"  {Colors.CYAN}[*] Performing WHOIS lookup...{Colors.ENDC}")
    whois_data = get_whois(target)
    results['whois'] = whois_data
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
    dns_records = get_dns_records(target)
    results['dns'] = dns_records
    for rtype, values in dns_records.items():
        print(f"      {rtype:8s}: {', '.join(values[:3])}")

    print(f"\n  {Colors.CYAN}[*] IP Geolocation:{Colors.ENDC}")
    ip_info = get_ip_info(target)
    results['ip_info'] = ip_info
    if ip_info:
        print(f"      IP        : {ip_info.get('query', 'N/A')}")
        print(f"      Location  : {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}")
        print(f"      ISP       : {ip_info.get('isp', 'N/A')}")
        print(f"      Org       : {ip_info.get('org', 'N/A')}")
        print(f"      AS        : {ip_info.get('as', 'N/A')}")

    print(f"\n  {Colors.CYAN}[*] SSL Certificate:{Colors.ENDC}")
    ssl_info = get_ssl_cert(target)
    results['ssl'] = ssl_info
    if ssl_info:
        issuer = ssl_info.get('issuer', {})
        print(f"      Issuer    : {issuer.get('organizationName', 'N/A')}")
        print(f"      Valid     : {ssl_info.get('not_before', 'N/A')} to {ssl_info.get('not_after', 'N/A')}")
        san = ssl_info.get('san', [])
        if san:
            print(f"      SANs      : {', '.join(san[:5])}")

    return results
