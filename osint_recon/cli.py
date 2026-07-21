#!/usr/bin/env python3
"""
OSINT Recon Tool - CLI Entry Point

A comprehensive OSINT tool for gathering information about targets.
Supports username enumeration, email intel, domain recon, phone analysis,
and name intelligence.

Inspired by:
- Sherlock (username enumeration)
- theHarvester (email/domain recon)
- SpiderFoot (automated OSINT)
- Recon-ng (modular framework)

Usage:
    osint-recon -m username -t johndoe
    osint-recon -m email -t user@example.com
    osint-recon -m domain -t example.com
    osint-recon -m phone -t +1234567890
    osint-recon -m name -t "John Doe"
    osint-recon -m full -t user@example.com
"""

import argparse
import json
import re
import sys
from datetime import datetime

from osint_recon import __version__
from osint_recon.banner import show_banner, show_scan_header, show_section, show_results_summary
from osint_recon.colors import Colors, Status
from osint_recon.modules import (
    enumerate_username,
    gather_email_intel,
    recon_domain,
    analyze_phone,
    analyze_name,
)


def detect_target_type(target):
    """
    Automatically detect the type of target.
    
    This enables the 'full' mode to work without specifying the mode.
    
    Detection logic:
    - Contains @ -> Email
    - Contains . and no spaces -> Domain
    - Contains only digits and + -> Phone
    - Everything else -> Name
    
    Args:
        target: Target string
        
    Returns:
        Detected target type (email, domain, phone, name)
    """
    # Email pattern
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return "email"
    
    # Domain pattern (contains dot, no spaces)
    if '.' in target and ' ' not in target:
        # Additional check: make sure it looks like a domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "domain"
    
    # Phone pattern (digits, +, spaces, dashes, parentheses)
    if re.match(r'^[\+]?[\d\s\-\(\)]{7,20}$', target):
        return "phone"
    
    # Default to name
    return "name"


def run_full_scan(target, verbose=False, rate_limit=1.0, output_prefix=None):
    """
    Run a comprehensive scan on the target.
    
    Automatically detects target type and runs appropriate modules.
    Can run multiple modules if the target matches multiple types.
    
    Args:
        target: Target to scan
        verbose: Enable verbose output
        rate_limit: Seconds between requests
        output_prefix: Prefix for output file
    """
    results = {}
    target_type = detect_target_type(target)
    
    print(f"\n{Colors.WARNING}[*] Running Full Reconnaissance{Colors.ENDC}")
    print(f"{Colors.CYAN}  Detected target type: {target_type}{Colors.ENDC}\n")
    
    if target_type == "email":
        # Email scan + username from email prefix
        results['email_intel'] = gather_email_intel(target, verbose, rate_limit)
        
        username = target.split('@')[0]
        show_section(f"Username Enumeration from Email Prefix: {username}")
        results['username_enum'] = enumerate_username(username, verbose, rate_limit)
        
    elif target_type == "domain":
        # Full domain recon
        results['domain_recon'] = recon_domain(target, verbose, rate_limit)
        
    elif target_type == "phone":
        # Phone analysis
        results['phone_intel'] = analyze_phone(target, verbose)
        
    else:
        # Name analysis + username enumeration
        results['name_intel'] = analyze_name(target, verbose)
        
        username = target.replace(' ', '')
        show_section(f"Username Enumeration: {username}")
        results['username_enum'] = enumerate_username(username, verbose, rate_limit)
    
    return results


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog='osint-recon',
        description='OSINT Recon Tool - Full person reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  osint-recon -m username -t johndoe
  osint-recon -m email -t user@example.com
  osint-recon -m domain -t example.com
  osint-recon -m phone -t +1234567890
  osint-recon -m name -t "John Doe"
  osint-recon -m full -t user@example.com
  osint-recon -m full -t "John Doe" -o results

Modes:
  username  - Enumerate username across 40+ platforms
  email     - Gather email intelligence (provider, MX, breach)
  domain    - Domain recon (WHOIS, DNS, SSL, ports)
  phone     - Phone number analysis and validation
  name      - Name parsing and username generation
  full      - Auto-detect and run comprehensive scan

Version: {__version__}
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
    parser.add_argument('-r', '--rate-limit', type=float, default=0.5,
                        help='Rate limit in seconds between requests (default: 0.5)')
    parser.add_argument('--check-fp', action='store_true',
                        help='Check for false positives before username enumeration')
    parser.add_argument('--deep', action='store_true',
                        help='Deep scan: verify emails, search web, discover connections (slower)')
    parser.add_argument('--version', action='version',
                        version=f'osint-recon {__version__}')
    
    args = parser.parse_args()
    
    # Show banner
    show_banner()
    show_scan_header(args.target, args.mode)
    
    # Initialize results
    results = {
        'metadata': {
            'tool': 'osint-recon',
            'version': __version__,
            'timestamp': datetime.now().isoformat(),
            'target': args.target,
            'mode': args.mode,
        }
    }
    
    try:
        # Run the appropriate scan
        if args.mode == 'username':
            results['username_enum'] = enumerate_username(
                args.target, args.verbose, args.rate_limit, args.check_fp
            )
            
        elif args.mode == 'email':
            results['email_intel'] = gather_email_intel(
                args.target, args.verbose, args.rate_limit
            )
            
        elif args.mode == 'domain':
            results['domain_recon'] = recon_domain(
                args.target, args.verbose, args.rate_limit
            )
            
        elif args.mode == 'phone':
            results['phone_intel'] = analyze_phone(args.target, args.verbose)
            
        elif args.mode == 'name':
            results['name_intel'] = analyze_name(args.target, args.verbose, args.rate_limit, args.deep)
            
        elif args.mode == 'full':
            scan_results = run_full_scan(
                args.target, args.verbose, args.rate_limit, args.output
            )
            results.update(scan_results)
        
        # Show results summary
        show_results_summary(results)
        
        # Save results if requested
        if args.output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{args.output}_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4, default=str)
            
            print(f"\n{Status.FOUND} {Colors.OKGREEN}Results saved to: {output_file}{Colors.ENDC}")
        
        print(f"\n{Colors.OKGREEN}[*] Reconnaissance complete!{Colors.ENDC}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Status.WARNING} {Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Status.ERROR} {Colors.FAIL}Error: {e}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
