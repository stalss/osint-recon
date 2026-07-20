#!/usr/bin/env python3
"""CLI entry point for osint-recon"""

import argparse
import json
import re
from datetime import datetime

from osint_recon import __version__
from osint_recon.banner import banner
from osint_recon.colors import Colors
from osint_recon.modules import (
    enumerate_username,
    gather_email_intel,
    recon_domain,
    analyze_phone,
    analyze_name,
)


def main():
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
  osint-recon -m name -t John Doe
  osint-recon -m full -t user@example.com
  osint-recon -m full -t John Doe -o results

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
    parser.add_argument('--version', action='version',
                        version=f'osint-recon {__version__}')

    args = parser.parse_args()
    results = {}

    banner()

    if args.output:
        results['metadata'] = {
            'tool': 'osint-recon',
            'version': __version__,
            'timestamp': datetime.now().isoformat(),
            'target': args.target,
            'mode': args.mode,
        }

    if args.mode == 'username':
        results['username_enum'] = enumerate_username(args.target, args.verbose)

    elif args.mode == 'email':
        results['email_intel'] = gather_email_intel(args.target, args.verbose)

    elif args.mode == 'domain':
        results['domain_recon'] = recon_domain(args.target, args.verbose)

    elif args.mode == 'phone':
        results['phone_intel'] = analyze_phone(args.target, args.verbose)

    elif args.mode == 'name':
        results['name_intel'] = analyze_name(args.target, args.verbose)

    elif args.mode == 'full':
        print(f"\n{Colors.WARNING}[*] Running Full Reconnaissance{Colors.ENDC}")

        if '@' in args.target:
            results['email_intel'] = gather_email_intel(args.target, args.verbose)
            username = args.target.split('@')[0]
            results['username_enum'] = enumerate_username(username, args.verbose)

        elif '.' in args.target and ' ' not in args.target:
            results['domain_recon'] = recon_domain(args.target, args.verbose)

        elif re.match(r'^[\+]?[\d\s\-\(\)]{7,15}$', args.target):
            results['phone_intel'] = analyze_phone(args.target, args.verbose)

        else:
            results['name_intel'] = analyze_name(args.target, args.verbose)
            results['username_enum'] = enumerate_username(args.target.replace(' ', ''), args.verbose)

    if args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{args.output}_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        print(f"\n{Colors.OKGREEN}[+] Results saved to: {output_file}{Colors.ENDC}")

    print(f"\n{Colors.OKGREEN}[*] Reconnaissance complete!{Colors.ENDC}")


if __name__ == '__main__':
    main()
