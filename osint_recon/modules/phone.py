"""Phone number intelligence"""

import re
from osint_recon.colors import Colors


def analyze_phone(phone, verbose=False):
    print(f"\n{Colors.OKGREEN}[*] Phone Number Intelligence: {phone}{Colors.ENDC}\n")
    results = {}

    cleaned = re.sub(r'[^\d+]', '', phone)

    if cleaned.startswith('+'):
        print(f"  {Colors.CYAN}[*] International format detected{Colors.ENDC}")
        country_code = cleaned[1:3] if len(cleaned) > 3 else cleaned[1:]
        print(f"  {Colors.CYAN}[*] Country code: +{country_code}{Colors.ENDC}")
    else:
        print(f"  {Colors.CYAN}[*] Local format detected{Colors.ENDC}")

    number_digits = re.sub(r'[^\d]', '', phone)
    print(f"  {Colors.CYAN}[*] Digits only: {number_digits}{Colors.ENDC}")
    print(f"  {Colors.CYAN}[*] Length: {len(number_digits)} digits{Colors.ENDC}")

    if len(number_digits) == 10:
        print(f"  {Colors.CYAN}[*] Format: Likely US/Canada number{Colors.ENDC}")
    elif len(number_digits) == 11 and number_digits.startswith('1'):
        print(f"  {Colors.CYAN}[*] Format: US/Canada with country code{Colors.ENDC}")

    results = {
        'original': phone,
        'cleaned': cleaned,
        'digits': number_digits,
        'length': len(number_digits),
    }

    return results
