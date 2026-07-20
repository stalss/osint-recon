"""Name-based intelligence gathering"""

from osint_recon.colors import Colors


def analyze_name(name, verbose=False):
    print(f"\n{Colors.OKGREEN}[*] Name Intelligence: {name}{Colors.ENDC}\n")
    results = {}

    parts = name.strip().split()
    if len(parts) >= 2:
        first_name = parts[0]
        last_name = parts[-1]
        middle_names = parts[1:-1] if len(parts) > 2 else []

        print(f"  {Colors.CYAN}[*] First Name : {first_name}{Colors.ENDC}")
        if middle_names:
            print(f"  {Colors.CYAN}[*] Middle Name: {' '.join(middle_names)}{Colors.ENDC}")
        print(f"  {Colors.CYAN}[*] Last Name  : {last_name}{Colors.ENDC}")

        results['first_name'] = first_name
        results['last_name'] = last_name
        results['middle_names'] = middle_names

        username_variations = [
            f"{first_name.lower()}{last_name.lower()}",
            f"{first_name.lower()}.{last_name.lower()}",
            f"{first_name.lower()}_{last_name.lower()}",
            f"{first_name[0].lower()}{last_name.lower()}",
            f"{first_name.lower()}{last_name[0].lower()}",
            f"{last_name.lower()}{first_name.lower()}",
            f"{first_name.lower()}{last_name.lower()}1",
            f"{first_name.lower()}_{last_name.lower()}1",
            f"{first_name.lower()}{last_name.lower()}_{first_name[0].lower()}",
            f"{first_name.lower()[0]}{last_name.lower()}123",
        ]

        print(f"\n  {Colors.CYAN}[*] Suggested username variations:{Colors.ENDC}")
        for i, variation in enumerate(username_variations, 1):
            print(f"      {i}. {variation}")
        results['username_variations'] = username_variations

    else:
        print(f"  {Colors.WARNING}[*] Single name detected - limited analysis{Colors.ENDC}")
        results['single_name'] = name

    return results
