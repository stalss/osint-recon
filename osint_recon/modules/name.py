"""
Name-based intelligence gathering module.

Inspired by SpiderFoot's name analysis:
- Name parsing (first, middle, last)
- Username variation generation
- Common username pattern detection
- Name-based search suggestions

Features:
- Intelligent name parsing
- Multiple username pattern generation
- Name variant detection (nicknames, etc.)
"""

from osint_recon.colors import Colors, Status


# Common name patterns for username generation
# Based on analysis of popular username formats
USERNAME_PATTERNS = [
    # Simple combinations
    "{first}{last}",
    "{first}.{last}",
    "{first}_{last}",
    "{first}-{last}",
    
    # Initials
    "{f}{last}",
    "{first}{l}",
    "{f}.{last}",
    "{first}.{l}",
    "{f}_{last}",
    "{first}_{l}",
    
    # Reversed
    "{last}{first}",
    "{last}.{first}",
    "{last}_{first}",
    "{last}-{first}",
    "{l}{first}",
    "{last}{f}",
    
    # With numbers (common patterns)
    "{first}{last}1",
    "{first}.{last}1",
    "{first}_{last}1",
    "{first}{last}123",
    "{first}{last}01",
    "{first}{last}_",
    
    # Year patterns (birth year range)
    "{first}{last}90",
    "{first}{last}95",
    "{first}{last}00",
    "{first}{last}99",
    
    # Underscore variations
    "{f}_{last}",
    "{first}_{l}",
    "{f}_{l}",
    "_{first}{last}",
    "{first}{last}_",
    
    # Dotted variations
    "{f}.{last}",
    "{first}.{l}",
    "{f}.{l}",
]


def parse_name(name):
    """
    Parse a full name into components.
    
    Handles:
    - Two-part names (John Doe)
    - Three-part names (John Michael Doe)
    - Four-part names (John Michael Van Doe)
    - Single names (Madonna)
    
    Args:
        name: Full name string
        
    Returns:
        Dict with parsed name components
    """
    parts = name.strip().split()
    
    result = {
        "full": name,
        "first": "",
        "last": "",
        "middle": [],
        "parts": parts,
        "part_count": len(parts),
    }
    
    if len(parts) == 0:
        return result
    
    if len(parts) == 1:
        # Single name (e.g., Madonna, Cher)
        result["first"] = parts[0]
        result["type"] = "single"
    elif len(parts) == 2:
        # Standard two-part name
        result["first"] = parts[0]
        result["last"] = parts[1]
        result["type"] = "standard"
    else:
        # Three or more parts
        result["first"] = parts[0]
        result["last"] = parts[-1]
        result["middle"] = parts[1:-1]
        result["type"] = "compound"
    
    return result


def generate_username_variations(name):
    """
    Generate username variations from a name.
    
    Uses common username patterns to generate likely variations.
    This is useful for finding the same person across different platforms.
    
    Inspired by SpiderFoot's username permutation generation.
    
    Args:
        name: Full name string
        
    Returns:
        List of username variations
    """
    parsed = parse_name(name)
    variations = []
    
    if parsed["part_count"] < 2:
        # Can't generate much from a single name
        variations.append(parsed["first"].lower())
        variations.append(parsed["first"].lower() + "1")
        return variations
    
    first = parsed["first"]
    last = parsed["last"]
    f = first[0] if first else ""
    l = last[0] if last else ""
    
    # Generate variations using patterns
    seen = set()
    for pattern in USERNAME_PATTERNS:
        try:
            username = pattern.format(
                first=first.lower(),
                last=last.lower(),
                f=f.lower(),
                l=l.lower(),
            )
            # Avoid duplicates
            if username not in seen:
                seen.add(username)
                variations.append(username)
        except (IndexError, KeyError):
            continue
    
    return variations


def suggest_search_queries(name):
    """
    Generate search queries for finding information about a person.
    
    Creates Google dork-style queries that can help find:
    - Social media profiles
    - Professional listings
    - Public records
    
    Args:
        name: Full name string
        
    Returns:
        List of search query suggestions
    """
    parsed = parse_name(name)
    queries = []
    
    # Basic name searches
    queries.append(f'"{name}"')
    queries.append(f'"{parsed["first"]} {parsed["last"]}"')
    
    if parsed["middle"]:
        queries.append(f'"{parsed["first"]} {" ".join(parsed["middle"])} {parsed["last"]}"')
    
    # Social media searches
    queries.append(f'"{name}" site:linkedin.com')
    queries.append(f'"{name}" site:twitter.com')
    queries.append(f'"{name}" site:facebook.com')
    queries.append(f'"{name}" site:instagram.com')
    queries.append(f'"{name}" site:github.com')
    
    # Professional searches
    queries.append(f'"{name}" resume OR CV OR portfolio')
    queries.append(f'"{name}" email OR contact')
    
    # Username searches
    username = f"{parsed['first'].lower()}{parsed['last'].lower()}"
    queries.append(f'"{username}" site:github.com OR site:twitter.com')
    
    return queries


def analyze_name(name, verbose=False):
    """
    Main function for name-based intelligence.
    
    Analyzes a name and provides:
    - Name parsing (first, middle, last)
    - Username variations
    - Search query suggestions
    
    Inspired by SpiderFoot's name analysis approach.
    
    Args:
        name: Target name
        verbose: Enable verbose output
        
    Returns:
        Dict with name intelligence
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Name Intelligence: {name}{Colors.ENDC}\n")
    results = {}
    
    # Parse the name
    parsed = parse_name(name)
    results['parsed'] = parsed
    
    print(f"  {Colors.CYAN}First Name   :{Colors.ENDC} {parsed['first']}")
    if parsed['middle']:
        print(f"  {Colors.CYAN}Middle Name(s) :{Colors.ENDC} {' '.join(parsed['middle'])}")
    print(f"  {Colors.CYAN}Last Name    :{Colors.ENDC} {parsed['last']}")
    print(f"  {Colors.CYAN}Name Type    :{Colors.ENDC} {parsed['type']}")
    
    # Generate username variations
    print(f"\n  {Colors.CYAN}[*] Generating username variations...{Colors.ENDC}")
    variations = generate_username_variations(name)
    results['username_variations'] = variations
    
    if variations:
        print(f"  {Colors.CYAN}Generated {len(variations)} variations:{Colors.ENDC}")
        for i, var in enumerate(variations[:15], 1):  # Show first 15
            print(f"    {i:2d}. {var}")
        if len(variations) > 15:
            print(f"    {Colors.DIM}... and {len(variations)-15} more{Colors.ENDC}")
    
    # Generate search queries
    print(f"\n  {Colors.CYAN}[*] Generating search queries...{Colors.ENDC}")
    queries = suggest_search_queries(name)
    results['search_queries'] = queries
    
    if queries:
        print(f"  {Colors.CYAN}Suggested searches:{Colors.ENDC}")
        for i, query in enumerate(queries[:8], 1):  # Show first 8
            print(f"    {i:2d}. {query}")
    
    # Additional analysis
    if verbose:
        print(f"\n  {Colors.DIM}--- Additional Analysis ---{Colors.ENDC}")
        print(f"  {Colors.DIM}Full name length: {len(name)} characters{Colors.ENDC}")
        print(f"  {Colors.DIM}Name parts: {parsed['part_count']}{Colors.ENDC}")
        if parsed['middle']:
            print(f"  {Colors.DIM}Middle names: {len(parsed['middle'])}{Colors.ENDC}")
    
    return results
