"""
Name-based intelligence gathering module.

Inspired by SpiderFoot's name analysis:
- Name parsing (first, middle, last)
- Username variation generation
- Common username pattern detection
- Name-based search suggestions
- Email pattern generation
- Social media profile enumeration

Features:
- Intelligent name parsing
- Multiple username pattern generation
- Email address pattern generation
- Social media profile URL generation
- Public records search suggestions
- Professional profile lookups
"""

import re
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


# Common email domains for pattern generation
COMMON_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "zoho.com",
]


# Email address patterns (based on research of common formats)
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{f}.{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}.{l}@{domain}",
    "{first}{l}@{domain}",
    "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
    "{last}.{first}@{domain}",
    "{last}{first}@{domain}",
    "{first}@{domain}",
    "{f}{last}{l}@{domain}",
]


# Social media / professional platforms with profile URL patterns
SOCIAL_PLATFORMS = {
    # Professional
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "StackOverflow": "https://stackoverflow.com/users/?tab=Accounts&Filter=All&q={username}",
    
    # Social
    "Twitter/X": "https://twitter.com/{username}",
    "Instagram": "https://www.instagram.com/{username}",
    "Facebook": "https://www.facebook.com/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    
    # Developer
    "Dev.to": "https://dev.to/{username}",
    "HackerRank": "https://www.hackerrank.com/{username}",
    "CodePen": "https://codepen.io/{username}",
    "Keybase": "https://keybase.io/{username}",
    
    # Creative
    "Behance": "https://www.behance.net/{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "Medium": "https://medium.com/@{username}",
    "Substack": "https://{username}.substack.com",
    
    # Gaming
    "Twitch": "https://www.twitch.tv/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    
    # Other
    "Reddit": "https://www.reddit.com/user/{username}",
    "Pinterest": "https://www.pinterest.com/{username}",
    "Flickr": "https://www.flickr.com/people/{username}",
    "Gravatar": "https://en.gravatar.com/{username}",
}


# Domain TLDs commonly used for personal sites
PERSONAL_DOMAIN_TLDS = [".com", ".me", ".dev", ".io", ".net", ".org", ".co"]


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


def generate_email_patterns(name, domains=None):
    """
    Generate likely email address patterns from a name.
    
    Generates common email formats using known domains.
    Useful for finding contact information or verifying email existence.
    
    Args:
        name: Full name string
        domains: List of email domains to use (default: common providers)
        
    Returns:
        List of email address patterns
    """
    parsed = parse_name(name)
    emails = []
    
    if parsed["part_count"] < 2:
        # Single name - limited patterns
        first = parsed["first"].lower()
        for domain in (domains or COMMON_EMAIL_DOMAINS):
            emails.append(f"{first}@{domain}")
        return emails
    
    first = parsed["first"]
    last = parsed["last"]
    f = first[0] if first else ""
    l = last[0] if last else ""
    
    # Generate email patterns for each domain
    for domain in (domains or COMMON_EMAIL_DOMAINS):
        for pattern in EMAIL_PATTERNS:
            try:
                email = pattern.format(
                    first=first.lower(),
                    last=last.lower(),
                    f=f.lower(),
                    l=l.lower(),
                    domain=domain,
                )
                emails.append(email)
            except (IndexError, KeyError):
                continue
    
    return emails


def generate_social_profile_urls(name):
    """
    Generate likely social media profile URLs from a name.
    
    Creates profile URLs for major platforms using common
    username patterns. Useful for manual or automated checks.
    
    Args:
        name: Full name string
        
    Returns:
        Dict mapping platform name to list of profile URLs
    """
    usernames = generate_username_variations(name)
    profiles = {}
    
    for platform, url_pattern in SOCIAL_PLATFORMS.items():
        platform_urls = []
        for username in usernames[:5]:  # Limit to top 5 variations per platform
            try:
                url = url_pattern.format(username=username)
                platform_urls.append(url)
            except KeyError:
                continue
        if platform_urls:
            profiles[platform] = platform_urls
    
    return profiles


def generate_personal_domain_suggestions(name):
    """
    Generate personal domain name suggestions.
    
    Suggests domain names that a person might own for their
    personal website or portfolio.
    
    Args:
        name: Full name string
        
    Returns:
        List of suggested domain names
    """
    parsed = parse_name(name)
    suggestions = []
    
    if parsed["part_count"] < 2:
        first = parsed["first"].lower()
        for tld in PERSONAL_DOMAIN_TLDS:
            suggestions.append(f"{first}{tld}")
        return suggestions
    
    first = parsed["first"].lower()
    last = parsed["last"].lower()
    f = first[0]
    l = last[0]
    
    # Common personal domain patterns
    domain_patterns = [
        f"{first}{last}",
        f"{first}.{last}",
        f"{f}{last}",
        f"{first}{l}",
        f"{first}{last}{f}",
        f"{last}{first}",
    ]
    
    for pattern in domain_patterns:
        for tld in PERSONAL_DOMAIN_TLDS:
            suggestions.append(f"{pattern}{tld}")
    
    return suggestions


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
    
    # Public records / people search
    queries.append(f'"{name}" site:whitepages.com OR site:spokeo.com')
    queries.append(f'"{name}" site:peoplefinder.com OR site:pipl.com')
    
    # Academic / research
    queries.append(f'"{name}" site:scholar.google.com OR site:researchgate.net')
    queries.append(f'"{name}" site:orcid.org')
    
    # News / mentions
    queries.append(f'"{name}" site:news.google.com')
    queries.append(f'"{name}" site:medium.com OR site:substack.com')
    
    return queries


def analyze_name(name, verbose=False, email_domains=None, search_all=False):
    """
    Main function for name-based intelligence.
    
    Analyzes a name and provides:
    - Name parsing (first, middle, last)
    - Username variations
    - Email address patterns
    - Social media profile URLs
    - Personal domain suggestions
    - Search query suggestions
    
    Inspired by SpiderFoot's name analysis approach.
    
    Args:
        name: Target name
        verbose: Enable verbose output
        email_domains: Custom email domains to check
        search_all: Enable all search features (slower but comprehensive)
        
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
        print(f"  {Colors.CYAN}Generated {len(variations)} username variations:{Colors.ENDC}")
        for i, var in enumerate(variations[:15], 1):  # Show first 15
            print(f"    {i:2d}. {var}")
        if len(variations) > 15:
            print(f"    {Colors.DIM}... and {len(variations)-15} more{Colors.ENDC}")
    
    # Generate email patterns
    print(f"\n  {Colors.CYAN}[*] Generating email patterns...{Colors.ENDC}")
    emails = generate_email_patterns(name, email_domains)
    results['email_patterns'] = emails
    
    if emails:
        print(f"  {Colors.CYAN}Generated {len(emails)} email patterns:{Colors.ENDC}")
        # Group by domain for cleaner display
        shown = 0
        for domain in (email_domains or COMMON_EMAIL_DOMAINS)[:3]:  # Show first 3 domains
            domain_emails = [e for e in emails if domain in e]
            if domain_emails:
                print(f"    {Colors.DIM}@{domain}:{Colors.ENDC}")
                for email in domain_emails[:4]:  # Show 4 per domain
                    print(f"      - {email}")
                    shown += 1
        remaining = len(emails) - shown
        if remaining > 0:
            print(f"    {Colors.DIM}... and {remaining} more patterns{Colors.ENDC}")
    
    # Generate social media profile URLs
    print(f"\n  {Colors.CYAN}[*] Generating social profile URLs...{Colors.ENDC}")
    profiles = generate_social_profile_urls(name)
    results['social_profiles'] = profiles
    
    if profiles:
        print(f"  {Colors.CYAN}Found profiles on {len(profiles)} platforms:{Colors.ENDC}")
        for platform, urls in list(profiles.items())[:8]:  # Show first 8 platforms
            print(f"    {Colors.GREEN}{platform}:{Colors.ENDC}")
            for url in urls[:2]:  # Show 2 URLs per platform
                print(f"      - {url}")
        if len(profiles) > 8:
            print(f"    {Colors.DIM}... and {len(profiles)-8} more platforms{Colors.ENDC}")
    
    # Generate personal domain suggestions
    print(f"\n  {Colors.CYAN}[*] Generating domain suggestions...{Colors.ENDC}")
    domains = generate_personal_domain_suggestions(name)
    results['domain_suggestions'] = domains
    
    if domains:
        print(f"  {Colors.CYAN}Suggested personal domains:{Colors.ENDC}")
        for domain in domains[:10]:  # Show first 10
            print(f"    - {domain}")
        if len(domains) > 10:
            print(f"    {Colors.DIM}... and {len(domains)-10} more suggestions{Colors.ENDC}")
    
    # Generate search queries
    print(f"\n  {Colors.CYAN}[*] Generating search queries...{Colors.ENDC}")
    queries = suggest_search_queries(name)
    results['search_queries'] = queries
    
    if queries:
        print(f"  {Colors.CYAN}Suggested searches:{Colors.ENDC}")
        for i, query in enumerate(queries[:10], 1):  # Show first 10
            print(f"    {i:2d}. {query}")
        if len(queries) > 10:
            print(f"    {Colors.DIM}... and {len(queries)-10} more queries{Colors.ENDC}")
    
    # Additional analysis
    if verbose:
        print(f"\n  {Colors.DIM}--- Additional Analysis ---{Colors.ENDC}")
        print(f"  {Colors.DIM}Full name length: {len(name)} characters{Colors.ENDC}")
        print(f"  {Colors.DIM}Name parts: {parsed['part_count']}{Colors.ENDC}")
        if parsed['middle']:
            print(f"  {Colors.DIM}Middle names: {len(parsed['middle'])}{Colors.ENDC}")
        print(f"  {Colors.DIM}Total username variations: {len(variations)}{Colors.ENDC}")
        print(f"  {Colors.DIM}Total email patterns: {len(emails)}{Colors.ENDC}")
        print(f"  {Colors.DIM}Total social profiles: {sum(len(v) for v in profiles.values())}{Colors.ENDC}")
    
    return results
