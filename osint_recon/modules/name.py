"""
Name-based intelligence gathering module — real OSINT.

Goes beyond pattern generation:
- Enumerates top username variations across 48 platforms
- Deep scrapes public profiles (bio, hobbies, work, friends, connections)
- Searches DuckDuckGo for public mentions + associated accounts
- Verifies email deliverability via SMTP
- Cross-references profiles to map social graph
- Builds a complete person profile with interests and connections

Inspired by Sherlock, SpiderFoot, Maltego, Sherlock-ng.
"""

import re
import json
import socket
import smtplib
import dns.resolver
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from osint_recon.colors import Colors, Status
from osint_recon.http_client import HTTPClient
from osint_recon.platforms import PLATFORMS


# Username patterns (ranked by likelihood)
USERNAME_PATTERNS_RANKED = [
    "{first}{last}",       # mannatraj
    "{first}.{last}",      # mannat.raj
    "{first}_{last}",      # mannat_raj
    "{f}{last}",           # mraj
    "{first}{l}",          # mannatr
    "{last}{first}",       # rajmannat
    "{f}.{last}",          # m.raj
    "{first}",             # mannat
]


# Email domains to check
EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "protonmail.com", "icloud.com", "proton.me",
]


# SMTP servers
SMTP_SERVERS = {
    "gmail.com": "gmail-smtp-in.l.google.com",
    "yahoo.com": "mta5.am0.yahoodns.net",
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "protonmail.com": "mail.protonmail.ch",
    "icloud.com": "apple-com.cust.akamai.net",
    "proton.me": "mail.protonmail.ch",
}


# ── Interests / hobbies keywords to extract from bios ────────────
HOBBY_KEYWORDS = [
    "gaming", "photography", "travel", "music", "reading", "cooking",
    "fitness", "yoga", "running", "cycling", "hiking", "painting",
    "drawing", "writing", "coding", "hacke?r", "anime", "manga",
    "film", "movie", "anime", "tech", "ai", "machine learning",
    "python", "javascript", "rust", "linux", "open source", "crypto",
    "blockchain", "nft", "crypto", "startup", "entrepreneur",
    "developer", "engineer", "designer", "artist", "musician",
    "volunteer", "activist", "enviro", "sustainability", "vegan",
    "coffee", "beer", "wine", "foodie", "chef", "baker",
    "cat", "dog", "pet", "plant", "garden",
]


def parse_name(name):
    """Parse full name into components."""
    parts = name.strip().split()
    result = {"full": name, "first": "", "last": "", "middle": [], "part_count": len(parts)}
    if len(parts) == 1:
        result["first"] = parts[0]
    elif len(parts) == 2:
        result["first"], result["last"] = parts
    elif len(parts) > 2:
        result["first"] = parts[0]
        result["last"] = parts[-1]
        result["middle"] = parts[1:-1]
    return result


def generate_usernames(name, limit=10):
    """Generate ranked username variations from name."""
    parsed = parse_name(name)
    if parsed["part_count"] < 2:
        return [parsed["first"].lower()]

    first, last = parsed["first"].lower(), parsed["last"].lower()
    f, l = first[0], last[0]
    seen, usernames = set(), []
    for pattern in USERNAME_PATTERNS_RANKED:
        try:
            u = pattern.format(first=first, last=last, f=f, l=l)
            if u not in seen and len(u) >= 3:
                seen.add(u)
                usernames.append(u)
        except (IndexError, KeyError):
            continue
    return usernames[:limit]


# ── Deep profile data extraction ─────────────────────────────────

def extract_profile_data(html, platform):
    """Deep extraction of public profile data from HTML."""
    info = {}

    # og tags (universal)
    for tag, key in [
        ('og:description', 'bio'), ('og:title', 'display_name'),
        ('og:image', 'avatar'), ('og:url', 'canonical_url'),
    ]:
        m = re.search(rf'property="{tag}"\s+content="([^"]*)"', html, re.I)
        if m:
            info[key] = m.group(1).strip()

    # name="description"
    if "bio" not in info:
        m = re.search(r'name="description"\s+content="([^"]*)"', html, re.I)
        if m:
            info["bio"] = m.group(1).strip()

    # Location
    for pat in [
        r'"location"\s*:\s*"([^"]{2,60})"',
        r'(?:based in|located in|from)\s*[:\-–]\s*([^\n<"]{2,60})',
        r'<(?:span|div|p)[^>]*>\s*📍\s*([^\n<]{2,60})',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            info["location"] = m.group(1).strip()
            break

    # Followers / following
    for pat, key in [
        (r'([\d,.]+[kKmM]?)\s*followers', 'followers'),
        (r'([\d,.]+[kKmM]?)\s*following', 'following'),
        (r'([\d,.]+[kKmM]?)\s*subscribers', 'subscribers'),
        (r'([\d,.]+[kKmM]?)\s*friends', 'friends'),
    ]:
        m = re.search(pat, html, re.I)
        if m:
            info[key] = m.group(1)

    # Work / Education
    for pat, key in [
        (r'"worksAt"\s*:\s*"([^"]*)"', 'works_at'),
        (r'"company"\s*:\s*"([^"]*)"', 'works_at'),
        (r'"employer"\s*:\s*"([^"]*)"', 'works_at'),
        (r'"education"\s*:\s*"([^"]*)"', 'education'),
        (r'"school"\s*:\s*"([^"]*)"', 'education'),
        (r'"university"\s*:\s*"([^"]*)"', 'education'),
    ]:
        m = re.search(pat, html, re.I)
        if m and m.group(1):
            info[key] = m.group(1).strip()

    # Skills / Technologies (GitHub, LinkedIn)
    skills_match = re.findall(r'"skill[s]?"\s*:\s*\[([^\]]+)\]', html, re.I)
    if skills_match:
        info["skills"] = [s.strip().strip('"') for s in skills_match[0].split(",")][:10]

    # Languages (GitHub repos)
    langs_match = re.findall(r'"language"\s*:\s*"([^"]+)"', html, re.I)
    if langs_match:
        info["languages"] = list(set(langs_match))[:8]

    # Public email
    email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', html)
    if email_match:
        email = email_match.group(0)
        junk = ["example", "test", "null", "noreply", "email", "sentry"]
        if not any(x in email.lower() for x in junk):
            info["email"] = email

    # Extract mentioned usernames / connections from page
    connections = set()

    # GitHub followers / following links
    gh_users = re.findall(r'href="/([^/"]+)"[^>]*class="[^"]*(?:avatar|user-link)[^"]*"', html)
    for u in gh_users[:20]:
        if u and not u.startswith((".", "orgs", "settings", "notifications")):
            connections.add(u)

    # Twitter/Instagram mentioned users
    mentions = re.findall(r'@(\w{2,30})', html)
    # Filter out common non-user words
    stopwords = {"http", "https", "www", "com", "org", "net", "the", "and", "for"}
    for m in mentions:
        if m.lower() not in stopwords:
            connections.add(m)

    # LinkedIn connections (public)
    li_connections = re.findall(r'/in/([a-zA-Z0-9._-]+)', html)
    for c in li_connections[:20]:
        connections.add(c)

    if connections:
        info["connections"] = list(connections)[:15]

    # Hobbies / Interests extraction from bio
    bio_text = info.get("bio", "").lower() + " " + html.lower()
    hobbies = []
    for kw in HOBBY_KEYWORDS:
        if re.search(rf'\b{kw}\b', bio_text):
            hobbies.append(kw.replace("\\", ""))
    if hobbies:
        info["hobbies"] = list(set(hobbies))[:10]

    return info


def check_username_exists(client, username, platform_name, platform_data):
    """Check if username exists and return deep profile data."""
    url = platform_data["url"].format(username)
    detection = platform_data["type"]

    response = client.head(url)
    if response is None or response.status_code >= 400:
        response = client.get(url)
    if response is None:
        return None

    found = False
    if detection == "status_code":
        found = response.status_code == 200
    elif detection == "message":
        err = platform_data.get("error_msg", "")
        found = response.status_code == 200 and (not err or err not in response.text)
    elif detection == "response_url":
        found = str(response.url) == url

    if not found:
        return None

    data = extract_profile_data(response.text, platform_name)
    return {"platform": platform_name, "url": url, "username": username, "data": data}


def search_username_across_platforms(username, rate_limit=0.5):
    """Check a single username across all platforms."""
    found = []
    with HTTPClient(rate_limit=rate_limit) as client:
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(check_username_exists, client, username, name, data): name
                for name, data in PLATFORMS.items()
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
    return found


# ── Email verification ───────────────────────────────────────────

def verify_email_smtp(email):
    """Verify if email might exist via SMTP."""
    domain = email.split("@")[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange).rstrip('.')
        with smtplib.SMTP(mx_host, 25, timeout=5) as smtp:
            smtp.ehlo("osint-recon.local")
            smtp.mail("test@osint-recon.local")
            code, _ = smtp.rcpt(email)
            if code == 250:
                return {"email": email, "status": "valid", "reason": "SMTP accepted"}
            return {"email": email, "status": "rejected", "reason": f"SMTP {code}"}
    except smtplib.SMTPResponseException as e:
        return {"email": email, "status": "rejected", "reason": f"SMTP {e.smtp_code}"}
    except Exception as e:
        return {"email": email, "status": "unknown", "reason": str(e)[:40]}


# ── Web search + connection discovery ────────────────────────────

def search_web_mentions(name, rate_limit=1.0):
    """Search DuckDuckGo for public mentions and connected accounts."""
    queries = [
        f'"{name}"',
        f'"{name}" site:linkedin.com',
        f'"{name}" site:github.com',
        f'"{name}" site:twitter.com OR site:instagram.com',
        f'"{name}" friends OR contacts OR connections',
    ]
    mentions = []

    with HTTPClient(rate_limit=rate_limit) as client:
        for query in queries:
            try:
                response = client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": query}
                )
                if not response or response.status_code != 200:
                    continue
                results = re.findall(
                    r'<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?'
                    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                    response.text, re.DOTALL
                )
                for link, title, snippet in results[:4]:
                    title = re.sub(r'<[^>]+>', '', title).strip()
                    snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                    url_m = re.search(r'uddg=([^&]+)', link)
                    actual_url = unquote(url_m.group(1)) if url_m else link
                    mentions.append({
                        "title": title,
                        "url": actual_url,
                        "snippet": snippet[:300],
                        "query": query,
                    })
            except Exception:
                continue
    return mentions


def discover_connections_from_web(mentions, rate_limit=1.0):
    """Scrape found profile pages for friend/connection names."""
    connection_hints = []
    urls_to_check = [m["url"] for m in mentions if any(
        p in m["url"] for p in ["linkedin.com", "github.com", "twitter.com", "instagram.com"]
    )][:5]

    with HTTPClient(rate_limit=rate_limit) as client:
        for url in urls_to_check:
            try:
                resp = client.get(url)
                if not resp or resp.status_code != 200:
                    continue
                html = resp.text

                # Extract any human names mentioned
                # Pattern: "Name Name" in title or headings
                name_mentions = re.findall(
                    r'<(?:h[1-6]|span|a)[^>]*>\s*([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?)\s*<',
                    html
                )
                for n in name_mentions[:5]:
                    if len(n) > 4:
                        connection_hints.append({
                            "name": n.strip(),
                            "source_url": url,
                            "source_platform": re.search(r'://(?:www\.)?(\w+)', url).group(1),
                        })
            except Exception:
                continue

    return connection_hints


# ── Main analysis ────────────────────────────────────────────────

def analyze_name_intel(name, verbose=False, rate_limit=0.5, deep_scan=False):
    """
    Real intelligence gathering for a person by name.

    1. Parse name, generate ranked usernames
    2. Check usernames across 48 platforms
    3. Deep scrape profiles: bio, hobbies, work, connections, skills
    4. Verify email patterns via SMTP
    5. Search web for mentions + associated accounts
    6. Scrape found profiles for friend/connection names
    7. Aggregate into a complete person profile

    Args:
        name: Full name (e.g., "Mannat Raj")
        verbose: Show all output
        rate_limit: Seconds between requests
        deep_scan: Also verify emails + search web + find connections (slower)

    Returns:
        Dict with aggregated person profile
    """
    parsed = parse_name(name)
    profile = {
        "name": parsed,
        "usernames_found": [],
        "profiles": [],
        "emails_found": [],
        "web_mentions": [],
        "connections": [],       # people connected to this person
        "all_hobbies": [],       # aggregated hobbies across platforms
        "all_skills": [],        # aggregated skills/tech
        "all_locations": [],     # all locations found
        "all_workplaces": [],    # work/education
        "social_graph": {},      # username -> list of connected usernames
    }

    print(f"\n{'='*65}")
    print(f"  PERSON INTELLIGENCE: {name}")
    print(f"{'='*65}\n")

    # ── Step 1: Generate and check usernames ──────────────────────
    print(f"{Status.INFO} {Colors.BOLD}[1/5]{Colors.ENDC} Generating username variations...")
    usernames = generate_usernames(name)
    print(f"  Testing {len(usernames)} usernames across {len(PLATFORMS)} platforms...\n")

    for username in usernames:
        print(f"  {Colors.CYAN}Checking: {username}{Colors.ENDC}")
        found = search_username_across_platforms(username, rate_limit)
        if found:
            print(f"    {Colors.OKGREEN}Found on {len(found)} platforms{Colors.ENDC}")
            for f in found:
                profile["profiles"].append(f)
                profile["usernames_found"].append(username)
                # Aggregate data
                data = f.get("data", {})
                if data.get("hobbies"):
                    profile["all_hobbies"].extend(data["hobbies"])
                if data.get("skills"):
                    profile["all_skills"].extend(data["skills"])
                if data.get("languages"):
                    profile["all_skills"].extend(data["languages"])
                if data.get("location"):
                    profile["all_locations"].append(data["location"])
                if data.get("works_at"):
                    profile["all_workplaces"].append(data["works_at"])
                if data.get("education"):
                    profile["all_workplaces"].append(data["education"])
                if data.get("connections"):
                    profile["social_graph"].setdefault(username, []).extend(data["connections"])
        else:
            if verbose:
                print(f"    {Colors.DIM}Not found{Colors.ENDC}")

    # Deduplicate
    seen_urls = set()
    unique = []
    for p in profile["profiles"]:
        if p["url"] not in seen_urls:
            seen_urls.add(p["url"])
            unique.append(p)
    profile["profiles"] = unique

    # Deduplicate aggregates
    profile["all_hobbies"] = list(set(profile["all_hobbies"]))
    profile["all_skills"] = list(set(profile["all_skills"]))
    profile["all_locations"] = list(set(profile["all_locations"]))
    profile["all_workplaces"] = list(set(profile["all_workplaces"]))

    # ── Step 2: Display found profiles with details ───────────────
    print(f"\n{'─'*65}")
    print(f"{Status.INFO} {Colors.BOLD}[2/5]{Colors.ENDC} Found profiles:")
    print(f"{'─'*65}\n")

    if profile["profiles"]:
        for p in profile["profiles"]:
            data = p.get("data", {})
            print(f"  {Colors.OKGREEN}✓ {p['platform']}{Colors.ENDC}")
            print(f"    URL:        {p['url']}")
            if data.get("display_name"):
                print(f"    Name:       {data['display_name']}")
            if data.get("bio"):
                print(f"    Bio:        {data['bio'][:120]}")
            if data.get("location"):
                print(f"    Location:   {data['location']}")
            if data.get("works_at"):
                print(f"    Works at:   {data['works_at']}")
            if data.get("education"):
                print(f"    Education:  {data['education']}")
            if data.get("followers"):
                print(f"    Followers:  {data['followers']}")
            if data.get("hobbies"):
                print(f"    Hobbies:    {', '.join(data['hobbies'])}")
            if data.get("skills"):
                print(f"    Skills:     {', '.join(data['skills'][:6])}")
            if data.get("connections"):
                print(f"    Connected:  {', '.join(data['connections'][:5])}")
            if data.get("email"):
                print(f"    Email:      {data['email']}")
                profile["emails_found"].append(data["email"])
            print()
    else:
        print(f"  {Colors.DIM}No profiles found with generated usernames{Colors.ENDC}\n")

    # ── Step 3: Email verification ────────────────────────────────
    if deep_scan:
        print(f"{'─'*65}")
        print(f"{Status.INFO} {Colors.BOLD}[3/5]{Colors.ENDC} Verifying email patterns...")
        print(f"{'─'*65}\n")
        first, last = parsed["first"].lower(), parsed["last"].lower()
        f = first[0] if first else ""
        email_patterns = [f"{first}.{last}", f"{first}{last}", f"{f}{last}", f"{first}"]

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {
                ex.submit(verify_email_smtp, f"{p}@{d}"): f"{p}@{d}"
                for p in email_patterns for d in EMAIL_DOMAINS[:3]
            }
            for fut in as_completed(futures):
                r = fut.result()
                if r["status"] == "valid":
                    print(f"  {Colors.OKGREEN}✓ {r['email']}{Colors.ENDC} — {r['reason']}")
                    profile["emails_found"].append(r["email"])
                elif verbose:
                    print(f"  {Colors.DIM}✗ {r['email']} — {r['reason']}{Colors.ENDC}")
    else:
        print(f"  {Colors.DIM}[3/5] Email verification skipped (--deep to enable){Colors.ENDC}\n")

    # ── Step 4: Web search ────────────────────────────────────────
    if deep_scan:
        print(f"\n{'─'*65}")
        print(f"{Status.INFO} {Colors.BOLD}[4/5]{Colors.ENDC} Searching web for mentions...")
        print(f"{'─'*65}\n")

        mentions = search_web_mentions(name, rate_limit)
        profile["web_mentions"] = mentions

        if mentions:
            for m in mentions[:8]:
                print(f"  {Colors.OKGREEN}→ {m['title']}{Colors.ENDC}")
                print(f"    {m['url']}")
                if m.get("snippet"):
                    print(f"    {Colors.DIM}{m['snippet'][:150]}...{Colors.ENDC}")
                print()
        else:
            print(f"  {Colors.DIM}No web mentions found{Colors.ENDC}\n")

        # ── Step 5: Find connections ──────────────────────────────
        print(f"{'─'*65}")
        print(f"{Status.INFO} {Colors.BOLD}[5/5]{Colors.ENDC} Discovering connections...")
        print(f"{'─'*65}\n")

        web_connections = discover_connections_from_web(mentions, rate_limit)
        profile["connections"] = web_connections

        if web_connections:
            print(f"  {Colors.CYAN}People connected to {name}:{Colors.ENDC}")
            seen_names = set()
            for c in web_connections:
                if c["name"] not in seen_names:
                    seen_names.add(c["name"])
                    print(f"    • {c['name']}  ({c['source_platform']})")
        else:
            print(f"  {Colors.DIM}No connections discovered from web{Colors.ENDC}\n")
    else:
        print(f"  {Colors.DIM}[4/5] Web search skipped (--deep to enable){Colors.ENDC}")
        print(f"  {Colors.DIM}[5/5] Connection discovery skipped (--deep to enable){Colors.ENDC}\n")

    # ── Final Summary ─────────────────────────────────────────────
    all_connected_users = set()
    for users in profile["social_graph"].values():
        all_connected_users.update(users)

    print(f"{'='*65}")
    print(f"  COMPLETE PERSON PROFILE: {name}")
    print(f"{'='*65}")
    print(f"  Accounts found:       {len(profile['profiles'])}")
    print(f"  Platforms active:     {len(set(p['platform'] for p in profile['profiles']))}")
    print(f"  Emails discovered:    {len(profile['emails_found'])}")
    print(f"  Known hobbies:        {', '.join(profile['all_hobbies'][:8]) or 'N/A'}")
    print(f"  Skills / Tech:        {', '.join(profile['all_skills'][:8]) or 'N/A'}")
    print(f"  Locations:            {', '.join(profile['all_locations'][:3]) or 'N/A'}")
    print(f"  Work / Education:     {', '.join(profile['all_workplaces'][:3]) or 'N/A'}")
    print(f"  Connected accounts:   {len(all_connected_users)} usernames")
    print(f"  Connected people:     {len(profile['connections'])}")
    print(f"  Web mentions:         {len(profile['web_mentions'])}")
    print(f"{'='*65}\n")

    return profile
