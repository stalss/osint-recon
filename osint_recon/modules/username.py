"""Username enumeration across platforms"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from osint_recon.colors import Colors


PLATFORMS = {
    "github": "https://github.com/{}",
    "twitter": "https://twitter.com/{}",
    "x": "https://x.com/{}",
    "instagram": "https://www.instagram.com/{}/",
    "linkedin": "https://www.linkedin.com/in/{}",
    "reddit": "https://www.reddit.com/user/{}",
    "youtube": "https://www.youtube.com/@{}",
    "tiktok": "https://www.tiktok.com/@{}",
    "pinterest": "https://www.pinterest.com/{}/",
    "tumblr": "https://{}.tumblr.com",
    "medium": "https://medium.com/@{}",
    "devto": "https://dev.to/{}",
    "gitlab": "https://gitlab.com/{}",
    "bitbucket": "https://bitbucket.org/{}/",
    "keybase": "https://keybase.io/{}",
    "hackerone": "https://hackerone.com/{}",
    "bugcrowd": "https://bugcrowd.com/{}",
    "tryhackme": "https://tryhackme.com/p/{}",
    "hackthebox": "https://app.hackthebox.com/profile/{}",
    "venmo": "https://venmo.com/{}",
    "cashapp": "https://cash.app/${}",
    "roblox": "https://www.roblox.com/user.aspx?username={}",
    "steam": "https://steamcommunity.com/id/{}",
    "twitch": "https://www.twitch.tv/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "flickr": "https://www.flickr.com/people/{}",
    "behance": "https://www.behance.net/{}",
    "dribbble": "https://dribbble.com/{}",
    "etsy": "https://www.etsy.com/people/{}",
    "ebay": "https://www.ebay.com/usr/{}",
    "gravatar": "https://en.gravatar.com/{}",
    "aboutme": "https://about.me/{}",
    "fiverr": "https://www.fiverr.com/{}",
    "upwork": "https://www.upwork.com/freelancers/{}",
    "discord": "https://discord.com/users/{}",
    "pastebin": "https://pastebin.com/u/{}",
    "replit": "https://replit.com/@{}",
    "npm": "https://www.npmjs.com/~{}",
    "pypi": "https://pypi.org/user/{}/",
    "dockerhub": "https://hub.docker.com/u/{}",
    "telegram": "https://t.me/{}",
    "facebook": "https://www.facebook.com/{}",
    "mastodon": "https://mastodon.social/@{}",
    "bsky": "https://bsky.app/profile/{}.bsky.social",
}


def check_platform(platform, url, username):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url.format(username), headers=headers, timeout=10, allow_redirects=True)
        if response.status_code == 200:
            return (platform, url.format(username), True)
        elif response.status_code == 404:
            return (platform, url.format(username), False)
        else:
            return (platform, url.format(username), None)
    except requests.RequestException:
        return (platform, url.format(username), None)


def enumerate_username(username, verbose=False):
    print(f"\n{Colors.OKGREEN}[*] Username Enumeration: {username}{Colors.ENDC}")
    print(f"{Colors.WARNING}[*] Checking {len(PLATFORMS)} platforms...{Colors.ENDC}\n")

    found = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_platform, platform, url, username): platform
            for platform, url in PLATFORMS.items()
        }
        for future in as_completed(futures):
            platform, url, exists = future.result()
            if exists is True:
                found.append({"platform": platform, "url": url})
                print(f"  {Colors.OKGREEN}[+] {platform:15s} : {url}{Colors.ENDC}")
            elif exists is None and verbose:
                print(f"  {Colors.WARNING}[~] {platform:15s} : Unable to verify{Colors.ENDC}")

    print(f"\n{Colors.CYAN}[*] Found on {len(found)}/{len(PLATFORMS)} platforms{Colors.ENDC}")
    return found
