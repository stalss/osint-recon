"""
Platform definitions for username enumeration.

Inspired by Sherlock's data.json approach:
- Each platform is defined as data, not code
- Easy to add new platforms without modifying logic
- Includes error detection patterns and regex validation

Platform types:
- status_code: Check HTTP status code (200 = found, 404 = not found)
- message: Check for specific error message in response body
- response_url: Check if URL changed (redirect to error page)

To add a new platform, simply add an entry to the PLATFORMS dict.
"""

# Platform definitions for username enumeration
# Each entry maps platform name -> {
#   "url": URL template with {} for username,
#   "type": Detection method ("status_code", "message", "response_url"),
#   "error_msg": (optional) String that indicates username NOT found,
#   "regex": (optional) Regex pattern to validate username before checking,
#   "category": Grouping for output display
# }
PLATFORMS = {
    # ===== Social Media =====
    "twitter": {
        "url": "https://x.com/{}",
        "type": "status_code",
        "category": "Social Media",
    },
    "instagram": {
        "url": "https://www.instagram.com/{}/",
        "type": "message",
        "error_msg": "Sorry, this page isn't available",
        "category": "Social Media",
    },
    "facebook": {
        "url": "https://www.facebook.com/{}",
        "type": "status_code",
        "category": "Social Media",
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{}",
        "type": "message",
        "error_msg": "Couldn't find this account",
        "category": "Social Media",
    },
    "youtube": {
        "url": "https://www.youtube.com/@{}",
        "type": "status_code",
        "category": "Social Media",
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{}/",
        "type": "status_code",
        "category": "Social Media",
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "type": "status_code",
        "category": "Social Media",
    },
    "tumblr": {
        "url": "https://{}.tumblr.com",
        "type": "status_code",
        "category": "Social Media",
    },
    "mastodon": {
        "url": "https://mastodon.social/@{}",
        "type": "status_code",
        "category": "Social Media",
    },
    "bluesky": {
        "url": "https://bsky.app/profile/{}.bsky.social",
        "type": "status_code",
        "category": "Social Media",
    },
    "snapchat": {
        "url": "https://www.snapchat.com/add/{}",
        "type": "status_code",
        "category": "Social Media",
    },
    "telegram": {
        "url": "https://t.me/{}",
        "type": "message",
        "error_msg": "If you have <strong>Telegram</strong>",
        "category": "Social Media",
    },
    "whatsapp": {
        "url": "https://wa.me/{}",
        "type": "status_code",
        "category": "Social Media",
    },
    
    # ===== Developer Platforms =====
    "github": {
        "url": "https://github.com/{}",
        "type": "status_code",
        "category": "Developer",
    },
    "gitlab": {
        "url": "https://gitlab.com/{}",
        "type": "status_code",
        "category": "Developer",
    },
    "bitbucket": {
        "url": "https://bitbucket.org/{}/",
        "type": "status_code",
        "category": "Developer",
    },
    "devto": {
        "url": "https://dev.to/{}",
        "type": "status_code",
        "category": "Developer",
    },
    "medium": {
        "url": "https://medium.com/@{}",
        "type": "status_code",
        "category": "Developer",
    },
    "replit": {
        "url": "https://replit.com/@{}",
        "type": "status_code",
        "category": "Developer",
    },
    "npm": {
        "url": "https://www.npmjs.com/~{}",
        "type": "status_code",
        "category": "Developer",
    },
    "pypi": {
        "url": "https://pypi.org/user/{}/",
        "type": "status_code",
        "category": "Developer",
    },
    "dockerhub": {
        "url": "https://hub.docker.com/u/{}",
        "type": "status_code",
        "category": "Developer",
    },
    "keybase": {
        "url": "https://keybase.io/{}",
        "type": "status_code",
        "category": "Developer",
    },
    
    # ===== Gaming =====
    "steam": {
        "url": "https://steamcommunity.com/id/{}",
        "type": "status_code",
        "category": "Gaming",
    },
    "twitch": {
        "url": "https://www.twitch.tv/{}",
        "type": "status_code",
        "category": "Gaming",
    },
    "roblox": {
        "url": "https://www.roblox.com/user.aspx?username={}",
        "type": "status_code",
        "category": "Gaming",
    },
    "discord": {
        "url": "https://discord.com/users/{}",
        "type": "status_code",
        "category": "Gaming",
    },
    "minecraft": {
        "url": "https://namemc.com/profile/{}",
        "type": "status_code",
        "category": "Gaming",
    },
    
    # ===== Professional =====
    "linkedin": {
        "url": "https://www.linkedin.com/in/{}",
        "type": "status_code",
        "category": "Professional",
    },
    "fiverr": {
        "url": "https://www.fiverr.com/{}",
        "type": "status_code",
        "category": "Professional",
    },
    "upwork": {
        "url": "https://www.upwork.com/freelancers/{}",
        "type": "status_code",
        "category": "Professional",
    },
    "behance": {
        "url": "https://www.behance.net/{}",
        "type": "status_code",
        "category": "Professional",
    },
    "dribbble": {
        "url": "https://dribbble.com/{}",
        "type": "status_code",
        "category": "Professional",
    },
    
    # ===== Finance =====
    "venmo": {
        "url": "https://venmo.com/{}",
        "type": "status_code",
        "category": "Finance",
    },
    "cashapp": {
        "url": "https://cash.app/${}",
        "type": "status_code",
        "category": "Finance",
    },
    
    # ===== Creative =====
    "soundcloud": {
        "url": "https://soundcloud.com/{}",
        "type": "status_code",
        "category": "Creative",
    },
    "flickr": {
        "url": "https://www.flickr.com/people/{}",
        "type": "status_code",
        "category": "Creative",
    },
    "etsy": {
        "url": "https://www.etsy.com/people/{}",
        "type": "status_code",
        "category": "Creative",
    },
    
    # ===== E-commerce =====
    "ebay": {
        "url": "https://www.ebay.com/usr/{}",
        "type": "status_code",
        "category": "E-commerce",
    },
    
    # ===== Security/Hacking =====
    "hackerone": {
        "url": "https://hackerone.com/{}",
        "type": "status_code",
        "category": "Security",
    },
    "bugcrowd": {
        "url": "https://bugcrowd.com/{}",
        "type": "status_code",
        "category": "Security",
    },
    "tryhackme": {
        "url": "https://tryhackme.com/p/{}",
        "type": "status_code",
        "category": "Security",
    },
    "hackthebox": {
        "url": "https://app.hackthebox.com/profile/{}",
        "type": "status_code",
        "category": "Security",
    },
    "rootme": {
        "url": "https://www.root-me.org/{}",
        "type": "status_code",
        "category": "Security",
    },
    
    # ===== Other =====
    "gravatar": {
        "url": "https://en.gravatar.com/{}",
        "type": "status_code",
        "category": "Other",
    },
    "aboutme": {
        "url": "https://about.me/{}",
        "type": "status_code",
        "category": "Other",
    },
    "pastebin": {
        "url": "https://pastebin.com/u/{}",
        "type": "status_code",
        "category": "Other",
    },
    "wikimedia": {
        "url": "https://meta.wikimedia.org/wiki/User:{}",
        "type": "status_code",
        "category": "Other",
    },
    "producthunt": {
        "url": "https://www.producthunt.com/@{}",
        "type": "status_code",
        "category": "Other",
    },
    "hubspot": {
        "url": "https://app.hubspot.com/{}",
        "type": "status_code",
        "category": "Other",
    },
}


def get_platforms_by_category():
    """Group platforms by category for organized output."""
    categories = {}
    for name, data in PLATFORMS.items():
        cat = data.get("category", "Other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(name)
    return categories


def get_platform_count():
    """Return total number of defined platforms."""
    return len(PLATFORMS)
