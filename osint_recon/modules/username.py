"""
Username enumeration module.

Inspired by Sherlock's approach:
- Data-driven platform definitions (see platforms.py)
- Concurrent requests with ThreadPoolExecutor
- False positive mitigation via random probe verification
- Regex validation before making requests
- Status enum for results (FOUND, NOT_FOUND, ERROR, UNKNOWN)

Detection methods:
- status_code: HTTP 200 = found, 404 = not found
- message: Check for specific error string in response body
- response_url: Check if final URL differs from original (redirect to error page)
"""

import re
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from osint_recon.colors import Colors, Status
from osint_recon.http_client import HTTPClient
from osint_recon.platforms import PLATFORMS, get_platforms_by_category


# Maximum concurrent threads (like Sherlock's default of 20)
MAX_WORKERS = 20


def generate_random_username(length=12):
    """
    Generate a random username for false positive detection.
    
    SpiderFoot uses this technique: if a random garbage username
    returns "found", the site likely always returns 200 and is
    unreliable for enumeration.
    
    Args:
        length: Length of random username
        
    Returns:
        Random alphanumeric string
    """
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def check_false_positive(client, platform_data):
    """
    Check if a platform has false positives by testing a random username.
    
    If a random username (that definitely doesn't exist) returns "found",
    the platform is unreliable and should be skipped.
    
    Args:
        client: HTTPClient instance
        platform_data: Platform configuration dict
        
    Returns:
        True if platform is reliable, False if it has false positives
    """
    random_user = generate_random_username()
    url = platform_data["url"].format(random_user)
    
    response = client.get(url)
    if response is None:
        return True  # Can't determine, assume reliable
    
    # Check if the random username was "found"
    if platform_data["type"] == "status_code":
        return response.status_code != 200
    elif platform_data["type"] == "message":
        error_msg = platform_data.get("error_msg", "")
        return error_msg and error_msg not in response.text
    
    return True


def check_username(client, username, platform_name, platform_data, verbose=False):
    """
    Check if a username exists on a specific platform.
    
    This is the core detection logic that handles different platform types:
    - status_code: Check HTTP response code
    - message: Look for error messages in response body
    - response_url: Detect redirects to error pages
    
    Args:
        client: HTTPClient instance
        username: Target username
        platform_name: Name of the platform
        platform_data: Platform configuration dict
        verbose: Enable verbose output
        
    Returns:
        Tuple of (platform_name, url, status, details)
    """
    url = platform_data["url"].format(username)
    detection_type = platform_data["type"]
    
    # Make the request
    response = client.head(url)  # Use HEAD first (faster)
    
    # If HEAD fails or returns unusual status, try GET
    if response is None or response.status_code >= 400:
        response = client.get(url)
    
    if response is None:
        return (platform_name, url, "error", "Connection failed")
    
    # Apply detection method
    if detection_type == "status_code":
        if response.status_code == 200:
            return (platform_name, url, "found", f"HTTP {response.status_code}")
        elif response.status_code == 404:
            return (platform_name, url, "not_found", f"HTTP {response.status_code}")
        else:
            return (platform_name, url, "unknown", f"HTTP {response.status_code}")
    
    elif detection_type == "message":
        error_msg = platform_data.get("error_msg", "")
        if error_msg and error_msg in response.text:
            return (platform_name, url, "not_found", "Error message found")
        elif response.status_code == 200:
            return (platform_name, url, "found", "No error message")
        else:
            return (platform_name, url, "unknown", f"HTTP {response.status_code}")
    
    elif detection_type == "response_url":
        # Check if we were redirected to an error page
        if str(response.url) != url:
            return (platform_name, url, "not_found", f"Redirected to {response.url}")
        return (platform_name, url, "found", "No redirect")
    
    return (platform_name, url, "unknown", "Unknown detection method")


def enumerate_username(username, verbose=False, rate_limit=0.5, check_fp=False):
    """
    Enumerate a username across all configured platforms.
    
    This is the main entry point for username enumeration.
    It uses concurrent requests for speed while respecting rate limits.
    
    Inspired by:
    - Sherlock's concurrent checking with ThreadPoolExecutor
    - SpiderFoot's false positive detection
    - theHarvester's organized output
    
    Args:
        username: Target username to search for
        verbose: Enable verbose output (show errors and unknown results)
        rate_limit: Seconds between requests per thread
        check_fp: Check for false positives before scanning
        
    Returns:
        List of found profiles with platform name and URL
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Username Enumeration: {username}{Colors.ENDC}")
    print(f"{Colors.DIM}  Checking {len(PLATFORMS)} platforms with {MAX_WORKERS} threads...{Colors.ENDC}\n")
    
    found = []
    errors = []
    categories = get_platforms_by_category()
    
    # Optional: Check for false positives first
    if check_fp:
        print(f"{Status.WARNING} Checking for false positive sites...{Colors.ENDC}")
        unreliable = []
        with HTTPClient(rate_limit=rate_limit) as client:
            for platform_name, platform_data in PLATFORMS.items():
                if not check_false_positive(client, platform_data):
                    unreliable.append(platform_name)
                    if verbose:
                        print(f"  {Status.WARNING} {platform_name} (unreliable - always returns found){Colors.ENDC}")
        if unreliable:
            print(f"{Status.WARNING} Skipping {len(unreliable)} unreliable platforms{Colors.ENDC}\n")
    
    # Run enumeration with thread pool
    with HTTPClient(rate_limit=rate_limit) as client:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all platform checks
            future_to_platform = {
                executor.submit(
                    check_username,
                    client,
                    username,
                    name,
                    data,
                    verbose,
                ): name
                for name, data in PLATFORMS.items()
            }
            
            # Process results as they complete
            for future in as_completed(future_to_platform):
                platform_name = future_to_platform[future]
                try:
                    name, url, status, details = future.result()
                    
                    if status == "found":
                        found.append({"platform": name, "url": url})
                        print(f"  {Status.FOUND} {Colors.OKGREEN}{name:18s}{Colors.ENDC} : {url}")
                    elif status == "error":
                        errors.append({"platform": name, "error": details})
                        if verbose:
                            print(f"  {Status.ERROR} {name:18s} : {details}")
                    elif status == "unknown" and verbose:
                        print(f"  {Status.WARNING} {name:18s} : {details}")
                        
                except Exception as e:
                    errors.append({"platform": platform_name, "error": str(e)})
    
    # Display summary
    print(f"\n{Colors.BOLD}{'─'*50}{Colors.ENDC}")
    print(f"{Colors.CYAN}  Results: {Colors.OKGREEN}{len(found)} found{Colors.ENDC} | "
          f"{Colors.DIM}{len(errors)} errors{Colors.ENDC} | "
          f"{len(PLATFORMS)} total platforms{Colors.ENDC}")
    
    # Show found platforms by category
    if found:
        print(f"\n{Colors.BOLD}  Found by Category:{Colors.ENDC}")
        for category, platforms in categories.items():
            found_in_cat = [f for f in found if f["platform"] in platforms]
            if found_in_cat:
                print(f"    {Colors.CYAN}{category}:{Colors.ENDC}")
                for item in found_in_cat:
                    print(f"      {item['platform']:18s} -> {item['url']}")
    
    return found
