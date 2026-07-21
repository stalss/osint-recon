"""
HTTP client with rate limiting, User-Agent rotation, and proxy support.

Inspired by:
- theHarvester's AsyncFetcher (proxy rotation, SSL handling)
- Sherlock's FuturesSession (concurrent requests with timeout)
- SpiderFoot's configurable fetch timeout and retry logic

Key features:
- Random User-Agent rotation to avoid detection
- Configurable rate limiting between requests
- Proxy support (HTTP/SOCKS5)
- Automatic retry with exponential backoff
- Timeout management
"""

import time
import random
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Curated list of realistic User-Agent strings
# Rotating these helps avoid detection by anti-bot systems
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]


class HTTPClient:
    """
    Centralized HTTP client for all network requests.
    
    Handles:
    - User-Agent rotation (random per request)
    - Rate limiting (configurable delay between requests)
    - Proxy support (HTTP/SOCKS5)
    - Automatic retries with exponential backoff
    - Connection pooling via requests.Session
    
    Usage:
        client = HTTPClient(rate_limit=1.0, proxy="http://proxy:8080")
        response = client.get("https://example.com")
        
        # Or use as a context manager
        with HTTPClient(rate_limit=0.5) as client:
            for url in urls:
                resp = client.get(url)
    """
    
    def __init__(self, rate_limit=0.5, timeout=10, proxy=None, retries=3):
        """
        Initialize the HTTP client.
        
        Args:
            rate_limit: Minimum seconds between requests (0 = no limit)
            timeout: Request timeout in seconds
            proxy: Proxy URL (e.g., "http://proxy:8080" or "socks5://proxy:1080")
            retries: Number of retries for failed requests
        """
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.last_request_time = 0
        self.request_count = 0
        self._lock = threading.Lock()
        
        # Create a session with connection pooling and retry strategy
        self.session = requests.Session()
        
        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,  # Wait 1, 2, 4 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
    
    def _wait_for_rate_limit(self):
        """Enforce rate limiting between requests (thread-safe)."""
        if self.rate_limit > 0:
            with self._lock:
                now = time.time()
                elapsed = now - self.last_request_time
                if elapsed < self.rate_limit:
                    sleep_time = self.rate_limit - elapsed + random.uniform(0, 0.5)
                    self.last_request_time = now + sleep_time
                    time.sleep(sleep_time)
                else:
                    self.last_request_time = now
    
    def _get_headers(self):
        """Generate request headers with random User-Agent."""
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    
    def get(self, url, allow_redirects=True, **kwargs):
        """
        Make a GET request with rate limiting and header rotation.
        
        Args:
            url: Target URL
            allow_redirects: Whether to follow redirects
            **kwargs: Additional arguments passed to requests.get
            
        Returns:
            requests.Response object or None on failure
        """
        self._wait_for_rate_limit()
        
        headers = self._get_headers()
        headers.update(kwargs.pop("headers", {}))
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
            with self._lock:
                self.last_request_time = time.time()
                self.request_count += 1
            return response
            
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.TooManyRedirects:
            return None
        except requests.exceptions.RequestException:
            return None
    
    def head(self, url, **kwargs):
        """Make a HEAD request (lighter than GET, useful for existence checks)."""
        self._wait_for_rate_limit()
        
        headers = self._get_headers()
        headers.update(kwargs.pop("headers", {}))
        
        try:
            response = self.session.head(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,  # Don't follow redirects for HEAD
                **kwargs,
            )
            with self._lock:
                self.last_request_time = time.time()
                self.request_count += 1
            return response
        except requests.exceptions.RequestException:
            return None
    
    def close(self):
        """Close the underlying session and release connections."""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __repr__(self):
        return f"HTTPClient(rate_limit={self.rate_limit}, timeout={self.timeout}, requests={self.request_count})"
