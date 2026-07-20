"""
Terminal colors and formatting utilities.

Provides consistent color handling across platforms.
Falls back gracefully when colorama is not installed.
"""

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

    # Provide empty fallback classes so code doesn't break
    class Fore:
        RED = GREEN = YELLOW = CYAN = BLUE = WHITE = MAGENTA = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


class Colors:
    """
    Centralized color constants for terminal output.
    
    Usage:
        print(f"{Colors.GREEN}[+] Success{Colors.ENDC}")
        print(f"{Colors.FAIL}[!] Error{Colors.ENDC}")
    """
    HEADER = Fore.BLUE if HAS_COLORAMA else ''
    OKGREEN = Fore.GREEN if HAS_COLORAMA else ''
    WARNING = Fore.YELLOW if HAS_COLORAMA else ''
    FAIL = Fore.RED if HAS_COLORAMA else ''
    CYAN = Fore.CYAN if HAS_COLORAMA else ''
    MAGENTA = Fore.MAGENTA if HAS_COLORAMA else ''
    WHITE = Fore.WHITE if HAS_COLORAMA else ''
    ENDC = Style.RESET_ALL if HAS_COLORAMA else ''
    BOLD = Style.BRIGHT if HAS_COLORAMA else ''
    DIM = Style.DIM if HAS_COLORAMA else ''


# Status indicators (like Sherlock's QueryStatus)
class Status:
    """Status indicators for scan results."""
    FOUND = f"{Colors.OKGREEN}[+]{Colors.ENDC}"
    NOT_FOUND = f"{Colors.DIM}[-]{Colors.ENDC}"
    ERROR = f"{Colors.FAIL}[!]{Colors.ENDC}"
    WARNING = f"{Colors.WARNING}[~]{Colors.ENDC}"
    INFO = f"{Colors.CYAN}[*]{Colors.ENDC}"
