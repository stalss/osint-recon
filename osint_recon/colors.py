"""Color handling for terminal output"""

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""


class Colors:
    HEADER = Fore.BLUE if hasattr(Fore, 'BLUE') else ''
    OKGREEN = Fore.GREEN if hasattr(Fore, 'GREEN') else ''
    WARNING = Fore.YELLOW if hasattr(Fore, 'YELLOW') else ''
    FAIL = Fore.RED if hasattr(Fore, 'RED') else ''
    CYAN = Fore.CYAN if hasattr(Fore, 'CYAN') else ''
    ENDC = Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''
    BOLD = Style.BRIGHT if hasattr(Style, 'BRIGHT') else ''
