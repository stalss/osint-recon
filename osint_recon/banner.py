"""
Banner display for the tool.

Shows tool name, version, and ASCII art on startup.
"""

from osint_recon.colors import Colors
from osint_recon import __version__


def show_banner():
    """
    Display the tool banner with ASCII art.
    
    The banner includes:
    - Tool name in ASCII art
    - Version number
    - Brief description
    """
    print(f"""
{Colors.HEADER}{Colors.BOLD}    ███████╗██╗███╗   ███╗██████╗ ██╗██████╗ ███████╗
    ██╔════╝██║████╗ ████║██╔══██╗██║██╔══██╗██╔════╝
    ███████╗██║██╔████╔██║██████╔╝██║██████╔╝█████╗  
    ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║██╔══██╗██╔══╝  
    ███████║██║██║ ╚═╝ ██║██║     ██║██║  ██║███████╗
    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝{Colors.ENDC}
{Colors.WARNING}    OSINT Recon Tool v{__version__} - Full Person Reconnaissance
{Colors.DIM}    Inspired by Sherlock, theHarvester, SpiderFoot, Recon-ng{Colors.ENDC}
""")


def show_scan_header(target, mode):
    """
    Display scan header with target and mode info.
    
    Args:
        target: The target being scanned
        mode: The recon mode being used
    """
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.CYAN}  Target : {Colors.WHITE}{target}{Colors.ENDC}")
    print(f"{Colors.CYAN}  Mode   : {Colors.WHITE}{mode}{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")


def show_section(title):
    """Display a section header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'─'*50}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {title}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'─'*50}{Colors.ENDC}")


def show_results_summary(results):
    """
    Display a summary of scan results.
    
    Args:
        results: Dictionary of scan results
    """
    total_found = 0
    for key, value in results.items():
        if isinstance(value, list):
            total_found += len(value)
        elif isinstance(value, dict):
            total_found += 1
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}  Scan Complete! Found {total_found} result(s){Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
