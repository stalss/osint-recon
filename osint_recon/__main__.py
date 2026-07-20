"""
Allow running as `python -m osint_recon`.

This module enables the tool to be run as:
    python -m osint_recon [args]

Equivalent to running:
    osint-recon [args]
"""

import sys
import os

# Add the parent directory to Python path if running as module
if __name__ == "__main__":
    from osint_recon.cli import main
    main()
