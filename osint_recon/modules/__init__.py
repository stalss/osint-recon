"""
OSINT Recon modules.

Each module provides a focused recon capability:
- username: Username enumeration across platforms
- email: Email intelligence gathering
- domain: Domain and IP reconnaissance
- phone: Phone number analysis
- name: Name-based intelligence
"""

from osint_recon.modules.username import enumerate_username
from osint_recon.modules.email import gather_email_intel
from osint_recon.modules.domain import recon_domain
from osint_recon.modules.phone import analyze_phone
from osint_recon.modules.name import analyze_name

__all__ = [
    "enumerate_username",
    "gather_email_intel",
    "recon_domain",
    "analyze_phone",
    "analyze_name",
]
