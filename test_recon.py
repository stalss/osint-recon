#!/usr/bin/env python3
"""
Test suite for OSINT Recon Tool
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recon import (
    UsernameEnumerator,
    EmailOSINT,
    DomainRecon,
    PhoneOSINT,
    NameOSINT,
    ReconTool,
)


class TestUsernameEnumerator:
    def test_initialization(self):
        enum = UsernameEnumerator("testuser")
        assert enum.username == "testuser"
        assert enum.found == []

    def test_platforms_list(self):
        enum = UsernameEnumerator("testuser")
        assert len(enum.PLATFORMS) > 20

    def test_verbose_mode(self):
        enum = UsernameEnumerator("testuser", verbose=True)
        assert enum.verbose is True


class TestEmailOSINT:
    def test_valid_email(self):
        email_osint = EmailOSINT("test@example.com")
        assert email_osint.validate_email() is True

    def test_invalid_email(self):
        email_osint = EmailOSINT("notanemail")
        assert email_osint.validate_email() is False

    def test_email_provider_gmail(self):
        email_osint = EmailOSINT("user@gmail.com")
        provider = email_osint.get_email_provider()
        assert "Gmail" in provider

    def test_email_provider_protonmail(self):
        email_osint = EmailOSINT("user@protonmail.com")
        provider = email_osint.get_email_provider()
        assert "ProtonMail" in provider

    def test_email_provider_unknown(self):
        email_osint = EmailOSINT("user@customdomain.xyz")
        provider = email_osint.get_email_provider()
        assert "Custom" in provider or "Unknown" in provider


class TestPhoneOSINT:
    def test_initialization(self):
        phone = PhoneOSINT("+1234567890")
        assert phone.phone == "+1234567890"

    def test_analysis(self):
        phone = PhoneOSINT("+1234567890")
        results = phone.analyze()
        assert 'digits' in results
        assert results['digits'] == "1234567890"


class TestNameOSINT:
    def test_full_name(self):
        name_osint = NameOSINT("John Doe")
        results = name_osint.analyze()
        assert results['first_name'] == "John"
        assert results['last_name'] == "Doe"

    def test_single_name(self):
        name_osint = NameOSINT("Madonna")
        results = name_osint.analyze()
        assert 'single_name' in results

    def test_username_variations(self):
        name_osint = NameOSINT("John Doe")
        results = name_osint.analyze()
        assert len(results['username_variations']) >= 5


class TestDomainRecon:
    def test_initialization(self):
        recon = DomainRecon("example.com")
        assert recon.target == "example.com"


class TestReconTool:
    def test_initialization(self):
        tool = ReconTool()
        assert tool.results == {}
        assert tool.verbose is False
