"""Test suite for OSINT Recon Tool"""

import pytest
from osint_recon.modules.username import PLATFORMS, check_platform
from osint_recon.modules.email import validate_email, get_email_provider
from osint_recon.modules.phone import analyze_phone
from osint_recon.modules.name import analyze_name
from osint_recon.modules.domain import get_whois, get_dns_records
from osint_recon import __version__


class TestUsernameModule:
    def test_platforms_count(self):
        assert len(PLATFORMS) > 30

    def test_platforms_have_urls(self):
        for platform, url in PLATFORMS.items():
            assert '{}' in url or '{0}' in url


class TestEmailModule:
    def test_valid_email(self):
        assert validate_email("test@example.com") is True

    def test_invalid_email(self):
        assert validate_email("notanemail") is False

    def test_invalid_email_no_at(self):
        assert validate_email("userexample.com") is False

    def test_provider_gmail(self):
        assert "Gmail" in get_email_provider("user@gmail.com")

    def test_provider_protonmail(self):
        assert "ProtonMail" in get_email_provider("user@protonmail.com")

    def test_provider_unknown(self):
        provider = get_email_provider("user@customdomain.xyz")
        assert "Custom" in provider or "Unknown" in provider


class TestPhoneModule:
    def test_analysis_international(self):
        results = analyze_phone("+1234567890")
        assert results['digits'] == "1234567890"
        assert results['length'] == 10

    def test_analysis_local(self):
        results = analyze_phone("5551234567")
        assert results['digits'] == "5551234567"

    def test_analysis_with_dashes(self):
        results = analyze_phone("+1-234-567-890")
        assert results['digits'] == "1234567890"


class TestNameModule:
    def test_full_name(self):
        results = analyze_name("John Doe")
        assert results['first_name'] == "John"
        assert results['last_name'] == "Doe"

    def test_single_name(self):
        results = analyze_name("Madonna")
        assert 'single_name' in results

    def test_username_variations_count(self):
        results = analyze_name("John Doe")
        assert len(results['username_variations']) >= 8

    def test_three_part_name(self):
        results = analyze_name("John Michael Doe")
        assert results['first_name'] == "John"
        assert results['last_name'] == "Doe"
        assert results['middle_names'] == ["Michael"]


class TestVersion:
    def test_version_exists(self):
        assert __version__ is not None

    def test_version_format(self):
        parts = __version__.split('.')
        assert len(parts) == 3
