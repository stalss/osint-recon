"""
Test suite for OSINT Recon Tool.

Tests cover:
- Username enumeration logic
- Email validation and provider detection
- Phone number analysis
- Name parsing and username generation
- Domain reconnaissance utilities
- HTTP client functionality
"""

import pytest
from osint_recon.modules.username import (
    generate_random_username,
    check_false_positive,
    check_username,
    enumerate_username,
)
from osint_recon.modules.email import (
    validate_email,
    get_email_provider,
    get_mx_records,
    check_breach_pwned,
)
from osint_recon.modules.phone import (
    normalize_phone,
    detect_format,
    validate_phone,
    format_as_e164,
    analyze_phone,
    COUNTRY_CODES,
)
from osint_recon.modules.name import (
    parse_name,
    generate_username_variations,
    suggest_search_queries,
    analyze_name,
)
from osint_recon.modules.domain import (
    get_whois,
    get_dns_records,
    get_ssl_certificate,
)
from osint_recon.http_client import HTTPClient
from osint_recon.colors import Colors, Status
from osint_recon import __version__
from osint_recon.platforms import PLATFORMS as ALL_PLATFORMS, get_platforms_by_category, get_platform_count


# ===== Username Module Tests =====

class TestUsernameModule:
    """Tests for username enumeration module."""
    
    def test_platforms_defined(self):
        """Verify platforms are defined."""
        assert len(ALL_PLATFORMS) > 30
    
    def test_platforms_have_required_fields(self):
        """Each platform must have url and type."""
        for name, data in ALL_PLATFORMS.items():
            assert "url" in data, f"{name} missing 'url'"
            assert "type" in data, f"{name} missing 'type'"
            assert data["type"] in ["status_code", "message", "response_url"], \
                f"{name} has invalid type: {data['type']}"
    
    def test_platforms_have_category(self):
        """Each platform should have a category."""
        for name, data in ALL_PLATFORMS.items():
            assert "category" in data, f"{name} missing 'category'"
    
    def test_platforms_have_error_msg_for_message_type(self):
        """Message-type platforms need an error_msg."""
        for name, data in ALL_PLATFORMS.items():
            if data["type"] == "message":
                assert "error_msg" in data, f"{name} uses message type but has no error_msg"
    
    def test_random_username_generation(self):
        """Random usernames should be the right length."""
        username = generate_random_username(12)
        assert len(username) == 12
        assert username.isalnum()
    
    def test_platforms_by_category(self):
        """Platforms should be groupable by category."""
        categories = get_platforms_by_category()
        assert len(categories) > 5
        assert "Social Media" in categories
        assert "Developer" in categories
    
    def test_platform_count(self):
        """Platform count should match."""
        assert get_platform_count() == len(ALL_PLATFORMS)


# ===== Email Module Tests =====

class TestEmailModule:
    """Tests for email intelligence module."""
    
    def test_valid_email(self):
        assert validate_email("user@example.com") is True
    
    def test_valid_email_with_dots(self):
        assert validate_email("first.last@example.com") is True
    
    def test_valid_email_with_plus(self):
        assert validate_email("user+tag@example.com") is True
    
    def test_invalid_email_no_at(self):
        assert validate_email("userexample.com") is False
    
    def test_invalid_email_no_domain(self):
        assert validate_email("user@") is False
    
    def test_invalid_email_no_tld(self):
        assert validate_email("user@example") is False
    
    def test_provider_gmail(self):
        provider = get_email_provider("user@gmail.com")
        assert "Gmail" in provider["name"]
        assert provider["encrypted"] is False
    
    def test_provider_protonmail(self):
        provider = get_email_provider("user@protonmail.com")
        assert "ProtonMail" in provider["name"]
        assert provider["encrypted"] is True
    
    def test_provider_tutanota(self):
        provider = get_email_provider("user@tutanota.com")
        assert "Tutanota" in provider["name"]
        assert provider["encrypted"] is True
    
    def test_provider_unknown(self):
        provider = get_email_provider("user@customdomain.xyz")
        assert "Custom" in provider["name"]


# ===== Phone Module Tests =====

class TestPhoneModule:
    """Tests for phone number analysis module."""
    
    def test_normalize_phone(self):
        assert normalize_phone("+1 (234) 567-890") == "+1234567890"
    
    def test_normalize_phone_dashes(self):
        assert normalize_phone("+1-234-567-890") == "+1234567890"
    
    def test_normalize_phone_spaces(self):
        assert normalize_phone("+1 234 567 890") == "+1234567890"
    
    def test_detect_international_format(self):
        result = detect_format("+1234567890")
        assert result["is_international"] is True
        assert result["format"] == "international"
    
    def test_detect_national_format(self):
        result = detect_format("5551234567")
        assert result["is_international"] is False
        assert "10-digit" in result["format"]
    
    def test_detect_us_country_code(self):
        result = detect_format("+15551234567")
        assert result.get("country") == "United States/Canada"
    
    def test_validate_too_short(self):
        is_valid, reason = validate_phone("123")
        assert is_valid is False
        assert "short" in reason.lower()
    
    def test_validate_too_long(self):
        is_valid, reason = validate_phone("+12345678901234567890123")
        assert is_valid is False
        assert "long" in reason.lower()
    
    def test_validate_valid(self):
        is_valid, reason = validate_phone("+1234567890")
        assert is_valid is True
    
    def test_format_e164(self):
        result = format_as_e164("5551234567")
        assert result == "+15551234567"
    
    def test_format_e164_already(self):
        result = format_as_e164("+15551234567")
        assert result == "+15551234567"
    
    def test_country_codes_exist(self):
        assert "1" in COUNTRY_CODES
        assert "44" in COUNTRY_CODES
        assert "81" in COUNTRY_CODES


# ===== Name Module Tests =====

class TestNameModule:
    """Tests for name intelligence module."""
    
    def test_parse_two_part_name(self):
        result = parse_name("John Doe")
        assert result["first"] == "John"
        assert result["last"] == "Doe"
        assert result["type"] == "standard"
    
    def test_parse_three_part_name(self):
        result = parse_name("John Michael Doe")
        assert result["first"] == "John"
        assert result["last"] == "Doe"
        assert result["middle"] == ["Michael"]
        assert result["type"] == "compound"
    
    def test_parse_single_name(self):
        result = parse_name("Madonna")
        assert result["first"] == "Madonna"
        assert result["type"] == "single"
    
    def test_parse_four_part_name(self):
        result = parse_name("John Michael Van Doe")
        assert result["first"] == "John"
        assert result["last"] == "Doe"
        assert result["middle"] == ["Michael", "Van"]
    
    def test_username_variations_count(self):
        variations = generate_username_variations("John Doe")
        assert len(variations) >= 20
    
    def test_username_variations_no_duplicates(self):
        variations = generate_username_variations("John Doe")
        assert len(variations) == len(set(variations))
    
    def test_search_queries_generated(self):
        queries = suggest_search_queries("John Doe")
        assert len(queries) >= 5
        assert any("linkedin" in q for q in queries)
        assert any("twitter" in q for q in queries)


# ===== HTTP Client Tests =====

class TestHTTPClient:
    """Tests for HTTP client module."""
    
    def test_initialization(self):
        client = HTTPClient()
        assert client.rate_limit == 0.5
        assert client.timeout == 10
    
    def test_custom_rate_limit(self):
        client = HTTPClient(rate_limit=2.0)
        assert client.rate_limit == 2.0
    
    def test_context_manager(self):
        with HTTPClient() as client:
            assert client is not None
    
    def test_repr(self):
        client = HTTPClient()
        assert "HTTPClient" in repr(client)


# ===== Version Tests =====

class TestVersion:
    """Tests for version and metadata."""
    
    def test_version_exists(self):
        assert __version__ is not None
    
    def test_version_format(self):
        parts = __version__.split('.')
        assert len(parts) == 3
    
    def test_version_is_string(self):
        assert isinstance(__version__, str)
