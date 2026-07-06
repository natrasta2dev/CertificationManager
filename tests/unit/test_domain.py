"""Tests pour le module validation/domain."""

import pytest

from src.core.validation.domain import DomainValidator


class TestDomainValidator:
    """Tests pour DomainValidator."""

    def test_valid_domains(self):
        assert DomainValidator.is_valid_domain("example.com") is True
        assert DomainValidator.is_valid_domain("sub.example.co.uk") is True
        assert DomainValidator.is_valid_domain("api-v2.example.org") is True

    def test_invalid_domains(self):
        assert DomainValidator.is_valid_domain("") is False
        assert DomainValidator.is_valid_domain("not a domain") is False
        assert DomainValidator.is_valid_domain("-bad.com") is False
        assert DomainValidator.is_valid_domain("a" * 254) is False

    def test_wildcard_domains(self):
        assert DomainValidator.is_valid_domain("*.example.com") is True
        assert DomainValidator.is_wildcard("*.example.com") is True
        assert DomainValidator.is_wildcard("example.com") is False
        assert DomainValidator.is_valid_domain("*.invalid") is False

    def test_validate_domains_list(self):
        valid, errors = DomainValidator.validate_domains(["a.com", "b.org"])
        assert valid is True
        assert errors == []

        valid, errors = DomainValidator.validate_domains(["good.com", "bad domain"])
        assert valid is False
        assert "bad domain" in errors

    def test_extract_base_domain(self):
        assert DomainValidator.extract_base_domain("*.example.com") == "example.com"
        assert DomainValidator.extract_base_domain("example.com") == "example.com"

    def test_matches_wildcard(self):
        assert DomainValidator.matches_wildcard("*.example.com", "api.example.com") is True
        assert DomainValidator.matches_wildcard("*.example.com", "example.com") is True
        assert DomainValidator.matches_wildcard("*.example.com", "other.net") is False
        assert DomainValidator.matches_wildcard("example.com", "api.example.com") is False
