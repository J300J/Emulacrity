"""Tests for allowlist domain matching and is_on_allowlist."""

from __future__ import annotations

from emulacrity.allowlist import DEFAULT_TRUSTED_SOURCES, is_on_allowlist


def test_url_exact_domain_match():
    assert is_on_allowlist("https://crowdstrike.com/blog/apt34", "", DEFAULT_TRUSTED_SOURCES)


def test_url_subdomain_match():
    assert is_on_allowlist(
        "https://labs.sentinelone.com/report", "", DEFAULT_TRUSTED_SOURCES
    )


def test_url_www_stripped():
    assert is_on_allowlist("https://www.cisa.gov/advisory", "", DEFAULT_TRUSTED_SOURCES)


def test_url_no_match():
    assert not is_on_allowlist("https://example-blog.com/post", "", DEFAULT_TRUSTED_SOURCES)


def test_publisher_exact_primary_name():
    assert is_on_allowlist("", "mandiant", DEFAULT_TRUSTED_SOURCES)


def test_publisher_case_insensitive():
    assert is_on_allowlist("", "CrowdStrike", DEFAULT_TRUSTED_SOURCES)


def test_publisher_partial_match():
    assert is_on_allowlist("", "Unit 42", DEFAULT_TRUSTED_SOURCES)


def test_publisher_no_match():
    assert not is_on_allowlist("", "Unknown Vendor Inc.", DEFAULT_TRUSTED_SOURCES)


def test_empty_url_and_publisher():
    assert not is_on_allowlist("", "", DEFAULT_TRUSTED_SOURCES)


def test_url_wins_even_if_publisher_blank():
    assert is_on_allowlist("https://ncsc.gov.uk/report", "", DEFAULT_TRUSTED_SOURCES)


def test_publisher_wins_even_if_url_blank():
    assert is_on_allowlist("", "CISA", DEFAULT_TRUSTED_SOURCES)


def test_custom_trusted_sources_subset():
    """Only CrowdStrike trusted — Mandiant URL should not match."""
    assert not is_on_allowlist(
        "https://mandiant.com/report", "", ["CrowdStrike"]
    )
    assert is_on_allowlist("https://crowdstrike.com/report", "", ["CrowdStrike"])
