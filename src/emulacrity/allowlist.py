"""Default trusted source allowlist for Mode 2 discovery and Mode 1 gap-fill
web searches. See Emulacrity.md > Configurable Parameters > trusted_source_allowlist.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

DEFAULT_TRUSTED_SOURCES: list[str] = [
    "CrowdStrike",
    "Mandiant (Google Threat Intelligence)",
    "Microsoft Threat Intelligence (MSTIC)",
    "Unit 42 (Palo Alto Networks)",
    "Recorded Future",
    "Cisco Talos",
    "Secureworks Counter Threat Unit (CTU)",
    "ESET Research",
    "SentinelOne / SentinelLabs",
    "CISA",
    "NCSC (UK)",
    "ACSC (Australia)",
    "CCCS (Canada)",
    "JPCERT/CC",
    "The DFIR Report",
    "Citizen Lab (University of Toronto)",
    "MITRE ATT&CK",
]

# Known domains for each allowlisted vendor, used to compute on_allowlist in
# code rather than trusting the model's self-report.
ALLOWLIST_DOMAINS: dict[str, list[str]] = {
    "CrowdStrike": ["crowdstrike.com", "adversary.crowdstrike.com"],
    "Mandiant (Google Threat Intelligence)": ["mandiant.com", "cloud.google.com"],
    "Microsoft Threat Intelligence (MSTIC)": [
        "microsoft.com",
        "techcommunity.microsoft.com",
        "msrc.microsoft.com",
    ],
    "Unit 42 (Palo Alto Networks)": ["unit42.paloaltonetworks.com", "paloaltonetworks.com"],
    "Recorded Future": ["recordedfuture.com", "go.recordedfuture.com"],
    "Cisco Talos": ["blog.talosintelligence.com", "talosintelligence.com"],
    "Secureworks Counter Threat Unit (CTU)": ["secureworks.com"],
    "ESET Research": ["eset.com", "welivesecurity.com"],
    "SentinelOne / SentinelLabs": ["sentinelone.com", "labs.sentinelone.com"],
    "CISA": ["cisa.gov"],
    "NCSC (UK)": ["ncsc.gov.uk"],
    "ACSC (Australia)": ["cyber.gov.au"],
    "CCCS (Canada)": ["cyber.gc.ca"],
    "JPCERT/CC": ["jpcert.or.jp"],
    "The DFIR Report": ["thedfirreport.com"],
    "Citizen Lab (University of Toronto)": ["citizenlab.ca"],
    "MITRE ATT&CK": ["attack.mitre.org", "mitre.org"],
}

# Excluded by default: technically credible research, but excluded because
# of documented state-nexus ties that make treating them as a "trusted"
# default source questionable for a tool meant to serve Western defending
# orgs. Users with a specific reason to trust one can re-add it via
# `trusted_source_allowlist_add` in config.
EXCLUDED_SOURCES: dict[str, str] = {
    "Kaspersky": "Russian state-nexus ties",
    "Positive Technologies": "Russian state-nexus ties; sanctioned entity",
    "Qihoo360/Netlab": "Chinese state-nexus ties",
}


def _hostname(url: str) -> str:
    try:
        h = urlparse(url).hostname or ""
        return h[4:] if h.startswith("www.") else h
    except Exception:
        return ""


def _primary_name(vendor: str) -> str:
    """'Mandiant (Google Threat Intelligence)' → 'mandiant'."""
    return re.split(r"\s*\(", vendor)[0].strip().lower()


def is_on_allowlist(url: str, publisher: str, trusted_sources: list[str]) -> bool:
    """Return True if url's domain or publisher name matches a trusted source.

    Domain matching uses ALLOWLIST_DOMAINS for the vendors in trusted_sources.
    Publisher matching normalises both sides and checks for substring overlap,
    so 'Mandiant' matches 'Mandiant (Google Threat Intelligence)'.
    """
    domain = _hostname(url)
    pub_norm = publisher.strip().lower()

    for vendor in trusted_sources:
        # domain check
        if domain:
            for allowed in ALLOWLIST_DOMAINS.get(vendor, []):
                if domain == allowed or domain.endswith("." + allowed):
                    return True
        # publisher name check
        if pub_norm:
            primary = _primary_name(vendor)
            if primary and (primary in pub_norm or pub_norm in primary):
                return True

    return False
