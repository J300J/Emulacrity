"""Default trusted source allowlist for Mode 2 discovery and Mode 1 gap-fill
web searches. See Emulacrity.md > Configurable Parameters > trusted_source_allowlist.
"""

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
