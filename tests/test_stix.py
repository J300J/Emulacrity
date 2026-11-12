"""Tests for ATT&CK STIX lookup — normalize, alias matching, campaign resolution."""

from __future__ import annotations

from emulacrity.attack_stix import _normalize, lookup_group

# ---------------------------------------------------------------------------
# Minimal fixture STIX bundle
# ---------------------------------------------------------------------------
# Contains:
#  - Group G0001 "TestGroup" with alias "TG" and "Test-Group"
#  - Technique T0001 linked directly to the group
#  - Campaign C0001 attributed to the group
#  - Technique T0002 linked via the campaign (campaign attribution path)
#  - Software S0001 linked directly to the group

_FIXTURE_BUNDLE: dict = {
    "type": "bundle",
    "objects": [
        # intrusion-set
        {
            "id": "intrusion-set--aaa",
            "type": "intrusion-set",
            "name": "TestGroup",
            "aliases": ["TG", "Test-Group", "Alt-Name"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0001", "url": "https://attack.mitre.org/groups/G0001"}
            ],
        },
        # attack-pattern (direct)
        {
            "id": "attack-pattern--t1",
            "type": "attack-pattern",
            "name": "Spearphishing",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0001", "url": "https://attack.mitre.org/techniques/T0001"}
            ],
        },
        # malware (direct)
        {
            "id": "malware--s1",
            "type": "malware",
            "name": "TestImplant",
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0001", "url": "https://attack.mitre.org/software/S0001"}
            ],
        },
        # campaign attributed to group
        {
            "id": "campaign--c1",
            "type": "campaign",
            "name": "Operation Test",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "C0001", "url": ""}
            ],
        },
        # attack-pattern used by campaign (not directly by group)
        {
            "id": "attack-pattern--t2",
            "type": "attack-pattern",
            "name": "Credential Dumping",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0002", "url": "https://attack.mitre.org/techniques/T0002"}
            ],
        },
        # relationship: group uses T0001
        {
            "id": "relationship--r1",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--aaa",
            "target_ref": "attack-pattern--t1",
        },
        # relationship: group uses S0001
        {
            "id": "relationship--r2",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--aaa",
            "target_ref": "malware--s1",
        },
        # relationship: campaign attributed-to group
        {
            "id": "relationship--r3",
            "type": "relationship",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--c1",
            "target_ref": "intrusion-set--aaa",
        },
        # relationship: campaign uses T0002
        {
            "id": "relationship--r4",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "campaign--c1",
            "target_ref": "attack-pattern--t2",
        },
    ],
}


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


def test_normalize_lowercases():
    assert _normalize("APT34") == "apt34"


def test_normalize_removes_hyphens():
    assert _normalize("APT-34") == "apt34"


def test_normalize_removes_spaces():
    assert _normalize("APT 34") == "apt34"


def test_normalize_removes_underscores():
    assert _normalize("apt_34") == "apt34"


def test_normalize_mixed():
    assert _normalize("Helix-Kitten") == "helixkitten"
    assert _normalize("Helix Kitten") == "helixkitten"


# ---------------------------------------------------------------------------
# lookup_group — name and alias matching
# ---------------------------------------------------------------------------


def test_lookup_by_canonical_name():
    profile = lookup_group("TestGroup", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    assert profile.name == "TestGroup"
    assert profile.attack_id == "G0001"


def test_lookup_by_alias():
    profile = lookup_group("TG", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    assert profile.name == "TestGroup"
    assert profile.matched_alias == "TG"


def test_lookup_by_normalized_alias():
    # "Alt-Name" is an alias; query "Alt Name" (space instead of hyphen).
    # The canonical name "TestGroup" does not normalize to "altname", so
    # the match must come via the alias path.
    profile = lookup_group("Alt Name", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    assert profile.matched_alias == "Alt-Name"


def test_lookup_case_insensitive():
    profile = lookup_group("testgroup", bundle=_FIXTURE_BUNDLE)
    assert profile is not None


def test_lookup_no_match():
    profile = lookup_group("UnknownGroup", bundle=_FIXTURE_BUNDLE)
    assert profile is None


# ---------------------------------------------------------------------------
# lookup_group — direct relationship resolution
# ---------------------------------------------------------------------------


def test_direct_technique_found():
    profile = lookup_group("TestGroup", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    technique_ids = [t.attack_id for t in profile.techniques]
    assert "T0001" in technique_ids


def test_direct_software_found():
    profile = lookup_group("TestGroup", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    software_ids = [s.attack_id for s in profile.software]
    assert "S0001" in software_ids


# ---------------------------------------------------------------------------
# lookup_group — campaign attribution resolution
# ---------------------------------------------------------------------------


def test_campaign_attributed_technique_found():
    """T0002 is only linked via campaign attribution, not directly."""
    profile = lookup_group("TestGroup", bundle=_FIXTURE_BUNDLE)
    assert profile is not None
    technique_ids = [t.attack_id for t in profile.techniques]
    assert "T0002" in technique_ids, "Campaign-attributed technique should be included"


def test_revoked_group_skipped():
    bundle = dict(_FIXTURE_BUNDLE)
    revoked_group = {
        "id": "intrusion-set--bbb",
        "type": "intrusion-set",
        "name": "TestGroup",
        "revoked": True,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "G9999", "url": ""}
        ],
    }
    # Insert revoked group before the real one
    bundle["objects"] = [revoked_group] + list(bundle["objects"])
    profile = lookup_group("TestGroup", bundle=bundle)
    # Should match the non-revoked group, not the revoked one
    assert profile is not None
    assert profile.attack_id == "G0001"
