"""MITRE ATT&CK STIX lookup — structured grounding for Pillars 1 & 4.

Supplements the model's free-text web_search/web_fetch loop with MITRE
ATT&CK's own structured Group -> Technique/Software graph, fetched from the
community-maintained STIX bundle (github.com/mitre-attack/attack-stix-data)
instead of inferred from vendor blog prose. This gives the model a factual
list of exactly which techniques and software ATT&CK documents for a group,
which web search alone can miss or misattribute.

Best-effort only: if the bundle can't be fetched/cached, or the actor has no
ATT&CK Group entry, evaluation proceeds without this context — the
web_search/web_fetch tools remain the primary and required source.

Known scope limit: only direct Group --uses--> Technique/Software
relationships are followed. Recent ATT&CK versions also model some group
activity through separate Campaign objects (Group --attributed-to-->
Campaign --uses--> Technique/Software); those are not resolved here.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

console = Console()

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "emulacrity" / "enterprise-attack.json"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # ATT&CK ships new revisions a few times a year
FETCH_TIMEOUT_SECONDS = 30.0


@dataclass
class AttackTechnique:
    attack_id: str
    name: str
    tactics: list[str] = field(default_factory=list)


@dataclass
class AttackSoftware:
    attack_id: str
    name: str
    kind: str  # "malware" | "tool"
    platforms: list[str] = field(default_factory=list)


@dataclass
class GroupProfile:
    attack_id: str
    name: str
    aliases: list[str]
    url: str
    techniques: list[AttackTechnique]
    software: list[AttackSoftware]


def _download_bundle(cache_path: Path) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True) as client:
        response = client.get(BUNDLE_URL)
        response.raise_for_status()
        tmp_path = cache_path.with_suffix(".tmp")
        tmp_path.write_bytes(response.content)
        tmp_path.replace(cache_path)


def _load_bundle(cache_path: Path = DEFAULT_CACHE_PATH) -> Optional[dict]:
    """Load the enterprise-attack STIX bundle, refreshing the on-disk cache
    if it's missing or older than CACHE_TTL_SECONDS.

    Returns None (rather than raising) on any network/parse failure, since
    this data source is supplementary, not required — evaluation should
    still proceed on web_search/web_fetch alone.
    """
    is_stale = (
        not cache_path.exists()
        or (time.time() - cache_path.stat().st_mtime) > CACHE_TTL_SECONDS
    )
    if is_stale:
        try:
            _download_bundle(cache_path)
        except (httpx.HTTPError, OSError) as exc:
            if cache_path.exists():
                console.print(
                    f"[yellow]Could not refresh ATT&CK STIX data ({exc}); "
                    "using cached copy.[/yellow]"
                )
            else:
                console.print(
                    f"[yellow]Could not fetch ATT&CK STIX data ({exc}); "
                    "continuing without it.[/yellow]"
                )
                return None

    try:
        return json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[yellow]Cached ATT&CK STIX data is unreadable ({exc}).[/yellow]")
        return None


def _external_id(obj: dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def lookup_group(actor: str, bundle: Optional[dict] = None) -> Optional[GroupProfile]:
    """Match `actor` (name or alias, case-insensitive) against ATT&CK Groups
    (STIX `intrusion-set` objects) and return its documented techniques and
    software.

    Returns None if the bundle can't be loaded or no group matches — this is
    a best-effort lookup, not a required input. Pass `bundle` explicitly to
    reuse an already-loaded bundle across calls instead of refetching.
    """
    bundle = bundle if bundle is not None else _load_bundle()
    if bundle is None:
        return None

    objects = bundle.get("objects", [])
    by_id = {obj["id"]: obj for obj in objects if "id" in obj}

    needle = actor.strip().lower()
    group = next(
        (
            obj
            for obj in objects
            if obj.get("type") == "intrusion-set"
            and not obj.get("revoked")
            and not obj.get("x_mitre_deprecated")
            and (
                obj.get("name", "").strip().lower() == needle
                or needle in {a.strip().lower() for a in obj.get("aliases", [])}
            )
        ),
        None,
    )
    if group is None:
        return None

    techniques: dict[str, AttackTechnique] = {}
    software: dict[str, AttackSoftware] = {}

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("source_ref") != group["id"]:
            continue

        target = by_id.get(obj.get("target_ref"))
        if target is None or target.get("revoked") or target.get("x_mitre_deprecated"):
            continue

        attack_id = _external_id(target)
        if not attack_id:
            continue

        if target.get("type") == "attack-pattern":
            tactics = [
                phase["phase_name"]
                for phase in target.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[attack_id] = AttackTechnique(
                attack_id=attack_id, name=target.get("name", ""), tactics=tactics
            )
        elif target.get("type") in ("malware", "tool"):
            software[attack_id] = AttackSoftware(
                attack_id=attack_id,
                name=target.get("name", ""),
                kind=target["type"],
                platforms=target.get("x_mitre_platforms", []),
            )

    return GroupProfile(
        attack_id=_external_id(group) or "",
        name=group.get("name", actor),
        aliases=group.get("aliases", []),
        url=_url(group),
        techniques=sorted(techniques.values(), key=lambda t: t.attack_id),
        software=sorted(software.values(), key=lambda s: s.attack_id),
    )


def format_group_context(profile: GroupProfile) -> str:
    """Render a GroupProfile as a text block for inclusion in the model's
    user message — structured grounding for Pillars 1 and 4."""
    lines = [f"ATT&CK Group: {profile.name} ({profile.attack_id})", f"URL: {profile.url}"]
    if profile.aliases:
        lines.append(f"Known aliases: {', '.join(profile.aliases)}")

    if profile.software:
        lines.append("\nSoftware/tools ATT&CK documents this group using:")
        for s in profile.software:
            platforms = f" [{', '.join(s.platforms)}]" if s.platforms else ""
            lines.append(f"  - {s.name} ({s.attack_id}, {s.kind}){platforms}")
    else:
        lines.append("\nNo software/tools documented for this group in ATT&CK.")

    if profile.techniques:
        lines.append("\nTechniques ATT&CK documents this group using:")
        for t in profile.techniques:
            tactics = f" [{', '.join(t.tactics)}]" if t.tactics else ""
            lines.append(f"  - {t.name} ({t.attack_id}){tactics}")
    else:
        lines.append("\nNo techniques documented for this group in ATT&CK.")

    return "\n".join(lines)
