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

import gzip
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import httpx
from rich.console import Console

console = Console()

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
# User-local path written by `emulacrity stix refresh`. When present it takes
# precedence over the vendored bundle shipped with the package.
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "emulacrity" / "enterprise-attack.json"
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
    matched_alias: str = ""  # the alias that matched the user's query, if not the canonical name


def _normalize(name: str) -> str:
    """Lowercase, strip, remove spaces/hyphens/underscores for fuzzy matching.

    'APT-34', 'APT 34', 'apt34' all normalize to 'apt34'.
    """
    return re.sub(r"[\s\-_]", "", name.lower().strip())


def _load_vendored_bundle() -> dict | None:
    """Load the ATT&CK STIX bundle vendored with this package release."""
    try:
        data = (resources.files("emulacrity") / "data" / "enterprise-attack.json.gz").read_bytes()
        return json.loads(gzip.decompress(data))
    except Exception as exc:
        console.print(f"[yellow]Could not read vendored ATT&CK STIX data ({exc}).[/yellow]")
        return None


def refresh_bundle(cache_path: Path = DEFAULT_CACHE_PATH) -> None:
    """Fetch the latest ATT&CK STIX bundle from MITRE and write it to *cache_path*.

    Called explicitly by `emulacrity stix refresh` — never on a normal
    evaluation run.  Raises on any network or HTTP error so the caller can
    surface a clear message.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True) as client:
        response = client.get(BUNDLE_URL)
        response.raise_for_status()
    tmp_path = cache_path.with_suffix(".tmp")
    tmp_path.write_bytes(response.content)
    tmp_path.replace(cache_path)


def _load_bundle(cache_path: Path = DEFAULT_CACHE_PATH) -> dict | None:
    """Load the ATT&CK STIX bundle.

    Preference order:
    1. User-local refreshed copy at *cache_path* (written by `stix refresh`).
    2. The bundle vendored with this package release.

    Returns None on any parse failure — this source is supplementary and
    evaluation continues on web_search/web_fetch alone.
    """
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            console.print(
                f"[yellow]User-refreshed ATT&CK STIX data is unreadable ({exc}); "
                "falling back to vendored bundle.[/yellow]"
            )

    return _load_vendored_bundle()


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def lookup_group(actor: str, bundle: dict | None = None) -> GroupProfile | None:
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

    needle_norm = _normalize(actor)
    matched_alias = ""
    group = None
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        canonical = obj.get("name", "")
        if _normalize(canonical) == needle_norm:
            group = obj
            break
        for alias in obj.get("aliases", []):
            if _normalize(alias) == needle_norm:
                group = obj
                matched_alias = alias
                break
        if group is not None:
            break

    if group is None:
        return None

    techniques: dict[str, AttackTechnique] = {}
    software: dict[str, AttackSoftware] = {}

    # Collect direct group -> technique/software relationships.
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("source_ref") != group["id"]:
            continue
        _collect_target(obj, by_id, techniques, software)

    # Resolve campaign-attributed techniques/software:
    # group <-attributed-to- campaign -uses-> technique/software
    campaign_ids: set[str] = set()
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "attributed-to"
            and obj.get("target_ref") == group["id"]
        ):
            src = by_id.get(obj.get("source_ref", ""))
            if src and src.get("type") == "campaign" and not src.get("revoked"):
                campaign_ids.add(src["id"])

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("source_ref") not in campaign_ids:
            continue
        _collect_target(obj, by_id, techniques, software)

    return GroupProfile(
        attack_id=_external_id(group) or "",
        name=group.get("name", actor),
        aliases=group.get("aliases", []),
        url=_url(group),
        techniques=sorted(techniques.values(), key=lambda t: t.attack_id),
        software=sorted(software.values(), key=lambda s: s.attack_id),
        matched_alias=matched_alias,
    )


def _collect_target(
    rel: dict,
    by_id: dict[str, dict],
    techniques: dict[str, AttackTechnique],
    software: dict[str, AttackSoftware],
) -> None:
    target = by_id.get(rel.get("target_ref", ""))
    if target is None or target.get("revoked") or target.get("x_mitre_deprecated"):
        return
    attack_id = _external_id(target)
    if not attack_id:
        return
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


def format_group_context(profile: GroupProfile) -> str:
    """Render a GroupProfile as a text block for inclusion in the model's
    user message — structured grounding for Pillars 1 and 4."""
    lines = [f"ATT&CK Group: {profile.name} ({profile.attack_id})", f"URL: {profile.url}"]
    if profile.matched_alias:
        lines.append(f"Matched via alias: {profile.matched_alias}")
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
