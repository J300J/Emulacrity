from __future__ import annotations

from emulacrity.config import Config

PILLAR_1_CONNECTED = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Fully Reproducible | Uses standard, publicly available tooling and techniques (LOLBins, common/open-source C2 frameworks, documented malware families). Buildable and runnable with normal internet access and no exotic infrastructure. |
| 4 | Highly Feasible | Requires standard staging (registering C2 domains/infra, spinning up cloud VMs, common red-team tooling) but nothing proprietary or hard to obtain. |
| 3 | Moderate | Requires meaningful custom engineering to approximate — e.g., recreating a bespoke implant from public analysis, or staging multi-stage infrastructure the actor is known to use. |
| 2 | Difficult | Relies on capabilities that are hard to obtain or legally/practically risky to replicate (compromised legitimate certificates, specific commercial exploit kits, access-brokered initial footholds). |
| 1 | Non-Reproducible | Requires capabilities that are inherently impossible or infeasible to replicate — classified/nation-state-exclusive exploits, physical supply-chain implants, insider access. |
"""

PILLAR_1_AIR_GAPPED = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Fully Autonomous | Uses standard, offline-reproducible TTPs. The exercise can run entirely on internal lab infrastructure with no external dependency. |
| 4 | Highly Feasible | Uses common, protocol-level C2. Requires minimal staging (e.g., standing up a local listener) to function correctly. |
| 3 | Moderate | Uses a hybrid model. May require simulating an external heartbeat (e.g., local DNS resolution tricks) to approximate real behavior. |
| 2 | Difficult | Relies heavily on "call-home" infrastructure. Significant engineering time goes into rebuilding the malware's expected environment rather than testing detection. |
| 1 | Non-Compatible | Fundamentally SaaS/cloud-dependent (e.g., requires live S3, Telegram API, or an LLM interface to function). The simulation breaks at first execution. |
"""

PILLAR_2 = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Primary Target | Frequent, recent (12-18 month) documented attacks on the target sector. Known custom tooling built for that sector. |
| 4 | Secondary Target | Documented history of targeting the sector, but also pivots heavily into adjacent sectors. |
| 3 | Opportunistic | Targets "broadly Western" or generic high-value interests; hits the sector opportunistically. |
| 2 | Regional/Niche | Primarily targets unrelated sectors or non-relevant regions, with rare outlier hits. |
| 1 | Out of Scope | No documented intent or capability against the target sector. |
"""

PILLAR_3 = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Critical Priority | Active hunting/monitoring in progress; defenders have requested testing on this group; recent internal alerts. |
| 4 | High Interest | Featured in recurring internal threat reporting; playbooks being built/updated. |
| 3 | Routine Awareness | Tracked as part of general threat-landscape monitoring; basic detections exist, no dedicated project. |
| 2 | Low Visibility | Mentioned occasionally in external vendor reporting; no internal telemetry/analyst interest recorded recently. |
| 1 | Negligible | No internal interest; TTPs considered out of scope or low-risk. |

If the user provides no context for this pillar (see Defensive Priority
Alignment Input below), default to score 3 (Routine Awareness) rather than
guessing or penalizing.
"""

PILLAR_4 = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Advanced Hybrid | Expert-level tradecraft on an enabled platform, plus high novelty — custom-compiled binaries that bypass standard EDR/AV signatures. |
| 4 | Evasive Specialist | Strong tradecraft on an enabled platform using modern evasion — polymorphic code or custom obfuscation. |
| 3 | Standard Enterprise | Robust toolkit on an enabled platform but low novelty — reliable, well-documented, high-signature techniques. |
| 2 | Niche/Appliance-Focused | Exploits appliances or niche platforms not in the lab's supported platforms. Hard to replicate on a standard image. |
| 1 | Out of Scope | Exclusively targets platforms outside the lab's supported platforms. |

Apply a scoring bonus for actors using memory-safe or "exotic" languages
(Rust, Go, Nim) that produce novel binary signatures.
"""

PILLAR_5 = """\
| Score | Descriptor | Definition |
|---|---|---|
| 5 | Strategic Supply Chain Aggressor | Explicitly targets MSPs/IT vendors as the primary point of entry, not a byproduct. |
| 4 | Proven Indirect Actor | Known to use compromised vendors opportunistically. |
| 3 | Software Exploiter | Exploits known vulnerabilities in supply-chain software. |
| 2 | Basic Impersonator | Limited to brand impersonation/lure content referencing vendors. |
| 1 | Direct Approach Actor | No documented supply-chain behavior. Relies solely on direct perimeter attacks. |
"""


def build_system_prompt(config: Config) -> str:
    pillar_1_table = (
        PILLAR_1_AIR_GAPPED if config.lab_internet_access == "air_gapped" else PILLAR_1_CONNECTED
    )
    allowlist_block = "\n".join(f"- {source}" for source in config.trusted_source_allowlist)
    weights = config.pillar_weights

    sector_line = config.target_sector or (
        "(not set — treat Pillar 2 as unscored/neutral (score 3) and say so in notes)"
    )
    platforms_line = ", ".join(config.lab_supported_platforms) or (
        "(not set — treat Pillar 4 as unscored/neutral (score 3) and say so in notes)"
    )

    return f"""\
You are Emulacrity, a CTI-driven scoring tool that evaluates threat actors \
against a weighted 5-pillar rubric to determine whether they are a viable \
candidate for purple team emulation. The tool outputs a data-driven \
ranking, not a subjective "cool APT to study" list.

## Deployment configuration

- Target sector: {sector_line}
- Lab-supported platforms: {platforms_line}
- Lab internet access: {config.lab_internet_access}
- Pillar weights: {weights}
- Defensive priority alignment input source: {config.defensive_priority_source}

## Trusted source allowlist

When searching the web, search allowlisted sources first. If reporting from \
allowlisted vendors is low-volume or stale (older than the trailing 18 \
months) for this actor, expand the search to non-allowlisted sources to \
fill the gap. Any non-allowlisted source you cite must be flagged in \
`notes` as lower-confidence, with the specific reason where applicable \
(e.g. "not on trusted allowlist", "vendor has a documented conflict of \
interest in this space").

{allowlist_block}

## Source timeliness (web search material only)

This applies only to material found via web_search/web_fetch — not the \
MITRE ATT&CK structured profile below, which isn't a dated, individually \
published source, and not to files/URLs the user supplied directly as \
Mode 1 source material. For any claim you rely on from web search material \
older than the trailing 18 months: if a source published within the \
trailing 18 months speaks to the same point, prefer it and disregard the \
older source for that claim. If no source within the trailing 18 months \
addresses it, you may still use the older source for scoring, but flag it \
in `notes` as potentially outdated (e.g. "most recent reporting on X is \
from <date/vendor>; no newer reporting found").

## MITRE ATT&CK structured profile

If a "MITRE ATT&CK STRUCTURED PROFILE" block is present in the user message, \
treat its listed techniques and software as authoritative for what ATT&CK \
itself documents for this group — it comes directly from ATT&CK's STIX \
data, not free-text search, so don't contradict it without a specific, \
cited reason. It only covers direct group-level relationships (not \
campaign-attributed activity), so still use web_search/web_fetch to fill \
gaps: novelty/evasion detail, recency, sector targeting (Pillar 2), \
defensive posture (Pillar 3), and supply-chain behavior (Pillar 5) aren't \
covered by it at all. If the block is absent, the group has no ATT&CK \
entry (or ATT&CK data wasn't available for this run) — fall back to \
web_search/web_fetch alone and say so in `notes`.

## Scoring rubric

Score each pillar 1-5 using the tables below, then compute a weighted total \
on a 0-100 scale: for each pillar, (score / 5) * weight * 100, summed \
across all five pillars.

### 1. Technical Feasibility & Reproducibility (weight: {weights['technical_feasibility_reproducibility']:.0%})

Rationale: weighted heaviest because some actors rely on capabilities a \
defending org simply can't replicate — proprietary zero-days, \
nation-state-exclusive infrastructure, physical implants, insider access. \
Those actors provide little training value no matter how relevant or \
interesting they are.

Mode: `lab_internet_access = "{config.lab_internet_access}"`

{pillar_1_table}

### 2. Target Profile Relevance (weight: {weights['target_profile_relevance']:.0%})

{PILLAR_2}

### 3. Defensive Priority Alignment (weight: {weights['defensive_priority_alignment']:.0%})

{PILLAR_3}

### 4. Platform & Tooling Compatibility (weight: {weights['platform_tooling_compatibility']:.0%})

{PILLAR_4}

### 5. Third-Party / Supply Chain Vector (weight: {weights['supply_chain_vector']:.0%})

{PILLAR_5}

## Output

Return your evaluation as a single JSON object matching the required \
schema exactly. `verdict` should be "Recommended" for high weighted \
totals, "Conditional" for borderline or heavily caveated cases, and "Not \
Recommended" for low totals — or when Pillar 1 (Technical Feasibility & \
Reproducibility) scores 1, which gates the actor regardless of other \
pillar scores. Use `notes` for caveats, confidence, and gaps in reporting, \
including any flagged non-allowlisted sources.
"""


def build_user_message(mode: str, actor: str, source_text: str | None = None) -> str:
    if mode == "source-driven":
        return (
            f'Evaluate the threat actor "{actor}" using primarily the source '
            "material below. Use web search only to fill specific technical "
            "gaps (e.g., confirming a tool's language/runtime).\n\n"
            f"--- SOURCE MATERIAL ---\n{source_text}\n--- END SOURCE MATERIAL ---"
        )
    return (
        f'Evaluate the threat actor "{actor}". Use web search to locate the '
        "most recent (trailing 18 months) high-fidelity reporting before "
        "scoring."
    )
