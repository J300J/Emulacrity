# Emulacrity — Open Source Framework Spec

## Purpose

A CTI-driven scoring tool that evaluates threat actors against a weighted, 5-pillar
rubric to determine whether they're a **viable candidate for purple team emulation** —
in a lab environment that **has standard internet access** (unlike the air-gapped
constraint of the original internal version). The tool outputs a data-driven ranking,
not a subjective "cool APT to study" list.

The core design constraint driving the rubric: since the lab can reach the internet,
the gate is no longer "can this even run without live services" — it's **how much
custom engineering, proprietary infrastructure, or capability the defending org can't
realistically obtain or replicate** is required to faithfully reproduce the actor's
tradecraft. Every pillar either measures that constraint directly or is weighted to
reflect its importance relative to it.

## Modes

- **Mode 1 — Source-Driven Analysis.** Triggered when the user supplies a PDF, text
  dump, or link (e.g., a vendor threat report). The model scores the actor primarily
  from the supplied source, using web search only to fill specific technical gaps
  (e.g., confirming a tool's language/runtime).
- **Mode 2 — Discovery Analysis.** Triggered when the user supplies only an actor
  name. The model uses web search to locate the most recent (trailing 18 months)
  high-fidelity reporting from vendors/orgs on the `trusted_source_allowlist` (see
  Configurable Parameters) before scoring.

## Scoring Model

Weighted sum across 5 pillars, each scored 1–5 by the analyst/model, normalized to a
100-point scale. Weights are **configurable per deployment** — the defaults below
reflect a lab-execution-first priority, but an org running a fully networked lab could
rebalance them.

| # | Pillar | Default Weight | What it gates |
|---|--------|----------------|----------------|
| 1 | Technical Feasibility & Reproducibility | 35% | Can this actor's tradecraft realistically be built and run with available, internet-accessible infrastructure? |
| 2 | Target Profile Relevance | 25% | Does this actor target the defending org's sector? |
| 3 | Defensive Priority Alignment | 20% | Does this align with what the blue team already cares about? |
| 4 | Platform & Tooling Compatibility | 10% | Does the toolkit run on the lab's supported OS/stack? |
| 5 | Third-Party / Supply Chain Vector | 10% | Does the actor use trusted-vendor pivoting as a technique to test? |

---

### 1. Technical Feasibility & Reproducibility (35%)

**What it measures:** Whether the actor's TTPs can be built and executed in the lab
using infrastructure and tooling that's realistically obtainable. The exact rubric
used depends on the `lab_internet_access` parameter:

**Rationale:** Still weighted heaviest, because in either mode some actors rely on
capabilities a defending org simply can't replicate — proprietary zero-days,
nation-state-exclusive infrastructure, physical implants, insider access. Those
actors provide little training value no matter how relevant or interesting they are.

#### Mode: `lab_internet_access = "connected"` (default)

Standard internet access is available for staging C2, registering domains, pulling
public tooling, etc. This is not a "can it run at all" gate — it's a measure of how
much custom engineering or unobtainable capability stands between "documented TTP"
and "runnable exercise."

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Fully Reproducible | Uses standard, publicly available tooling and techniques (LOLBins, common/open-source C2 frameworks, documented malware families). Buildable and runnable with normal internet access and no exotic infrastructure. |
| 4 | Highly Feasible | Requires standard staging (registering C2 domains/infra, spinning up cloud VMs, common red-team tooling) but nothing proprietary or hard to obtain. |
| 3 | Moderate | Requires meaningful custom engineering to approximate — e.g., recreating a bespoke implant from public analysis, or staging multi-stage infrastructure the actor is known to use. |
| 2 | Difficult | Relies on capabilities that are hard to obtain or legally/practically risky to replicate (compromised legitimate certificates, specific commercial exploit kits, access-brokered initial footholds). |
| 1 | Non-Reproducible | Requires capabilities that are inherently impossible or infeasible to replicate — classified/nation-state-exclusive exploits, physical supply-chain implants, insider access. |

#### Mode: `lab_internet_access = "air_gapped"`

No outbound internet access. The gate is stricter: if the actor's tradecraft depends
on live internet services (SaaS C2, cloud APIs, live phishing infra), it cannot be
faithfully emulated in the lab at all, regardless of how well-engineered a workaround
might be.

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Fully Autonomous | Uses standard, offline-reproducible TTPs. The exercise can run entirely on internal lab infrastructure with no external dependency. |
| 4 | Highly Feasible | Uses common, protocol-level C2. Requires minimal staging (e.g., standing up a local listener) to function correctly. |
| 3 | Moderate | Uses a hybrid model. May require simulating an external heartbeat (e.g., local DNS resolution tricks) to approximate real behavior. |
| 2 | Difficult | Relies heavily on "call-home" infrastructure. Significant engineering time goes into rebuilding the malware's expected environment rather than testing detection. |
| 1 | Non-Compatible | Fundamentally SaaS/cloud-dependent (e.g., requires live S3, Telegram API, or an LLM interface to function). The simulation breaks at first execution. |

---

### 2. Target Profile Relevance (25%)

**What it measures:** Whether the actor has a documented history of targeting the
defending organization's sector. **This should be a configurable input** (e.g.,
"Financial Services," "Healthcare," "Technology," "Government") rather than hardcoded
— the rubric logic stays the same, but the sector value is a parameter set per
deployment.

**Rationale:** Prioritizes actors with demonstrated intent and capability against the
defender's actual industry, which is what justifies the exercise's ROI to leadership.

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Primary Target | Frequent, recent (12–18 month) documented attacks on the target sector. Known custom tooling built for that sector. |
| 4 | Secondary Target | Documented history of targeting the sector, but also pivots heavily into adjacent sectors. Consistent intent, less specialization. |
| 3 | Opportunistic | Targets "broadly Western" or generic high-value interests. Might hit the sector opportunistically but doesn't specialize in it. |
| 2 | Regional/Niche | Primarily targets unrelated sectors or non-relevant regions, with rare outlier hits on the target sector. |
| 1 | Out of Scope | No documented intent or capability against the target sector. |

---

### 3. Defensive Priority Alignment (20%)

**What it measures:** How actively the defending org's own SOC/CTI function is
already tracking or concerned about this actor — internal alerts issued, active
hunting, overlap with prior assessment/red-team findings.

**Rationale:** Exercises that map to what defenders are *already* worried about
produce more engagement and more directly improve playbooks than testing against an
actor nobody on the blue team has heard of.

**How the user provides this input:** The open-source tool has no live backend of its
own (internal CTI/ticketing integrations are org-specific and out of scope for a
public tool), so this pillar is scored from whatever context the user supplies at
evaluation time, in order of preference:

1. **Guided prompts (default).** The tool asks a short set of targeted questions per
   actor — e.g., "Is this actor being actively hunted?", "Any internal alerts on this
   actor in the last 90 days?", "Does this overlap with a recent assessment/red-team
   finding?" — and scores off the answers. If the user skips this, default to a
   neutral score (3 — Routine Awareness) rather than guessing or penalizing.
2. **Freeform paste/import.** The user can paste unstructured context — a ticketing
   export, a Slack thread, SOC meeting notes — and the model extracts signal from it
   the same way Mode 1 handles a source document.
3. **`defensive_priority_source` adapter.** See the Configurable Parameters section —
   a documented plugin interface for users who want to wire up their own internal
   CTI/ticketing system. The tool matches an actor by name against a user-supplied
   JSON export; nothing about the source system itself is part of the open-source
   tool.

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Critical Priority | Active hunting or monitoring in progress. Defenders have specifically requested testing/training on this group. Recent internal alerts issued. |
| 4 | High Interest | Group is featured in recurring internal threat reporting. Existing playbooks for this group are being built or updated. |
| 3 | Routine Awareness | Tracked as part of general threat-landscape monitoring. Basic detections exist but no dedicated project is tied to them. |
| 2 | Low Visibility | Mentioned occasionally in external vendor reporting, but no internal telemetry or analyst interest recorded recently. |
| 1 | Negligible | No internal interest. TTPs considered out of scope or low-risk by current defensive leadership. |

---

### 4. Platform & Tooling Compatibility (10%)

**What it measures:** Whether the actor's toolkit runs on the platforms enabled in
`lab_supported_platforms` (`windows_server`, `windows_endpoint`, `macos`, `linux`,
`cloud` — any combination). A scoring bonus applies for actors using memory-safe or
"exotic" languages (Rust, Go, Nim) that produce novel binary signatures.

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Advanced Hybrid | Expert-level tradecraft on an enabled platform, plus high novelty — custom-compiled binaries that bypass standard EDR/AV signatures. |
| 4 | Evasive Specialist | Strong tradecraft on an enabled platform using modern evasion — polymorphic code or custom obfuscation. |
| 3 | Standard Enterprise | Robust toolkit on an enabled platform but low novelty — reliable, well-documented, high-signature techniques. |
| 2 | Niche/Appliance-Focused | Exploits appliances or niche platforms not in `lab_supported_platforms`. Hard to replicate on a standard image. |
| 1 | Out of Scope | Exclusively targets platforms outside `lab_supported_platforms`. |

---

### 5. Third-Party / Supply Chain Vector (10%)

**What it measures:** Whether the actor treats trusted third parties (MSPs, IT
vendors, upstream software) as a primary point of entry — useful for testing
detection of "trusted tunnel" and service-account abuse rather than just perimeter
defense.

| Score | Descriptor | Definition |
|---|---|---|
| 5 | Strategic Supply Chain Aggressor | Explicitly targets MSPs/IT vendors as the primary point of entry, not a byproduct. Tests detection of trusted-vendor tunnel abuse. |
| 4 | Proven Indirect Actor | Known to use compromised vendors opportunistically. Tests correlation between external vendor alerts and internal activity. |
| 3 | Software Exploiter | Exploits known vulnerabilities in supply-chain software. Tests vulnerability management and detection speed. |
| 2 | Basic Impersonator | Limited to brand impersonation/lure content referencing vendors. Tests email gateway and user awareness. |
| 1 | Direct Approach Actor | No documented supply-chain behavior. Relies solely on direct perimeter attacks. |

---

## Output Format

Each evaluated actor should produce a structured result, e.g.:

```json
{
  "actor": "string",
  "aliases": ["string"],
  "mode": "source-driven | discovery",
  "sources": ["string (title/link)"],
  "scores": {
    "technical_feasibility_reproducibility": {"score": 1-5, "justification": "string"},
    "target_profile_relevance": {"score": 1-5, "justification": "string"},
    "defensive_priority_alignment": {"score": 1-5, "justification": "string"},
    "platform_tooling_compatibility": {"score": 1-5, "justification": "string"},
    "supply_chain_vector": {"score": 1-5, "justification": "string"}
  },
  "weighted_total": "0-100",
  "verdict": "Recommended | Conditional | Not Recommended",
  "notes": "string — caveats, confidence, gaps in reporting"
}
```

## Configurable Parameters (deployment-time)

These replace the hardcoded, org-specific values from the internal version:

- `trusted_source_allowlist` — the vendors/orgs treated as high-fidelity reporting
  sources when the model is searching the web (Mode 2 discovery, and Mode 1 gap-fill
  searches). Does not restrict Mode 1's primary input — a user-supplied source
  document is scored regardless of who published it. Ships with a default list;
  users can override it via `trusted_source_allowlist.add` /
  `trusted_source_allowlist.remove`, or supply a full replacement list — if a full
  replacement list is provided, it short-circuits `.add`/`.remove` entirely and is
  used as-is. An empty list (`[]`) in any form is invalid — the tool raises an error
  and requires at least one source rather than silently falling back to "any source."

  **Search behavior:** The model searches allowlisted sources first. If reporting
  from allowlisted vendors is low-volume or stale (outside the trailing 18-month
  window) for a given actor, it expands the search to non-allowlisted sources to fill
  the gap. Any non-allowlisted source cited in the output must be flagged in that
  actor's `notes` field as lower-confidence, along with the specific reason where
  applicable (e.g., "not on trusted allowlist," "vendor has a documented conflict of
  interest in this space").

  **Source timeliness:** Applies only to material found via web search — not
  structured, non-time-stamped reference data (e.g. a MITRE ATT&CK group/technique
  lookup), and not to files/URLs the user supplies directly as Mode 1 source
  material. For any claim the model relies on from web search material older
  than the trailing 18 months: if a source published within the trailing 18 months
  speaks to the same point, that newer source is preferred and the older one is
  disregarded for that claim. If no source within the trailing 18 months addresses
  it, the older source may still be used for scoring, but must be flagged in `notes`
  as potentially outdated.

  **Maintenance:** This default list is maintained by the project and will be
  updated periodically; revisions are published via the GitHub repo rather than
  fetched at runtime.

  **Default list:**
  - CrowdStrike
  - Mandiant (Google Threat Intelligence)
  - Microsoft Threat Intelligence (MSTIC)
  - Unit 42 (Palo Alto Networks)
  - Recorded Future
  - Cisco Talos
  - Secureworks Counter Threat Unit (CTU)
  - ESET Research
  - SentinelOne / SentinelLabs
  - CISA
  - NCSC (UK)
  - ACSC (Australia)
  - CCCS (Canada)
  - JPCERT/CC
  - The DFIR Report
  - Citizen Lab (University of Toronto)
  - MITRE ATT&CK (taxonomy/reference source, not incident reporting)

  **Explicitly excluded by default:** Kaspersky, Positive Technologies, and
  Qihoo360/Netlab. Their research is technically credible, but all three carry
  documented state-nexus ties (Russian and Chinese, respectively) that make treating
  them as a "trusted" default source questionable for a tool meant to serve Western
  defending orgs by default. Excluded, not blocklisted — users who have a specific
  reason to trust one (e.g., independent research use, non-Western deployment) can
  add it back via `trusted_source_allowlist.add`.

- `target_sector` — industry profile used for Pillar 2 scoring (e.g., "Financial Services")
- `lab_supported_platforms` — OS/stack the lab can execute against. Accepts one or more of: `"windows_server"`, `"windows_endpoint"`, `"macos"`, `"linux"`, `"cloud"` (e.g., `["windows_server", "windows_endpoint"]`)
- `lab_internet_access` — `"connected" | "air_gapped"`. Switches the Pillar 1 rubric between the two modes below. Defaults to `"connected"`.
- `pillar_weights` — override the default 35/25/20/10/10 split
- `defensive_priority_source` — how Pillar 3 input is gathered. One of:
  - `"guided_prompts"` (default) — tool asks targeted questions per actor at evaluation time
  - `"freeform"` — user pastes unstructured context (ticketing export, notes, etc.)
  - `"adapter"` — user supplies a JSON array conforming to:
    ```json
    [{"actor": "string", "alert_count_90d": 0, "last_seen": "YYYY-MM-DD", "active_hunt": true, "notes": "string"}]
    ```
    The tool matches an actor entry by name and passes it to the model; users wire up
    their own internal CTI/ticketing system to produce this JSON, and nothing about
    the source system is part of the open-source tool.

The worked examples (e.g., APT34/Helix Kitten as a high sector-relevance actor) cite
publicly documented, vendor-published threat intelligence.
