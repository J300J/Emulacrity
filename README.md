# Emulacrity

CTI-driven scoring tool that evaluates threat actors against a weighted 5-pillar rubric to
determine whether they're a viable candidate for purple team emulation.

Full spec: [`Emulacrity.md`](./Emulacrity.md).

## Install

```bash
pip install -e .
```

Requires an `ANTHROPIC_API_KEY` in the environment.

## Usage

```bash
# Mode 2 — discovery (actor name only)
emulacrity evaluate "APT34" --sector "Financial Services" --table

# Mode 1 — source-driven (PDF, text file, or URL)
emulacrity evaluate "APT34" --source ./vendor-report.pdf --table

# Mode 1 with multiple source documents — repeat --source
emulacrity evaluate "APT34" \
  --source ./mandiant-report.pdf \
  --source ./crowdstrike-report.pdf \
  --source https://example.com/blog-post \
  --pdf apt34-eval.pdf

# Override lab-supported platforms and pillar weights for one run
emulacrity evaluate "APT34" \
  --platforms windows_endpoint --platforms cloud \
  --weight technical=0.40 --weight sector=0.20

# Override the lab's internet access mode, write JSON to a file, and use a
# specific config file instead of the default resolution order
emulacrity evaluate "APT34" \
  --internet-access air_gapped \
  --config ./emulacrity.yaml \
  --output ./apt34-eval.json

# Config
emulacrity config init          # write emulacrity.yaml with defaults
emulacrity config show          # print the resolved config
emulacrity sources              # list the trusted source allowlist
```

### Overriding platforms and pillar weights

`--platforms` fully replaces `lab_supported_platforms` for the run when given (repeatable;
omit to use the config file's value). `--weight KEY=VALUE` is a *patch*, not a replacement —
only the pillars you name change; the rest keep their configured value, and all five must
still sum to 1.0 or the run fails with a clear error before any API call. `KEY` accepts either
the short alias or the full `pillar_weights` key:

| Short | Full key |
|---|---|
| `technical` | `technical_feasibility_reproducibility` |
| `sector` | `target_profile_relevance` |
| `defensive` | `defensive_priority_alignment` |
| `platform` | `platform_tooling_compatibility` |
| `supply_chain` | `supply_chain_vector` |

### Defensive Priority Alignment (Pillar 3) input

Emulacrity has no live backend of its own, so Pillar 3 is scored from whatever context you
supply at evaluation time. Set `defensive_priority_source` in config to declare which
mechanism your deployment uses (default: `guided_prompts`), then supply the matching input
at evaluation time. Whichever concrete input is actually given always wins, regardless of
the configured default:

```bash
# guided_prompts (default) — interactively asks a few targeted questions.
# Skip with --no-interactive (or piping stdin) to default Pillar 3 to neutral.
emulacrity evaluate "APT34"

# freeform — paste unstructured context (ticketing export, Slack thread, SOC notes)
emulacrity evaluate "APT34" --defensive-context "SOC flagged this actor in this week's huddle."
emulacrity evaluate "APT34" --defensive-context-file ./soc-notes.txt

# adapter — a JSON array from your own internal CTI/ticketing system, matched by actor name
emulacrity evaluate "APT34" --defensive-adapter ./adapter-export.json
```

Adapter file shape (see `Emulacrity.md` → Configurable Parameters):

```json
[{"actor": "APT34", "alert_count_90d": 3, "last_seen": "2026-06-01", "active_hunt": true, "notes": "..."}]
```

Config resolution order: `--config` flag > `./emulacrity.yaml` > `~/.config/emulacrity/config.yaml` >
built-in defaults. See `Emulacrity.md` → Configurable Parameters for the full parameter list.
