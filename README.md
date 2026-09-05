# Detection-as-Code Pipeline

<p align="center">
  <img src="https://img.shields.io/badge/Detection--as--Code-Sigma-2563EB?style=for-the-badge&logo=databricks&logoColor=white" />
  <img src="https://img.shields.io/badge/CI%2FCD-Gates-111827?style=for-the-badge&logo=githubactions&logoColor=white" />
  <img src="https://img.shields.io/badge/Behavioral%20Tests-TP%20%7C%20Benign-7C3AED?style=for-the-badge&logo=pytest&logoColor=white" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-DC2626?style=for-the-badge&logo=mitre&logoColor=white" />
  <img src="https://img.shields.io/badge/SIEM%20Outputs-SPL%20%7C%20KQL-0A66C2?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Live%20Deploy-Wazuh%20%7C%20Sentinel-16A34A?style=for-the-badge&logo=microsoftazure&logoColor=white" />
</p>

Enterprise-grade CI/CD pipeline for managing Sigma detection rules with automated validation, testing, and MITRE ATT&CK coverage tracking.

## Why This Exists

Most Detection-as-Code portfolio projects stop at basic file monitoring. This pipeline demonstrates real detection engineering maturity through structured validation, testing, and coverage analysis.

- **Rule Lifecycle Management**: Rules progress through `draft` → `experimental` → `production` → `deprecated` states
- **Behavioral Testing**: Rules are validated against curated log samples containing true positives AND benign activity
- **Confidence-Weighted Coverage**: MITRE heatmaps show detection confidence, not just "we have a rule"
- **False Positive Context**: Production rules include tuning metadata and exclusion patterns

## Repository Structure

```
detection-as-code/
├── .github/
│   └── workflows/
│       └── validate-and-deploy.yml    # Main CI/CD pipeline
├── rules/                             # Sigma rules — the single source of truth
│   ├── windows/
│   │   ├── credential_access/         # MITRE tactic-aligned directories
│   │   ├── execution/
│   │   └── initial_access/
│   └── linux/
│       └── credential_access/
├── wazuh/                             # Wazuh deployment seam
│   ├── rule_map.yml                   # Sigma <-> Wazuh rule-ID contract
│   └── rules/                         # Native Wazuh XML (dac_windows, dac_linux)
├── sentinel/                          # Microsoft Sentinel deployment seam
│   ├── parsers/Sysmon.kql             # Projects the Event table's Sysmon XML into columns
│   ├── rule_map.yml                   # Sigma <-> Sentinel contract + per-rule disposition
│   └── README.md                      # The Event-table trap + live-verification evidence
├── infra/                             # Bicep IaC for the burst Sentinel lab
│   ├── main.bicep                     # Workspace + DCR + opt-in VM / domain controller
│   ├── main.bicepparam                # Pinned sub/RG/name/region (see infra/README.md)
│   ├── modules/                       # workspace / dcr / vm + scoped Sysmon config
│   │   └── promote-dc.ps1             # AD DS promotion, via runCommands (Phase 2b)
│   ├── scripts/
│   │   ├── seed-ad.ps1                # OUs, users, groups, SPN, audit subcategories
│   │   └── fire-domain-logons.ps1     # Live-fire auth telemetry against the DC
│   └── README.md                      # Cost model, phase-by-phase deploy, teardown
├── tests/                             # Pytest suite for the pipeline tooling
│   ├── conftest.py                    # Makes scripts/ importable in tests
│   ├── test_export_manifest.py        # Manifest exporter; sibling suites cover the
│   │                                  #   converter, both deployers, and both clients
│   └── samples/
│       ├── true_positives/            # Log samples that SHOULD trigger rules
│       └── benign/                    # Log samples that should NOT trigger
├── scripts/
│   ├── validate_rules.py              # Schema + custom field validation
│   ├── generate_coverage.py           # MITRE ATT&CK coverage analysis
│   ├── test_detections.py             # Tier-1 behavioral testing (offline, in-repo AST)
│   ├── test_detections_wazuh.py       # Tier-2 functional testing (live Wazuh engine)
│   ├── export_manifest.py             # Production-rule manifest for ADTE
│   ├── convert_sentinel.py            # Wraps Sysmon predicates as `Sysmon | where ...`
│   ├── deploy_sentinel_rules.py       # Deploys parser + analytics rules via ARM REST
│   ├── sentinel_client.py             # Sentinel/ARM API client (SP or az login auth)
│   ├── deploy_wazuh_rules.py          # Deploys native rules to a live Wazuh manager
│   ├── wazuh_client.py                # Wazuh Manager API client
│   ├── conftest.py                    # Excludes test_detections.py from pytest
│   └── requirements.txt
├── configs/
│   ├── coverage_config.yml            # MITRE technique weights/priorities
│   └── sigma_config.yml               # Field mappings. NOT wired in: CI converts with
│                                      #   `--pipeline sysmon` and nothing reads this file,
│                                      #   so rules use raw Sysmon field names.
├── docs/
│   ├── COVERAGE.md                    # Auto-generated coverage report
│   ├── attack-navigator-layer.json    # Auto-generated ATT&CK Navigator layer
│   ├── rule_manifest.json             # Auto-generated production-rule manifest
│   ├── rule_manifest_schema.md        # Manifest schema / ADTE contract
│   ├── RULE_STANDARD.md               # Rule authoring guidelines
│   ├── wazuh_functional_testing.md    # Tier-2 functional testing write-up
│   ├── AD_LAB_EVIDENCE.md             # Domain-controller build evidence + honest limits
│   └── evidence/                      # Captured JSON backing AD_LAB_EVIDENCE.md
├── pytest.ini                         # Pytest config (testpaths = tests)
└── README.md
```

## Rule Lifecycle States

| State | Description | CI Requirements |
|-------|-------------|-----------------|
| `draft` | Under development, not deployed | Passes schema validation only |
| `experimental` | Testing in non-production | Passes linting, has test samples |
| `production` | Active in SIEM | Full validation + behavioral tests pass |
| `deprecated` | Scheduled for removal | Documented replacement or justification |

Rules specify their state in the `custom.lifecycle` field:

```yaml
custom:
    lifecycle: production
    confidence: high
    false_positive_rate: low
    tuning_notes: |
        Exclude backup software (Veeam, Acronis) via process name
        Whitelist specific service accounts in finance dept
```

## Pipeline Stages

### 1. Schema Validation
Validates all rules against the official Sigma specification plus custom required fields.

### 2. Unit Tests
Runs the pytest suite (`tests/`) against the pipeline tooling in `scripts/`. Runs in parallel with schema validation and gates PRs — a tooling regression fails the check before rules are ever converted or published.

### 3. Linting
Checks for:
- Missing MITRE ATT&CK tags
- Invalid log source configurations
- Deprecated field usage
- Detection logic errors (impossible conditions, etc.)

### 4. SIEM Conversion
Converts rules to target SIEM query languages via a parallel matrix:
- Splunk SPL
- Microsoft Sentinel / Defender KQL (`kusto`)

### 5. Behavioral Testing
Two tiers of detection verification:
- **Tier 1 (offline, every PR):** converted queries are evaluated against test samples with an in-repo parser/AST — true positives detected (sensitivity), benign samples don't trigger (specificity). Hermetic, no infrastructure.
- **Tier 2 (functional, `workflow_dispatch`):** the same detections, authored as native Wazuh rules, are verified against a **live Wazuh engine** via the Manager API `logtest` endpoint — the real decoders and ruleset decide which rule fires. See [Functional Detection Testing](docs/wazuh_functional_testing.md).

### 6. Coverage Analysis
Generates a MITRE ATT&CK coverage report with confidence weighting (main branch only). Commits `docs/COVERAGE.md` and the ATT&CK Navigator layer back to the repo.

### 7. Rule Manifest Export
Exports every production rule to `docs/rule_manifest.json` for downstream consumption by ADTE (main branch only, gated on the unit tests). See [ADTE Integration](#adte-integration).

## Live Deployment

Converted queries are not the end of the pipeline — both target SIEMs have a real, tooled deploy
path, each with a rule-ID contract so nothing deploys silently or goes unaccounted for.

| Target | Seam | Deploy tool | Status |
|---|---|---|---|
| **Wazuh** | [`wazuh/`](wazuh/) — native XML + `rule_map.yml` | `scripts/deploy_wazuh_rules.py` (Manager API) | Rules functionally verified against a **live engine**, not just converted (Tier 2) |
| **Microsoft Sentinel** | [`sentinel/`](sentinel/) — `Sysmon.kql` parser + `rule_map.yml` | `scripts/deploy_sentinel_rules.py` (ARM REST) | Parser + 2 analytics rules deployed and **detection-validated on live telemetry** |

Both deployers are readback-verifying (`PUT` → `GET` → compare) and support `--dry-run` /
`--verify-only`. Every rule is dispositioned in its `rule_map.yml`; rules that cannot deploy to a
given target are skipped with a **logged reason**, never dropped silently.

The Sentinel path exists because generated KQL does not run as-is: the Azure Monitor Agent lands
Sysmon in the generic `Event` table with fields buried in `EventData` XML, so a raw predicate
matches **zero rows with no error**. [`sentinel/parsers/Sysmon.kql`](sentinel/parsers/Sysmon.kql)
re-materialises those fields as columns; see [`sentinel/README.md`](sentinel/README.md) for the
full trap write-up and the live-verification evidence.

The lab those rules run in is itself code. [`infra/`](infra/) stands up the Log Analytics
workspace, the data collection rule, and an opt-in Windows Server 2022 event-source VM (AMA +
Sysmon) via Bicep. That VM can be promoted in-template to an **Active Directory domain
controller** (`promoteToDomainController`, Phase 2b): `promote-dc.ps1` installs AD DS and creates
the forest, `seed-ad.ps1` seeds OUs, users, groups, a Kerberoastable SPN and the audit
subcategories, and `fire-domain-logons.ps1` generates real authentication telemetry against it.
The DCR is widened to collect the resulting `4624/4625/4672/4768/4771/4776` and friends. The
build, the queries that confirmed the events landed in Sentinel, and its honest limits are in
[`docs/AD_LAB_EVIDENCE.md`](docs/AD_LAB_EVIDENCE.md).

**The Azure lab is deliberately burst infrastructure: it is stood up, exercised, evidenced, and
torn down the same session, so it is not running now.** Cost model, per-phase deploy commands and
teardown are in [`infra/README.md`](infra/README.md). Re-running the pipeline against Sentinel
means redeploying it first.

## Evidence

The lab claims above are backed by captured artifacts rather than assertions. The lab is burst
infrastructure that gets torn down after each run, so nothing here can be re-queried later — the
capture *is* the record.

- [`docs/AD_LAB_EVIDENCE.md`](docs/AD_LAB_EVIDENCE.md) — the domain-controller build: forest
  creation, the seeded directory, the audit subcategories enabled, the live-fire authentication
  run, and the Sentinel queries confirming those events landed. It carries an **honest-limits**
  section naming what the run did *not* prove — the fire authenticated over NTLM, so `4768`/`4771`
  are deployed but unexercised, and no analytics rule was armed during the window.
- [`docs/evidence/`](docs/evidence/) — the raw JSON behind that document: directory export, DCR
  configuration, and the live-fire query results.
- [`sentinel/README.md`](sentinel/README.md) — the `Event`-table trap and the live verification of
  the encoded-PowerShell detection against real telemetry.

Each document states its own limits alongside its results, on the principle that evidence which
overstates itself is worse than none.

## Quick Start

```bash
# Install dependencies
pip install -r scripts/requirements.txt
pip install sigma-cli

# Run the tooling unit tests
python -m pytest

# Validate a single rule
sigma check rules/windows/credential_access/lsass_memory_access.yml

# Convert to Splunk SPL
sigma convert -t splunk rules/windows/credential_access/lsass_memory_access.yml

# Generate coverage report
python scripts/generate_coverage.py --output docs/COVERAGE.md

# Export the production-rule manifest for ADTE
python scripts/export_manifest.py --rules-dir rules --output docs/rule_manifest.json
```

## ADTE Integration

This pipeline publishes a machine-readable manifest of production rules for [ADTE](https://github.com/dlpz-SEC) (Autonomous Detection Triage Engine), which maps triaged incidents back to detection coverage, confidence weighting, and tuning guidance.

- **Artifact:** `docs/rule_manifest.json` — every `lifecycle: production` rule with its ATT&CK techniques, `confidence_weight`, false-positive rate, tuning notes, and `wazuh_rule_ids`.
- **Contract:** documented in [`docs/rule_manifest_schema.md`](docs/rule_manifest_schema.md). ADTE joins incidents to detections on the rule `id`, and joins **live Wazuh alerts** on `rule.id` ∈ `wazuh_rule_ids` — recovering the full detection context (confidence, tuning notes, techniques) for anything the Wazuh engine fires.
- **Freshness:** regenerated on every push to `main`; committed back only when rule content changes, so `generated_at` is a stable content-change watermark rather than a per-run timestamp.

This closes the loop: **DaC defines detections → Wazuh and Sentinel run them → ADTE triages the
alerts with full rule context.**

## Adding New Rules

1. Create rule in appropriate `rules/{os}/{tactic}/` directory
2. Follow naming convention: `{technique_name}_{variant}.yml`
3. Include all required fields (see `docs/RULE_STANDARD.md`)
4. Add test samples in `tests/samples/true_positives/`
5. Set `lifecycle: draft` initially
6. Open PR - CI will validate

## Coverage Metrics

Coverage is measured with confidence weighting:

| Confidence | Weight | Criteria |
|------------|--------|----------|
| High | 1.0 | Production rule, low FP rate, behavioral tests pass |
| Medium | 0.6 | Experimental rule OR moderate FP rate |
| Low | 0.3 | Draft rule OR high FP rate OR no test samples |

A technique with three "low confidence" rules scores lower than one "high confidence" rule.

## Development
This project was built with AI-assisted development. All rules were validated locally and through CI. Pipeline logic, lifecycle gating, and coverage methodology were understood before publication.

## License

MIT 
