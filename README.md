# Detection-as-Code Pipeline

<p align="center">
  <img src="https://img.shields.io/badge/Detection--as--Code-Sigma-2563EB?style=for-the-badge&logo=databricks&logoColor=white" />
  <img src="https://img.shields.io/badge/CI%2FCD-Gates-111827?style=for-the-badge&logo=githubactions&logoColor=white" />
  <img src="https://img.shields.io/badge/Behavioral%20Tests-TP%20%7C%20Benign-7C3AED?style=for-the-badge&logo=pytest&logoColor=white" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-DC2626?style=for-the-badge&logo=mitre&logoColor=white" />
  <img src="https://img.shields.io/badge/SIEM%20Outputs-SPL%20%7C%20KQL%20%7C%20ES-0A66C2?style=for-the-badge&logo=splunk&logoColor=white" />
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
├── rules/
│   ├── windows/
│   │   ├── credential_access/         # MITRE tactic-aligned directories
│   │   ├── execution/
│   │   ├── persistence/
│   │   └── discovery/
│   └── linux/
│       ├── execution/
│       └── persistence/
├── tests/
│   └── samples/
│       ├── true_positives/            # Log samples that SHOULD trigger rules
│       └── benign/                    # Log samples that should NOT trigger
├── scripts/
│   ├── validate_rules.py              # Schema + custom field validation
│   ├── generate_coverage.py           # MITRE ATT&CK coverage analysis
│   ├── test_detections.py             # Behavioral testing against samples
│   └── requirements.txt
├── configs/
│   ├── sigma_config.yml               # Field mappings for SIEM conversion
│   └── coverage_config.yml            # MITRE technique weights/priorities
├── docs/
│   ├── COVERAGE.md                    # Auto-generated coverage report
│   └── RULE_STANDARD.md               # Rule authoring guidelines
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

### 2. Linting  
Checks for:
- Missing MITRE ATT&CK tags
- Invalid log source configurations
- Deprecated field usage
- Detection logic errors (impossible conditions, etc.)

### 3. SIEM Conversion
Converts rules to target SIEM query languages:
- Splunk SPL
- Microsoft Sentinel KQL
- Elastic Query DSL

### 4. Behavioral Testing
Runs converted queries against test samples to verify:
- True positives are detected (sensitivity)
- Benign samples don't trigger (specificity)

### 5. Coverage Analysis
Generates MITRE ATT&CK coverage report with confidence weighting.

## Quick Start

```bash
# Install dependencies
pip install -r scripts/requirements.txt
pip install sigma-cli

# Validate a single rule
sigma check rules/windows/credential_access/lsass_access.yml

# Convert to Splunk SPL
sigma convert -t splunk rules/windows/credential_access/lsass_access.yml

# Generate coverage report
python scripts/generate_coverage.py --output docs/COVERAGE.md
```

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
