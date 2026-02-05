# Rule Authoring Standards

This document defines the standards for writing Sigma rules in this repository.

## Required Fields by Lifecycle State

### Draft Rules
Minimum viable rule for development purposes.

```yaml
title: Short descriptive title
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        FieldName: value
    condition: selection
custom:
    lifecycle: draft
```

### Experimental Rules
Ready for testing in non-production environments.

```yaml
title: Short descriptive title
description: Multi-line description explaining what this detects and why
tags:
    - attack.tactic_name
    - attack.tXXXX
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        FieldName: value
    condition: selection
custom:
    lifecycle: experimental
    confidence: medium
```

### Production Rules
Full documentation required for deployment.

```yaml
title: Short descriptive title
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  # UUID v4
status: stable
description: |
    Multi-line description explaining:
    - What behavior this detects
    - Why it's malicious
    - How attackers use this technique
references:
    - https://attack.mitre.org/techniques/TXXXX/
    - Additional research links
author: Your Name / Team Name
date: YYYY/MM/DD
modified: YYYY/MM/DD
tags:
    - attack.tactic_name
    - attack.tXXXX
    - attack.tXXXX.XXX  # Subtechnique if applicable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        FieldName: value
    filter_known_good:
        FieldName|contains:
            - legitimate_value
    condition: selection and not filter_known_good
level: high
falsepositives:
    - Specific false positive scenario 1
    - Specific false positive scenario 2
custom:
    lifecycle: production
    confidence: high
    false_positive_rate: low
    investigation_steps: |
        1. First step
        2. Second step
    tuning_notes: |
        Environment-specific tuning guidance
    owner: team@example.com
    review_frequency: quarterly
    last_reviewed: YYYY-MM-DD
```

## Naming Conventions

### File Names
- Use lowercase with underscores: `suspicious_lsass_access.yml`
- Include technique name: `powershell_encoded_command.yml`
- Add variant suffix if multiple rules for same technique: `scheduled_task_creation_cli.yml`

### Directory Structure
Place rules in directories matching MITRE ATT&CK tactics:
```
rules/
├── windows/
│   ├── credential_access/
│   ├── execution/
│   ├── persistence/
│   └── ...
└── linux/
    ├── execution/
    └── ...
```

## Detection Logic Guidelines

### Selection Naming
Use descriptive selection names:
```yaml
detection:
    selection_process:        # What we're looking for
        Image|endswith: '\cmd.exe'
    selection_suspicious_args:  # Why it's suspicious
        CommandLine|contains:
            - ' -enc '
            - ' -e '
    filter_legitimate:        # Known good exclusions
        ParentImage|endswith: '\legitimate.exe'
    condition: selection_process and selection_suspicious_args and not filter_legitimate
```

### Avoid Common Mistakes

1. **Don't use overly broad conditions**
   ```yaml
   # BAD - too noisy
   detection:
       selection:
           Image|endswith: '.exe'
       condition: selection
   ```

2. **Don't forget case sensitivity**
   ```yaml
   # GOOD - handles case variations
   selection:
       CommandLine|contains|all:
           - '/c'  # Will match /C and /c
   ```

3. **Document all exclusions**
   ```yaml
   # Each filter should have a comment explaining WHY
   filter_backup_tools:
       # Veeam agent performs legitimate LSASS queries for 
       # VSS writer enumeration during backup operations
       SourceImage|contains: '\VeeamAgent'
   ```

## MITRE ATT&CK Tagging

### Required Tags
- At least one tactic tag: `attack.credential_access`
- Technique ID for experimental/production: `attack.t1003`
- Subtechnique if applicable: `attack.t1003.001`

### Tag Format
```yaml
tags:
    - attack.credential_access    # Tactic (lowercase with underscores)
    - attack.t1003               # Technique (lowercase t + 4 digits)
    - attack.t1003.001           # Subtechnique (technique + .XXX)
```

## Testing Requirements

### True Positive Samples
Every production rule MUST have at least one true positive test sample that demonstrates the attack behavior.

Sample format:
```json
{
    "name": "Descriptive name",
    "description": "What attack this simulates",
    "type": "true_positive",
    "technique_id": "T1003.001",
    "events": [
        { "field": "value" }
    ]
}
```

### False Positive Testing
Document known false positive scenarios in the rule and include benign samples that should NOT trigger.

## Review Checklist

Before submitting a rule for production:

- [ ] UUID is unique (generate with `uuidgen` or online tool)
- [ ] Description explains the "what" and "why"
- [ ] MITRE ATT&CK tags are accurate
- [ ] Detection logic has been tested
- [ ] False positives are documented
- [ ] Tuning notes provide actionable guidance
- [ ] Test samples exist (true positive and benign)
- [ ] Investigation steps help SOC analysts respond
