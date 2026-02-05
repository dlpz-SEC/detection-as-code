#!/usr/bin/env python3
"""
Sigma Rule Validator

Validates Sigma rules against:
1. Official Sigma YAML schema
2. Custom organizational requirements (MITRE tags, lifecycle fields, etc.)
3. Logic consistency checks

Enterprise considerations:
- Strict mode fails on warnings (for production rules)
- JSON output for integration with other tooling
- Detailed error messages for rapid remediation
"""

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Lifecycle(str, Enum):
    DRAFT = "draft"
    EXPERIMENTAL = "experimental"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


@dataclass
class ValidationIssue:
    """Structured validation issue for reporting."""
    file: str
    severity: Severity
    code: str
    message: str
    line: Optional[int] = None
    
    def to_dict(self):
        return {
            "file": self.file,
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "line": self.line
        }


# Required fields based on lifecycle state
LIFECYCLE_REQUIREMENTS = {
    Lifecycle.DRAFT: {
        "required": ["title", "logsource", "detection"],
        "recommended": ["description", "tags"]
    },
    Lifecycle.EXPERIMENTAL: {
        "required": ["title", "logsource", "detection", "description", "tags", "level"],
        "recommended": ["references", "author", "date"]
    },
    Lifecycle.PRODUCTION: {
        "required": [
            "title", "logsource", "detection", "description", "tags", 
            "level", "status", "author", "date", "id"
        ],
        "recommended": ["references", "falsepositives"]
    },
    Lifecycle.DEPRECATED: {
        "required": ["title", "logsource", "detection", "custom.deprecation_reason"],
        "recommended": []
    }
}


def validate_rule_schema(rule: dict, filepath: str) -> list[ValidationIssue]:
    """
    Validate rule against basic Sigma schema requirements.
    
    The official Sigma schema is permissive - this function checks the
    structural requirements that must be present for any valid rule.
    """
    issues = []
    
    # Title is always required
    if "title" not in rule:
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="MISSING_TITLE",
            message="Rule must have a 'title' field"
        ))
    elif not isinstance(rule["title"], str) or len(rule["title"]) < 5:
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="INVALID_TITLE",
            message="Title must be a string with at least 5 characters"
        ))
    
    # Logsource validation
    if "logsource" not in rule:
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="MISSING_LOGSOURCE",
            message="Rule must have a 'logsource' field"
        ))
    else:
        logsource = rule["logsource"]
        if not isinstance(logsource, dict):
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="INVALID_LOGSOURCE",
                message="Logsource must be a dictionary"
            ))
        else:
            # Logsource should have at least one of: category, product, service
            if not any(k in logsource for k in ["category", "product", "service"]):
                issues.append(ValidationIssue(
                    file=filepath,
                    severity=Severity.ERROR,
                    code="EMPTY_LOGSOURCE",
                    message="Logsource must specify at least one of: category, product, service"
                ))
    
    # Detection validation
    if "detection" not in rule:
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="MISSING_DETECTION",
            message="Rule must have a 'detection' field"
        ))
    else:
        detection = rule["detection"]
        if not isinstance(detection, dict):
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="INVALID_DETECTION",
                message="Detection must be a dictionary"
            ))
        elif "condition" not in detection:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="MISSING_CONDITION",
                message="Detection must have a 'condition' field"
            ))
        else:
            # Check that condition references existing selections
            condition = detection["condition"]
            selection_names = [k for k in detection.keys() if k != "condition"]
            
            # Basic check: condition should reference at least one selection
            if not selection_names:
                issues.append(ValidationIssue(
                    file=filepath,
                    severity=Severity.ERROR,
                    code="NO_SELECTIONS",
                    message="Detection must have at least one selection (besides condition)"
                ))
            else:
                # Check for unreferenced selections
                for sel in selection_names:
                    if sel not in condition and sel.replace("_", "") not in condition:
                        issues.append(ValidationIssue(
                            file=filepath,
                            severity=Severity.WARNING,
                            code="UNREFERENCED_SELECTION",
                            message=f"Selection '{sel}' is not referenced in condition"
                        ))
    
    # Level validation
    if "level" in rule:
        valid_levels = ["informational", "low", "medium", "high", "critical"]
        if rule["level"] not in valid_levels:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="INVALID_LEVEL",
                message=f"Level must be one of: {', '.join(valid_levels)}"
            ))
    
    # Status validation
    if "status" in rule:
        valid_statuses = ["stable", "test", "experimental", "deprecated", "unsupported"]
        if rule["status"] not in valid_statuses:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="INVALID_STATUS",
                message=f"Status must be one of: {', '.join(valid_statuses)}"
            ))
    
    # ID format validation (should be UUID)
    if "id" in rule:
        import re
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, str(rule["id"]).lower()):
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="INVALID_UUID",
                message="Rule ID must be a valid UUID format"
            ))
    
    return issues


def validate_mitre_tags(rule: dict, filepath: str, lifecycle: Lifecycle) -> list[ValidationIssue]:
    """
    Validate MITRE ATT&CK tagging requirements.
    
    Production rules require:
    - At least one technique tag (attack.tXXXX)
    - Valid technique ID format
    
    Experimental rules require:
    - At least one tactic tag (attack.tactic_name)
    """
    issues = []
    tags = rule.get("tags", [])
    
    if not isinstance(tags, list):
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="INVALID_TAGS",
            message="Tags must be a list"
        ))
        return issues
    
    attack_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]
    tactic_tags = [t for t in attack_tags if not t.startswith("attack.t") and not t.startswith("attack.s")]
    technique_tags = [t for t in attack_tags if t.startswith("attack.t")]
    subtechnique_tags = [t for t in attack_tags if ".t" in t and "." in t.split("attack.t")[-1]]
    
    # Valid MITRE tactics
    valid_tactics = [
        "attack.reconnaissance", "attack.resource_development", "attack.initial_access",
        "attack.execution", "attack.persistence", "attack.privilege_escalation",
        "attack.defense_evasion", "attack.credential_access", "attack.discovery",
        "attack.lateral_movement", "attack.collection", "attack.command_and_control",
        "attack.exfiltration", "attack.impact"
    ]
    
    if lifecycle in [Lifecycle.PRODUCTION, Lifecycle.EXPERIMENTAL]:
        if not attack_tags:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="MISSING_MITRE_TAGS",
                message=f"Rules with lifecycle '{lifecycle.value}' must have MITRE ATT&CK tags"
            ))
    
    if lifecycle == Lifecycle.PRODUCTION:
        if not technique_tags:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="MISSING_TECHNIQUE_ID",
                message="Production rules must have at least one technique tag (attack.tXXXX)"
            ))
    
    # Validate tactic names
    for tag in tactic_tags:
        if tag not in valid_tactics:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.WARNING,
                code="UNKNOWN_TACTIC",
                message=f"Unknown tactic tag: {tag}"
            ))
    
    # Validate technique ID format (attack.t1XXX or attack.t1XXX.XXX)
    import re
    technique_pattern = r'^attack\.t\d{4}(\.\d{3})?$'
    for tag in technique_tags:
        if not re.match(technique_pattern, tag):
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.WARNING,
                code="INVALID_TECHNIQUE_FORMAT",
                message=f"Technique tag '{tag}' doesn't match expected format (attack.tXXXX or attack.tXXXX.XXX)"
            ))
    
    return issues


def validate_custom_fields(rule: dict, filepath: str) -> list[ValidationIssue]:
    """
    Validate custom organizational fields (lifecycle, confidence, etc.).
    """
    issues = []
    custom = rule.get("custom", {})
    
    # Determine lifecycle
    lifecycle_str = custom.get("lifecycle", "draft")
    try:
        lifecycle = Lifecycle(lifecycle_str)
    except ValueError:
        issues.append(ValidationIssue(
            file=filepath,
            severity=Severity.ERROR,
            code="INVALID_LIFECYCLE",
            message=f"Invalid lifecycle value: {lifecycle_str}. Must be one of: {', '.join(l.value for l in Lifecycle)}"
        ))
        lifecycle = Lifecycle.DRAFT
    
    # Validate required fields based on lifecycle
    requirements = LIFECYCLE_REQUIREMENTS.get(lifecycle, LIFECYCLE_REQUIREMENTS[Lifecycle.DRAFT])
    
    for field in requirements["required"]:
        if "." in field:  # Nested field (e.g., custom.deprecation_reason)
            parts = field.split(".")
            value = rule
            for part in parts:
                value = value.get(part, {}) if isinstance(value, dict) else None
            if not value:
                issues.append(ValidationIssue(
                    file=filepath,
                    severity=Severity.ERROR,
                    code="MISSING_REQUIRED_FIELD",
                    message=f"Rules with lifecycle '{lifecycle.value}' require field: {field}"
                ))
        elif field not in rule:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.ERROR,
                code="MISSING_REQUIRED_FIELD",
                message=f"Rules with lifecycle '{lifecycle.value}' require field: {field}"
            ))
    
    for field in requirements["recommended"]:
        if field not in rule:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.WARNING,
                code="MISSING_RECOMMENDED_FIELD",
                message=f"Consider adding field: {field}"
            ))
    
    # Production rules should have confidence rating
    if lifecycle == Lifecycle.PRODUCTION:
        confidence = custom.get("confidence")
        if confidence not in ["high", "medium", "low"]:
            issues.append(ValidationIssue(
                file=filepath,
                severity=Severity.WARNING,
                code="MISSING_CONFIDENCE",
                message="Production rules should have custom.confidence (high/medium/low)"
            ))
    
    return issues


def validate_rule(filepath: Path, strict: bool = False) -> list[ValidationIssue]:
    """
    Validate a single Sigma rule file.
    
    Args:
        filepath: Path to the rule YAML file
        strict: If True, treat warnings as errors
    
    Returns:
        List of validation issues found
    """
    issues = []
    
    try:
        with open(filepath) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        issues.append(ValidationIssue(
            file=str(filepath),
            severity=Severity.ERROR,
            code="YAML_PARSE_ERROR",
            message=f"Failed to parse YAML: {e}"
        ))
        return issues
    
    if not isinstance(rule, dict):
        issues.append(ValidationIssue(
            file=str(filepath),
            severity=Severity.ERROR,
            code="INVALID_RULE_FORMAT",
            message="Rule must be a YAML dictionary"
        ))
        return issues
    
    # Run all validators
    issues.extend(validate_rule_schema(rule, str(filepath)))
    
    # Get lifecycle for context-aware validation
    lifecycle_str = rule.get("custom", {}).get("lifecycle", "draft")
    try:
        lifecycle = Lifecycle(lifecycle_str)
    except ValueError:
        lifecycle = Lifecycle.DRAFT
    
    issues.extend(validate_mitre_tags(rule, str(filepath), lifecycle))
    issues.extend(validate_custom_fields(rule, str(filepath)))
    
    return issues


def main():
    parser = argparse.ArgumentParser(description="Validate Sigma rules")
    parser.add_argument("--rules-dir", required=True, help="Directory containing rules")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--output", help="Output file for JSON report")
    args = parser.parse_args()
    
    rules_dir = Path(args.rules_dir)
    all_issues = []
    error_count = 0
    warning_count = 0
    
    # Find and validate all rules
    for filepath in rules_dir.rglob("*.yml"):
        issues = validate_rule(filepath, args.strict)
        all_issues.extend(issues)
        
        for issue in issues:
            if issue.severity == Severity.ERROR:
                error_count += 1
            elif issue.severity == Severity.WARNING:
                warning_count += 1
    
    # Print summary to console
    print(f"\n{'='*60}")
    print(f"Validation Complete")
    print(f"{'='*60}")
    print(f"Rules checked: {len(list(rules_dir.rglob('*.yml')))}")
    print(f"Errors: {error_count}")
    print(f"Warnings: {warning_count}")
    print(f"{'='*60}\n")
    
    # Print detailed issues
    for issue in all_issues:
        severity_symbol = "❌" if issue.severity == Severity.ERROR else "⚠️" if issue.severity == Severity.WARNING else "ℹ️"
        print(f"{severity_symbol} [{issue.code}] {issue.file}")
        print(f"   {issue.message}\n")
    
    # Write JSON report
    if args.output:
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_rules": len(list(rules_dir.rglob("*.yml"))),
                "errors": error_count,
                "warnings": warning_count
            },
            "issues": [i.to_dict() for i in all_issues]
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to: {args.output}")
    
    # Exit with error if any issues (or warnings in strict mode)
    if error_count > 0:
        sys.exit(1)
    if args.strict and warning_count > 0:
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
