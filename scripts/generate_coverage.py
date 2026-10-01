#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Analyzer

Generates coverage reports with confidence-weighted scoring.
Key differentiator: A technique with three noisy rules scores LOWER than
one high-fidelity detection.

Output formats:
- Markdown report with coverage tables
- ATT&CK Navigator JSON layer for visualization
"""

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml


# Confidence weights for coverage scoring
CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
    None: 0.3  # Default for missing confidence
}

# Behavioral-test state weights. A rule with no behavioral evidence
# ("untested" — a correlation rule converting to aggregation SPL, a rule no
# true-positive sample routes to, or no Tier-1 result at all) must score BELOW
# a rule with a passing behavioral test, but above a rule whose test actually
# failed. Scoring it as passed would inflate published coverage.
TEST_STATE_WEIGHTS = {
    "passed": 1.0,
    "untested": 0.6,
    "failed": 0.5,
}

# Lifecycle weights (draft rules contribute less to coverage)
LIFECYCLE_WEIGHTS = {
    "production": 1.0,
    "experimental": 0.7,
    "draft": 0.2,
    "deprecated": 0.0
}

# MITRE ATT&CK tactic ordering (enterprise matrix, ATT&CK v19.1 - the release
# scripts/sigma_lint.py pins). v19 renamed TA0005 Defense Evasion to Stealth
# and added TA0112 Defense Impairment beside it.
TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "stealth", "defense_impairment", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact"
]

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development", 
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "stealth": "Stealth",
    "defense_impairment": "Defense Impairment",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}

# Retired tactic names and what replaced them, so rules tagged the old way
# still count. TA0005 kept its ID when v19 renamed it.
TACTIC_ALIASES = {"defense_evasion": "stealth"}


@dataclass
class RuleCoverage:
    """Coverage information for a single rule."""
    filepath: str
    title: str
    techniques: list[str]
    tactics: list[str]
    lifecycle: str
    confidence: Optional[str]
    level: str
    # "passed" | "failed" | "untested". Tri-valued on purpose: a rule with no
    # behavioral evidence is not the same as one that passed, and must not
    # claim full coverage weight. untested_reason says which kind of absence.
    test_state: str
    untested_reason: Optional[str] = None
    
    @property
    def coverage_score(self) -> float:
        """Calculate weighted coverage score for this rule."""
        confidence_weight = CONFIDENCE_WEIGHTS.get(self.confidence, 0.3)
        lifecycle_weight = LIFECYCLE_WEIGHTS.get(self.lifecycle, 0.2)
        # "untested" sits between passed and failed: it is not a broken rule,
        # but it has no behavioral evidence, so it cannot score as if it did.
        test_weight = TEST_STATE_WEIGHTS.get(self.test_state, 0.5)

        return confidence_weight * lifecycle_weight * test_weight


@dataclass 
class TechniqueCoverage:
    """Aggregated coverage for a single technique."""
    technique_id: str
    technique_name: str
    tactics: list[str]
    rules: list[RuleCoverage]
    
    @property
    def coverage_score(self) -> float:
        """
        Calculate technique coverage score.
        
        Key insight: More rules doesn't necessarily mean better coverage.
        We use max score with diminishing returns for additional rules.
        
        Formula: max_score + sum(other_scores) * 0.1 (capped at +0.2)
        """
        if not self.rules:
            return 0.0
        
        scores = sorted([r.coverage_score for r in self.rules], reverse=True)
        max_score = scores[0]
        
        # Additional rules provide diminishing marginal value
        # (indicates depth but also potential overlap/redundancy)
        bonus = min(sum(scores[1:]) * 0.1, 0.2)
        
        return min(max_score + bonus, 1.0)
    
    @property
    def confidence_level(self) -> str:
        """Determine overall confidence level based on score."""
        score = self.coverage_score
        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score > 0:
            return "low"
        return "none"


def parse_rule(filepath: Path, test_results: dict = None) -> Optional[RuleCoverage]:
    """Parse a Sigma rule and extract coverage information.

    Handles multi-document files (pySigma correlation rules = base rule +
    correlation doc): the first detection-bearing doc provides the rule
    metadata, and MITRE tags are unioned across every doc so correlation
    techniques appear in coverage instead of silently vanishing.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f)
                    if isinstance(d, dict)]
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        return None

    if not docs:
        return None

    rule = next((d for d in docs if "detection" in d), docs[0])

    tags = []
    for doc in docs:
        for tag in doc.get("tags", []) or []:
            if tag not in tags:
                tags.append(tag)
    custom = rule.get("custom", {})
    
    # Extract MITRE techniques and tactics
    techniques = []
    tactics = []
    
    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        
        value = tag[7:]  # Remove "attack." prefix
        
        if re.match(r'^t\d{4}(\.\d{3})?$', value):
            techniques.append(value.upper())  # Normalize to uppercase
        else:
            # Sigma spec form is hyphenated (attack.credential-access); older
            # rules use underscores. Read both, key internally on underscores.
            tactic = value.replace("-", "_")
            tactic = TACTIC_ALIASES.get(tactic, tactic)
            if tactic in TACTIC_ORDER and tactic not in tactics:
                tactics.append(tactic)

    test_state, untested_reason = resolve_test_state(filepath.stem, test_results)

    return RuleCoverage(
        filepath=str(filepath),
        title=rule.get("title", "Unknown"),
        techniques=techniques,
        tactics=tactics,
        lifecycle=custom.get("lifecycle", "draft"),
        confidence=custom.get("confidence"),
        level=rule.get("level", "medium"),
        test_state=test_state,
        untested_reason=untested_reason,
    )


def _sensitivity_tested(entry: dict) -> bool:
    """Whether any true-positive sample was actually evaluated for a rule.

    test_detections.py emits `sensitivity_tested` explicitly. Older result
    files only carry the "detected/total" string, so fall back to parsing it.
    An entry that states neither is treated as untested: absence of evidence
    is not evidence.
    """
    if "sensitivity_tested" in entry:
        return bool(entry["sensitivity_tested"])
    match = re.match(r"^\s*\d+\s*/\s*(\d+)\s*$", str(entry.get("true_positives", "")))
    return bool(match) and int(match.group(1)) > 0


def resolve_test_state(rule_name: str, test_results: Optional[dict]) -> tuple[str, Optional[str]]:
    """Map a rule's Tier-1 result to (test_state, untested_reason).

    The harness passes a rule that no true-positive sample routes to (0/0),
    because its CI gate only asks "no false positives, and sensitivity OK
    where testable". That is a gate, not evidence: coverage must score such a
    rule as untested, or a rule nobody exercised claims full weight.
    """
    if test_results is None:
        return "untested", "no test results supplied"
    skipped = set(test_results.get("summary", {}).get("skipped_aggregation", []))
    if rule_name in skipped:
        return "untested", "aggregation query"
    entry = test_results.get("results", {}).get(rule_name)
    if entry is None:
        return "untested", "no Tier-1 result"
    if not entry.get("passed"):
        return "failed", None
    if not _sensitivity_tested(entry):
        return "untested", "no true-positive sample"
    return "passed", None


def load_technique_names() -> dict:
    """
    Load MITRE ATT&CK technique names.
    
    In production, this would load from the official MITRE STIX data.
    For this example, we return a subset of common techniques.
    """
    # Common techniques - in production, load from MITRE ATT&CK STIX
    return {
        "T1003": "OS Credential Dumping",
        "T1003.001": "LSASS Memory",
        "T1003.002": "Security Account Manager",
        "T1003.003": "NTDS",
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.003": "Windows Command Shell",
        "T1059.005": "Visual Basic",
        "T1059.007": "JavaScript",
        "T1547": "Boot or Logon Autostart Execution",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1053": "Scheduled Task/Job",
        "T1053.005": "Scheduled Task",
        "T1055": "Process Injection",
        "T1055.001": "Dynamic-link Library Injection",
        "T1055.012": "Process Hollowing",
        "T1082": "System Information Discovery",
        "T1087": "Account Discovery",
        "T1069": "Permission Groups Discovery",
        "T1018": "Remote System Discovery",
        "T1105": "Ingress Tool Transfer",
        "T1140": "Deobfuscate/Decode Files or Information",
        "T1027": "Obfuscated Files or Information",
        "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery",
        "T1078": "Valid Accounts",
        "T1078.002": "Domain Accounts",
        "T1110": "Brute Force",
        "T1110.001": "Password Guessing",
        "T1110.003": "Password Spraying",
        # Add more as needed
    }


# MITRE tactics per parent technique, as of ATT&CK v19.1 (sub-techniques
# inherit their parent's).
# Sigma tags carry tactics at RULE level, with no link to a specific technique,
# so a rule tagged execution + defense-evasion + T1059 + T1027 cannot say which
# tactic goes with which technique. This table supplies the missing link.
TECHNIQUE_TACTICS = {
    "T1003": ["credential_access"],
    "T1018": ["discovery"],
    "T1027": ["stealth"],
    "T1053": ["execution", "persistence", "privilege_escalation"],
    "T1055": ["stealth", "privilege_escalation"],
    "T1059": ["execution"],
    "T1069": ["discovery"],
    "T1078": ["initial_access", "persistence", "privilege_escalation", "stealth"],
    "T1082": ["discovery"],
    "T1087": ["discovery"],
    "T1105": ["command_and_control"],
    "T1110": ["credential_access"],
    "T1140": ["stealth"],
    "T1486": ["impact"],
    "T1490": ["impact"],
    "T1547": ["persistence", "privilege_escalation"],
}


def resolve_tactics(technique_id: str, rule_tactics: set[str]) -> list[str]:
    """Tactics a technique is reported under, in ATT&CK matrix order.

    Known technique: the MITRE tactics its covering rules actually claim, or
    all of its MITRE tactics if they claim none of them. Unknown technique:
    the union of tactics its covering rules claim.
    """
    known = TECHNIQUE_TACTICS.get(technique_id.split(".")[0])
    if known is None:
        chosen = set(rule_tactics)
    else:
        chosen = {t for t in known if t in rule_tactics} or set(known)
    return [t for t in TACTIC_ORDER if t in chosen]


def build_coverage_map(rules_dir: Path, test_results: dict = None) -> dict[str, TechniqueCoverage]:
    """Build a map of technique ID to coverage information."""
    technique_names = load_technique_names()
    coverage_map: dict[str, TechniqueCoverage] = {}
    claimed_tactics: dict[str, set[str]] = defaultdict(set)

    # Parse all rules
    for filepath in sorted(rules_dir.rglob("*.yml")):
        rule_coverage = parse_rule(filepath, test_results)
        if not rule_coverage:
            continue

        # Add rule to each technique it covers
        for tech_id in rule_coverage.techniques:
            if tech_id not in coverage_map:
                coverage_map[tech_id] = TechniqueCoverage(
                    technique_id=tech_id,
                    technique_name=technique_names.get(tech_id, "Unknown"),
                    tactics=[],
                    rules=[]
                )
            coverage_map[tech_id].rules.append(rule_coverage)
            claimed_tactics[tech_id].update(rule_coverage.tactics)

    # Tactics are resolved once every covering rule is known, so the result
    # does not depend on which rule file happened to be parsed first.
    for tech_id, tech in coverage_map.items():
        tech.tactics = resolve_tactics(tech_id, claimed_tactics[tech_id])

    return coverage_map


def count_rule_files(coverage_map: dict[str, TechniqueCoverage]) -> int:
    """Distinct rule files behind the map (a rule tagging N techniques counts once)."""
    return len({r.filepath for t in coverage_map.values() for r in t.rules})


def generate_markdown_report(
    coverage_map: dict[str, TechniqueCoverage], test_results_supplied: bool = True
) -> str:
    """Generate a Markdown coverage report."""
    behavioral = (
        "included" if test_results_supplied
        else "not supplied, so every rule is scored as untested"
    )
    lines = [
        "# MITRE ATT&CK Coverage Report",
        "",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        f"*Tier-1 behavioral test results: {behavioral}.*",
        "",
        "## Executive Summary",
        "",
    ]
    
    # Calculate summary statistics
    total_techniques = len(coverage_map)
    high_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "high")
    med_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "medium")
    low_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "low")
    rule_files = count_rule_files(coverage_map)
    
    lines.extend([
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Techniques Covered | {total_techniques} |",
        f"| High Confidence | {high_conf} |",
        f"| Medium Confidence | {med_conf} |",
        f"| Low Confidence | {low_conf} |",
        f"| Rule files | {rule_files} |",
        "",
        "## Coverage by Tactic",
        "",
    ])
    
    # Group by tactic
    tactic_coverage: dict[str, list[TechniqueCoverage]] = defaultdict(list)
    for tech in coverage_map.values():
        for tactic in tech.tactics:
            tactic_coverage[tactic].append(tech)
    
    for tactic in TACTIC_ORDER:
        techniques = tactic_coverage.get(tactic, [])
        if not techniques:
            continue
        
        tactic_name = TACTIC_NAMES.get(tactic, tactic)
        lines.append(f"### {tactic_name}")
        lines.append("")
        lines.append("| Technique | Name | Rules | Confidence | Score |")
        lines.append("|-----------|------|-------|------------|-------|")
        
        for tech in sorted(techniques, key=lambda t: t.technique_id):
            confidence_emoji = {
                "high": "🟢",
                "medium": "🟡", 
                "low": "🟠",
                "none": "⚪"
            }.get(tech.confidence_level, "⚪")
            
            lines.append(
                f"| {tech.technique_id} | {tech.technique_name} | "
                f"{len(tech.rules)} | {confidence_emoji} {tech.confidence_level} | "
                f"{tech.coverage_score:.2f} |"
            )
        
        lines.append("")
    
    # Gap analysis section
    lines.extend([
        "## Coverage Gaps",
        "",
        "Techniques below medium confidence, with failing tests, or not "
        "behaviorally tested:",
        "",
    ])

    gaps = [t for t in coverage_map.values()
            if t.confidence_level in ["low", "none"] or
            any(r.test_state != "passed" for r in t.rules)]
    
    if gaps:
        lines.append("| Technique | Issue |")
        lines.append("|-----------|-------|")
        for tech in sorted(gaps, key=lambda t: t.technique_id):
            issues = []
            if tech.confidence_level == "low":
                issues.append("Low confidence")
            if any(r.test_state == "failed" for r in tech.rules):
                issues.append("Test failures")
            reasons = sorted({r.untested_reason or "untested"
                              for r in tech.rules if r.test_state == "untested"})
            if reasons:
                issues.append(f"Not behaviorally tested ({'; '.join(reasons)})")
            lines.append(f"| {tech.technique_id} | {', '.join(issues)} |")
    else:
        lines.append("*No significant coverage gaps identified.*")
    
    lines.append("")
    
    return "\n".join(lines)


def generate_navigator_layer(coverage_map: dict[str, TechniqueCoverage]) -> dict:
    """
    Generate ATT&CK Navigator layer JSON.
    
    This format can be imported into https://mitre-attack.github.io/attack-navigator/
    for visual coverage analysis.
    """
    techniques = []
    
    for tech in coverage_map.values():
        score = tech.coverage_score
        
        # Map score to color gradient (0 = red, 1 = green)
        if score >= 0.8:
            color = "#2ecc71"  # Green - high confidence
        elif score >= 0.5:
            color = "#f1c40f"  # Yellow - medium confidence
        elif score > 0:
            color = "#e67e22"  # Orange - low confidence
        else:
            color = "#e74c3c"  # Red - no coverage
        
        techniques.append({
            "techniqueID": tech.technique_id,
            "score": round(score * 100),
            "color": color,
            "comment": f"Rules: {len(tech.rules)}, Confidence: {tech.confidence_level}",
            "enabled": True,
            "metadata": [
                {"name": "rule_count", "value": str(len(tech.rules))},
                {"name": "confidence", "value": tech.confidence_level}
            ]
        })
    
    layer = {
        "name": "Detection Coverage",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": f"Detection coverage as of {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#e74c3c", "#f1c40f", "#2ecc71"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "High Confidence (80-100)", "color": "#2ecc71"},
            {"label": "Medium Confidence (50-79)", "color": "#f1c40f"},
            {"label": "Low Confidence (1-49)", "color": "#e67e22"},
            {"label": "No Coverage", "color": "#e74c3c"}
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }
    
    return layer


def main():
    parser = argparse.ArgumentParser(description="Generate MITRE ATT&CK coverage report")
    parser.add_argument("--rules-dir", required=True, help="Directory containing rules")
    parser.add_argument("--test-results", help="JSON file with test results")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--format", choices=["markdown", "navigator"], default="markdown")
    args = parser.parse_args()
    
    # Load test results if provided
    test_results = None
    if args.test_results:
        try:
            with open(args.test_results, encoding="utf-8") as f:
                test_results = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load test results: {e}")
    
    # Build coverage map
    rules_dir = Path(args.rules_dir)
    coverage_map = build_coverage_map(rules_dir, test_results)
    
    print(f"Analyzed {count_rule_files(coverage_map)} rule files")
    print(f"Covering {len(coverage_map)} techniques")

    # Generate output. Explicit UTF-8: the report carries emoji, which the
    # Windows default code page (cp1252) cannot encode.
    if args.format == "markdown":
        content = generate_markdown_report(coverage_map, test_results is not None)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Markdown report written to: {args.output}")
    
    elif args.format == "navigator":
        layer = generate_navigator_layer(coverage_map)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2)
        print(f"Navigator layer written to: {args.output}")


if __name__ == "__main__":
    main()
