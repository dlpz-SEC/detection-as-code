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
from datetime import datetime
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

# Lifecycle weights (draft rules contribute less to coverage)
LIFECYCLE_WEIGHTS = {
    "production": 1.0,
    "experimental": 0.7,
    "draft": 0.2,
    "deprecated": 0.0
}

# MITRE ATT&CK tactic ordering
TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery",
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
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}


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
    test_passed: bool
    
    @property
    def coverage_score(self) -> float:
        """Calculate weighted coverage score for this rule."""
        confidence_weight = CONFIDENCE_WEIGHTS.get(self.confidence, 0.3)
        lifecycle_weight = LIFECYCLE_WEIGHTS.get(self.lifecycle, 0.2)
        test_weight = 1.0 if self.test_passed else 0.5
        
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
    """Parse a Sigma rule and extract coverage information."""
    try:
        with open(filepath) as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        return None
    
    if not isinstance(rule, dict):
        return None
    
    tags = rule.get("tags", [])
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
        elif value in TACTIC_ORDER:
            tactics.append(value)
    
    # Check test results
    test_passed = True
    if test_results:
        rule_name = filepath.stem
        rule_result = test_results.get("results", {}).get(rule_name, {})
        test_passed = rule_result.get("passed", True)
    
    return RuleCoverage(
        filepath=str(filepath),
        title=rule.get("title", "Unknown"),
        techniques=techniques,
        tactics=tactics,
        lifecycle=custom.get("lifecycle", "draft"),
        confidence=custom.get("confidence"),
        level=rule.get("level", "medium"),
        test_passed=test_passed
    )


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
        # Add more as needed
    }


def build_coverage_map(rules_dir: Path, test_results: dict = None) -> dict[str, TechniqueCoverage]:
    """Build a map of technique ID to coverage information."""
    technique_names = load_technique_names()
    coverage_map: dict[str, TechniqueCoverage] = {}
    
    # Parse all rules
    for filepath in rules_dir.rglob("*.yml"):
        rule_coverage = parse_rule(filepath, test_results)
        if not rule_coverage:
            continue
        
        # Add rule to each technique it covers
        for tech_id in rule_coverage.techniques:
            if tech_id not in coverage_map:
                coverage_map[tech_id] = TechniqueCoverage(
                    technique_id=tech_id,
                    technique_name=technique_names.get(tech_id, "Unknown"),
                    tactics=rule_coverage.tactics,
                    rules=[]
                )
            coverage_map[tech_id].rules.append(rule_coverage)
    
    return coverage_map


def generate_markdown_report(coverage_map: dict[str, TechniqueCoverage]) -> str:
    """Generate a Markdown coverage report."""
    lines = [
        "# MITRE ATT&CK Coverage Report",
        "",
        f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        "## Executive Summary",
        "",
    ]
    
    # Calculate summary statistics
    total_techniques = len(coverage_map)
    high_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "high")
    med_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "medium")
    low_conf = sum(1 for t in coverage_map.values() if t.confidence_level == "low")
    total_rules = sum(len(t.rules) for t in coverage_map.values())
    
    lines.extend([
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Techniques Covered | {total_techniques} |",
        f"| High Confidence | {high_conf} |",
        f"| Medium Confidence | {med_conf} |",
        f"| Low Confidence | {low_conf} |",
        f"| Total Rules | {total_rules} |",
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
        "Techniques below medium confidence or with failing tests:",
        "",
    ])
    
    gaps = [t for t in coverage_map.values() 
            if t.confidence_level in ["low", "none"] or 
            any(not r.test_passed for r in t.rules)]
    
    if gaps:
        lines.append("| Technique | Issue |")
        lines.append("|-----------|-------|")
        for tech in sorted(gaps, key=lambda t: t.technique_id):
            issues = []
            if tech.confidence_level == "low":
                issues.append("Low confidence")
            if any(not r.test_passed for r in tech.rules):
                issues.append("Test failures")
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
        "description": f"Detection coverage as of {datetime.utcnow().strftime('%Y-%m-%d')}",
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
    parser.add_argument("--include-heatmap", action="store_true", help="Include ASCII heatmap in markdown")
    args = parser.parse_args()
    
    # Load test results if provided
    test_results = None
    if args.test_results:
        try:
            with open(args.test_results) as f:
                test_results = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load test results: {e}")
    
    # Build coverage map
    rules_dir = Path(args.rules_dir)
    coverage_map = build_coverage_map(rules_dir, test_results)
    
    print(f"Analyzed {sum(len(t.rules) for t in coverage_map.values())} rules")
    print(f"Covering {len(coverage_map)} techniques")
    
    # Generate output
    if args.format == "markdown":
        content = generate_markdown_report(coverage_map)
        with open(args.output, "w") as f:
            f.write(content)
        print(f"Markdown report written to: {args.output}")
    
    elif args.format == "navigator":
        layer = generate_navigator_layer(coverage_map)
        with open(args.output, "w") as f:
            json.dump(layer, f, indent=2)
        print(f"Navigator layer written to: {args.output}")


if __name__ == "__main__":
    main()
