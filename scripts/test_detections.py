#!/usr/bin/env python3
"""
Detection Behavioral Testing Framework

Tests converted SIEM queries against curated log samples to validate:
1. True Positive Detection: Rules trigger on malicious samples
2. False Positive Resistance: Rules don't trigger on benign samples

IMPORTANT LIMITATION:
This is a MOCK evaluator that parses Splunk SPL queries and evaluates
them against JSON log samples using Python pattern matching. It does NOT:
- Connect to actual Splunk
- Handle all SPL functions
- Provide production-grade query evaluation

For production use, you would:
- Use Splunk's SDK for local query evaluation
- Connect to a Splunk dev instance via REST API
- Use tools like Atomic Red Team for live testing

This implementation demonstrates the TESTING METHODOLOGY, which is
the differentiator for a portfolio project.
"""

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class TestSample:
    """A log sample for testing detections."""
    name: str
    filepath: str
    event_type: str  # "true_positive" or "benign"
    technique_id: Optional[str]  # For TP samples, which technique this demonstrates
    events: list[dict]
    
    @classmethod
    def load(cls, filepath: Path) -> "TestSample":
        """Load a test sample from a JSON file."""
        with open(filepath) as f:
            data = json.load(f)
        
        return cls(
            name=data.get("name", filepath.stem),
            filepath=str(filepath),
            event_type=data.get("type", "unknown"),
            technique_id=data.get("technique_id"),
            events=data.get("events", [])
        )


@dataclass
class QueryEvaluator:
    """
    Mock SPL query evaluator.
    
    Handles a subset of SPL syntax for demonstration purposes.
    """
    
    def parse_splunk_query(self, query: str) -> dict:
        """
        Parse a Splunk SPL query into evaluation criteria.
        
        Handles patterns like:
        - field=value
        - field="value with spaces"
        - field IN ("val1", "val2")
        - field="*wildcard*"
        - NOT field=value
        """
        criteria = {
            "includes": [],  # (field, value, is_wildcard)
            "excludes": [],  # (field, value, is_wildcard)
            "in_lists": [],  # (field, [values])
        }
        
        # Remove common SPL prefixes (these would be data source selections)
        query = re.sub(r'^(index=\S+\s*|\`[^`]+\`\s*)', '', query)
        
        # Parse NOT conditions
        not_pattern = r'NOT\s+(\w+)\s*=\s*"?([^"\s]+)"?'
        for match in re.finditer(not_pattern, query, re.IGNORECASE):
            field, value = match.groups()
            is_wildcard = "*" in value
            criteria["excludes"].append((field, value, is_wildcard))
        
        # Parse IN conditions
        in_pattern = r'(\w+)\s+IN\s*\(([^)]+)\)'
        for match in re.finditer(in_pattern, query, re.IGNORECASE):
            field = match.group(1)
            values_str = match.group(2)
            values = [v.strip().strip('"\'') for v in values_str.split(',')]
            criteria["in_lists"].append((field, values))
        
        # Parse simple field=value conditions (excluding NOT and IN matches)
        cleaned_query = re.sub(not_pattern, '', query, flags=re.IGNORECASE)
        cleaned_query = re.sub(in_pattern, '', cleaned_query, flags=re.IGNORECASE)
        
        eq_pattern = r'(\w+)\s*=\s*"([^"]+)"|(\w+)\s*=\s*(\S+)'
        for match in re.finditer(eq_pattern, cleaned_query):
            if match.group(1):
                field, value = match.group(1), match.group(2)
            else:
                field, value = match.group(3), match.group(4)
            
            is_wildcard = "*" in value
            criteria["includes"].append((field, value, is_wildcard))
        
        return criteria
    
    def wildcard_match(self, pattern: str, value: str) -> bool:
        """Match a wildcard pattern against a value."""
        if not isinstance(value, str):
            value = str(value)
        
        # Convert SPL wildcard to regex
        regex_pattern = re.escape(pattern).replace(r'\*', '.*')
        return bool(re.match(f'^{regex_pattern}$', value, re.IGNORECASE))
    
    def event_matches(self, event: dict, criteria: dict) -> bool:
        """Check if an event matches the query criteria."""
        
        # Check exclusions first (if any exclusion matches, event doesn't match)
        for field, value, is_wildcard in criteria["excludes"]:
            if field in event:
                event_value = event[field]
                if is_wildcard:
                    if self.wildcard_match(value, event_value):
                        return False
                elif str(event_value).lower() == value.lower():
                    return False
        
        # Check IN lists
        for field, values in criteria["in_lists"]:
            if field not in event:
                return False
            event_value = str(event[field]).lower()
            if not any(v.lower() == event_value for v in values):
                return False
        
        # Check includes (all must match)
        for field, value, is_wildcard in criteria["includes"]:
            if field not in event:
                return False
            event_value = event[field]
            if is_wildcard:
                if not self.wildcard_match(value, event_value):
                    return False
            elif str(event_value).lower() != value.lower():
                return False
        
        return True
    
    def evaluate(self, query: str, events: list[dict]) -> list[dict]:
        """Evaluate a query against a list of events, returning matches."""
        criteria = self.parse_splunk_query(query)
        
        # If no criteria parsed, this is likely a query we can't handle
        if not any([criteria["includes"], criteria["excludes"], criteria["in_lists"]]):
            # Return empty to indicate we couldn't evaluate
            # In a real implementation, this would be an error
            return []
        
        return [e for e in events if self.event_matches(e, criteria)]


@dataclass
class TestResult:
    """Result of testing a single rule."""
    rule_name: str
    query_file: str
    passed: bool
    true_positives_detected: int
    true_positives_total: int
    false_positives: int
    benign_samples_tested: int
    errors: list[str] = field(default_factory=list)
    
    @property
    def sensitivity(self) -> float:
        """Percentage of true positives detected."""
        if self.true_positives_total == 0:
            return 1.0
        return self.true_positives_detected / self.true_positives_total
    
    @property
    def specificity(self) -> float:
        """Percentage of benign samples correctly not flagged."""
        if self.benign_samples_tested == 0:
            return 1.0
        return (self.benign_samples_tested - self.false_positives) / self.benign_samples_tested


def load_test_samples(samples_dir: Path) -> tuple[list[TestSample], list[TestSample]]:
    """Load all test samples, separated by type."""
    true_positives = []
    benign = []
    
    tp_dir = samples_dir / "true_positives"
    benign_dir = samples_dir / "benign"
    
    if tp_dir.exists():
        for filepath in tp_dir.glob("*.json"):
            try:
                sample = TestSample.load(filepath)
                sample.event_type = "true_positive"
                true_positives.append(sample)
            except Exception as e:
                print(f"Warning: Could not load {filepath}: {e}")
    
    if benign_dir.exists():
        for filepath in benign_dir.glob("*.json"):
            try:
                sample = TestSample.load(filepath)
                sample.event_type = "benign"
                benign.append(sample)
            except Exception as e:
                print(f"Warning: Could not load {filepath}: {e}")
    
    return true_positives, benign


def test_rule(
    query_file: Path,
    true_positive_samples: list[TestSample],
    benign_samples: list[TestSample],
    evaluator: QueryEvaluator
) -> TestResult:
    """Test a single converted rule against samples."""
    
    rule_name = query_file.stem
    errors = []
    
    # Load the converted query
    try:
        with open(query_file) as f:
            query = f.read().strip()
    except Exception as e:
        return TestResult(
            rule_name=rule_name,
            query_file=str(query_file),
            passed=False,
            true_positives_detected=0,
            true_positives_total=0,
            false_positives=0,
            benign_samples_tested=0,
            errors=[f"Could not load query: {e}"]
        )
    
    # Test against true positives
    tp_detected = 0
    tp_total = 0
    
    for sample in true_positive_samples:
        tp_total += 1
        matches = evaluator.evaluate(query, sample.events)
        if matches:
            tp_detected += 1
        else:
            errors.append(f"Failed to detect true positive: {sample.name}")
    
    # Test against benign samples
    fp_count = 0
    benign_tested = 0
    
    for sample in benign_samples:
        benign_tested += 1
        matches = evaluator.evaluate(query, sample.events)
        if matches:
            fp_count += 1
            errors.append(f"False positive on benign sample: {sample.name}")
    
    # Determine pass/fail
    # Rules pass if they:
    # - Detect at least 80% of true positives (if any exist)
    # - Have zero false positives
    sensitivity_threshold = 0.8
    passed = True
    
    if tp_total > 0 and (tp_detected / tp_total) < sensitivity_threshold:
        passed = False
    
    if fp_count > 0:
        passed = False
    
    return TestResult(
        rule_name=rule_name,
        query_file=str(query_file),
        passed=passed,
        true_positives_detected=tp_detected,
        true_positives_total=tp_total,
        false_positives=fp_count,
        benign_samples_tested=benign_tested,
        errors=errors
    )


def main():
    parser = argparse.ArgumentParser(description="Test detections against log samples")
    parser.add_argument("--queries-dir", required=True, help="Directory with converted queries")
    parser.add_argument("--samples-dir", required=True, help="Directory with test samples")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--fail-on-fp", action="store_true", help="Exit with error on false positives")
    args = parser.parse_args()
    
    queries_dir = Path(args.queries_dir)
    samples_dir = Path(args.samples_dir)
    
    # Load test samples
    true_positives, benign = load_test_samples(samples_dir)
    print(f"Loaded {len(true_positives)} true positive samples")
    print(f"Loaded {len(benign)} benign samples")
    
    # Initialize evaluator
    evaluator = QueryEvaluator()
    
    # Test all queries
    results: dict[str, dict] = {}
    total_passed = 0
    total_failed = 0
    total_fp = 0
    
    for query_file in queries_dir.rglob("*.txt"):
        print(f"Testing: {query_file.stem}")
        
        result = test_rule(query_file, true_positives, benign, evaluator)
        results[result.rule_name] = {
            "passed": result.passed,
            "sensitivity": result.sensitivity,
            "specificity": result.specificity,
            "true_positives": f"{result.true_positives_detected}/{result.true_positives_total}",
            "false_positives": result.false_positives,
            "errors": result.errors
        }
        
        if result.passed:
            total_passed += 1
            print(f"  ✅ PASSED (TP: {result.true_positives_detected}/{result.true_positives_total}, FP: {result.false_positives})")
        else:
            total_failed += 1
            print(f"  ❌ FAILED (TP: {result.true_positives_detected}/{result.true_positives_total}, FP: {result.false_positives})")
            for error in result.errors[:3]:  # Show first 3 errors
                print(f"     - {error}")
        
        total_fp += result.false_positives
    
    # Write results
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_rules": total_passed + total_failed,
            "passed": total_passed,
            "failed": total_failed,
            "total_false_positives": total_fp
        },
        "results": results
    }
    
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n{'='*50}")
    print(f"Test Summary")
    print(f"{'='*50}")
    print(f"Total: {total_passed + total_failed}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print(f"False Positives: {total_fp}")
    print(f"\nResults written to: {args.output}")
    
    # Exit with error if requested and FPs found
    if args.fail_on_fp and total_fp > 0:
        print("\nFailing due to false positives (--fail-on-fp)")
        exit(1)
    
    if total_failed > 0:
        exit(1)


if __name__ == "__main__":
    main()
