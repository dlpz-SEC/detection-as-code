# MITRE ATT&CK Coverage Report

*Generated: 2026-10-01 10:01 UTC*

*Tier-1 behavioral test results: included.*

## Executive Summary

| Metric | Value |
|--------|-------|
| Techniques Covered | 10 |
| High Confidence | 2 |
| Medium Confidence | 7 |
| Low Confidence | 1 |
| Rule files | 7 |

## Coverage by Tactic

### Initial Access

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1078 | Valid Accounts | 1 | 🟡 medium | 0.70 |
| T1078.002 | Domain Accounts | 1 | 🟡 medium | 0.70 |

### Execution

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1059 | Command and Scripting Interpreter | 1 | 🟡 medium | 0.60 |
| T1059.001 | PowerShell | 1 | 🟡 medium | 0.60 |

### Persistence

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1078 | Valid Accounts | 1 | 🟡 medium | 0.70 |
| T1078.002 | Domain Accounts | 1 | 🟡 medium | 0.70 |

### Stealth

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1027 | Obfuscated Files or Information | 1 | 🟡 medium | 0.60 |

### Credential Access

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1003 | OS Credential Dumping | 1 | 🟢 high | 1.00 |
| T1003.001 | LSASS Memory | 1 | 🟢 high | 1.00 |
| T1110 | Brute Force | 4 | 🟡 medium | 0.69 |
| T1110.001 | Password Guessing | 2 | 🟡 medium | 0.64 |
| T1110.003 | Password Spraying | 2 | 🟠 low | 0.28 |

## Coverage Gaps

Techniques below medium confidence, with failing tests, or not behaviorally tested:

| Technique | Issue |
|-----------|-------|
| T1110 | Not behaviorally tested (aggregation query; no true-positive sample) |
| T1110.001 | Not behaviorally tested (aggregation query; no true-positive sample) |
| T1110.003 | Low confidence, Not behaviorally tested (aggregation query; no true-positive sample) |
