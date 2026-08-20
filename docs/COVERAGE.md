# MITRE ATT&CK Coverage Report

*Generated: 2026-08-20 18:14 UTC*

## Executive Summary

| Metric | Value |
|--------|-------|
| Techniques Covered | 10 |
| High Confidence | 4 |
| Medium Confidence | 5 |
| Low Confidence | 1 |
| Total Rules | 15 |

## Coverage by Tactic

### Initial Access

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1078 | Unknown | 1 | 🟡 medium | 0.70 |
| T1078.002 | Unknown | 1 | 🟡 medium | 0.70 |

### Execution

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1027 | Obfuscated Files or Information | 1 | 🟡 medium | 0.60 |
| T1059 | Command and Scripting Interpreter | 1 | 🟡 medium | 0.60 |
| T1059.001 | PowerShell | 1 | 🟡 medium | 0.60 |

### Persistence

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1078 | Unknown | 1 | 🟡 medium | 0.70 |
| T1078.002 | Unknown | 1 | 🟡 medium | 0.70 |

### Defense Evasion

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1027 | Obfuscated Files or Information | 1 | 🟡 medium | 0.60 |
| T1059 | Command and Scripting Interpreter | 1 | 🟡 medium | 0.60 |
| T1059.001 | PowerShell | 1 | 🟡 medium | 0.60 |

### Credential Access

| Technique | Name | Rules | Confidence | Score |
|-----------|------|-------|------------|-------|
| T1003 | OS Credential Dumping | 1 | 🟢 high | 1.00 |
| T1003.001 | LSASS Memory | 1 | 🟢 high | 1.00 |
| T1110 | Unknown | 4 | 🟢 high | 1.00 |
| T1110.001 | Unknown | 2 | 🟢 high | 1.00 |
| T1110.003 | Unknown | 2 | 🟠 low | 0.45 |

## Coverage Gaps

Techniques below medium confidence, with failing tests, or not behaviorally tested:

| Technique | Issue |
|-----------|-------|
| T1110 | Not behaviorally tested (aggregation query) |
| T1110.001 | Not behaviorally tested (aggregation query) |
| T1110.003 | Low confidence, Not behaviorally tested (aggregation query) |
