# Functional Detection Testing (Tier 2)

Verifies detections against Wazuh's **real** analysis engine — the same decoders
and ruleset that fire in production — instead of an offline model of it.

Verified against **Wazuh 4.14.2**.

## Two tiers

| | Tier 1 — Behavioral Tests | Tier 2 — Functional Tests |
|---|---|---|
| Script | `scripts/test_detections.py` | `scripts/test_detections_wazuh.py` |
| Evaluates | Converted Splunk SPL, offline parser/AST | Live Wazuh engine via Manager API `logtest` |
| Rules under test | Sigma → SPL | Native Wazuh XML twins (`wazuh/rules/*.xml`) |
| Needs infra | No — runs anywhere | Yes — a reachable Wazuh manager |
| CI | Every push/PR (hermetic gate) | `workflow_dispatch` only, self-hosted runner |
| Verdict | Simulated match | Which `rule.id` the engine actually fired |

Each tier skips what it cannot test: Tier 1 skips samples with no offline
`events`; Tier 2 skips samples with no `wazuh` block.

## What Tier 2 can and cannot verify (important)

**✅ Works: syslog / JSON-decoded sources** (Linux, network, application logs).
Proven end to end — the SSH brute-force detection below is verified against the
live engine on every run.

**❌ Does not work: Windows Sysmon / eventchannel.** This is a hard limitation
of `logtest`, established empirically (7 `log_format` × `location` combinations
all decode as `json`):

```xml
<!-- 0575-win-base_rules.xml — the root of the entire Windows rule tree -->
<rule id="60000" level="0">
    <decoded_as>windows_eventchannel</decoded_as>   <!-- the gate -->
    <field name="win.system.providerName">\.+</field>
</rule>
```

`windows_eventchannel` is **internal to analysisd** (it appears in no decoder
file — 203 decoders on a stock manager, none named `win*`). It is applied based
on how the *agent* delivers the event, which `logtest` cannot emulate: injected
events are claimed by the generic `json` decoder, so rule 60000 never matches
and the whole Sysmon chain (`60000 → 60004 → 61600 → 61612`) stays silent.

Consequence: `wazuh/rules/dac_windows.xml` is **deployed and production-correct**
(its `if_sid` parents were verified against the live ruleset — `61612` = Sysmon
Event 10, `61603` = Event 1), but it cannot be functionally verified by logtest.
Verifying it requires a Windows endpoint running Sysmon + wazuh-agent and
testing through real ingestion → alert queries, not logtest.

## How it works

The runner sends each sample's raw event through `PUT /logtest` (Manager API,
port 55000). Wazuh runs it through the real decoders and rules and reports the
winning rule. Assertions are **scoped to our custom rule IDs** (from
`wazuh/rule_map.yml`):

- **True positive** passes when it lands on one of its `expected_rule_ids`.
- **Benign** passes as long as no *alerting* rule of ours fires. Built-in rules
  firing is normal and expected (a successful login legitimately fires `5715`);
  landing on a level-0 suppression child is the filter working — also a pass.
- We never assert "nothing fired".

**logtest sessions carry correlation state**, which is what makes frequency-based
detections testable: sending N failures in one session escalates exactly as
production would.

Exit codes: `0` all pass · `1` detection failure / false positive · `2`
infrastructure failure (VM unreachable, auth). The runner never restarts the
manager — only `deploy_wazuh_rules.py` does.

## The contract: `wazuh/rule_map.yml`

Binds each Sigma rule (by UUID) to its native Wazuh rule IDs and MITRE
techniques. `tests/test_rule_map.py` fails CI if the map, the XML, and the Sigma
rules drift apart, and `export_manifest.py` reads it to publish `wazuh_rule_ids`
in the manifest for the ADTE join.

## Worked example: SSH brute force (T1110.001)

The Sigma rule (`rules/linux/credential_access/ssh_brute_force.yml`) expresses
the **atomic event** so it stays portable across SIEMs. The Wazuh twin adds the
**correlation threshold**, which is where Wazuh's engine does the work:

```xml
<rule id="100200" level="12" frequency="6" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>   <!-- sshd: non-existent user -->
  <same_source_ip />
  <mitre><id>T1110</id><id>T1110.001</id></mitre>
</rule>
```

Deliberately tighter than Wazuh's built-in `5712` (which fires at 8), so a slow
guesser is caught earlier. Live verification:

```
attempt 1-5: rule=5710    level=5   sshd: Attempt to login using a non-existent user
attempt 6:   rule=100200  level=12  DAC: SSH brute force - 6+ invalid-user failures
benign:      rule=5715    level=3   sshd: authentication success   (100200 silent)
```

Relevant built-in chain (`0095-sshd_rules.xml`, confirmed on the live manager):
`5700` sshd base → `5710` invalid user (level 5, T1110.001) → `5712` built-in
brute force (frequency 8/120s) · `5715` auth success (level 3).

## Setup

1. Copy `.env.example` to `.env` (git-ignored) and fill in the Manager API
   host/user/password.
2. Confirm reachability: `Test-NetConnection <vm-ip> -Port 55000`.

> **The Manager API (55000) has a different user store than the Indexer /
> dashboard (9200).** The web UI's `admin` account will *not* authenticate
> against the API — it wants `wazuh` / `wazuh-wui`. Install-time passwords live
> in `wazuh-install-files.tar` → `wazuh-passwords.txt`.

## Sample payload format

A sample opts into Tier 2 with a `wazuh` block:

```json
{
  "name": "SSH Brute Force - Invalid User Guessing",
  "type": "true_positive",
  "technique_id": "T1110.001",
  "wazuh": {
    "log_format": "syslog",
    "location": "/var/log/auth.log",
    "expected_rule_ids": ["100200"],
    "events": ["Jul 16 07:20:01 web-server sshd[3001]: Failed password for invalid user oracle from 203.0.113.77 port 60001 ssh2", "..."]
  }
}
```

Benign samples carry `expected_rule_ids: []`. A sample with no `wazuh` block is
skipped by Tier 2; a sample with no offline `events` is skipped by Tier 1.

## Runbook

```powershell
# 1. Deploy the native rules (upload + readback verify + one restart)
python scripts\deploy_wazuh_rules.py --rule-map wazuh\rule_map.yml

# 2. Run the functional suite
python scripts\test_detections_wazuh.py --samples-dir tests\samples --rule-map wazuh\rule_map.yml --output wazuh_results.json --fail-on-fp
$LASTEXITCODE   # 0 pass / 1 detection failure / 2 infra
```

## CI

The `Functional Tests (Wazuh)` job is `workflow_dispatch`-only and targets a
`[self-hosted, wazuh-lab]` runner, with `DAC_WAZUH_API_*` as repo secrets. It
never runs on push/PR, so it cannot block merges and no fork can reach the
runner or its secrets. Tier 1 remains the always-on gate.

## Out of scope

`logtest` runs the identical decoder+rule pipeline on the post-transport
payload, so it fully verifies **rule logic** for the sources it supports. It
does **not** test the agent side — `ossec.conf` subscriptions, Sysmon config
coverage, or log shipping. Those need a live agent.
