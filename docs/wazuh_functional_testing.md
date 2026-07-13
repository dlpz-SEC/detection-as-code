# Functional Detection Testing (Tier 2)

Verifies detections against Wazuh's **real** analysis engine — the same
decoders and ruleset that run in production — instead of an offline model.

## Two tiers

| | Tier 1 — Behavioral Tests | Tier 2 — Functional Tests |
|---|---|---|
| Script | `scripts/test_detections.py` | `scripts/test_detections_wazuh.py` |
| Evaluates | Converted Splunk SPL, offline parser/AST | Live Wazuh engine via Manager API `logtest` |
| Rules under test | Sigma → SPL | Native Wazuh XML twins (`wazuh/rules/dac_windows.xml`) |
| Needs infra | No — runs anywhere | Yes — a reachable Wazuh manager (the lab VM) |
| CI | Every push/PR (hermetic gate) | `workflow_dispatch` only, self-hosted runner |
| Verdict | Simulated match | Which `rule.id` actually fired |

Tier 1 stays the always-on gate. Tier 2 is the truth check: it proves the
detection logic behaves in Wazuh, and it exercises the native rules ADTE
ultimately consumes.

## How it works

The runner sends each sample's raw event through `PUT /logtest` on the
Manager API (port 55000). Wazuh runs the event through its decoders and
rules and reports the winning rule. Assertions are **scoped to our custom
rule IDs** (from `wazuh/rule_map.yml`):

- **True positive** passes when it lands on one of its `expected_rule_ids`.
- **Benign** passes as long as no *alerting* rule of ours fires. Built-in
  Wazuh rules firing is normal; landing on a level-0 suppression child
  (e.g. `100111`, the SCCM filter) is the filter working — also a pass.
- We never assert "nothing fired".

Exit codes: `0` all pass · `1` a detection failed or false-positived ·
`2` infrastructure failure (VM unreachable / auth). The runner never
restarts the manager — only `deploy_wazuh_rules.py` does.

## The contract: `wazuh/rule_map.yml`

Binds each Sigma rule (by UUID) to its native Wazuh rule IDs and MITRE
techniques. `tests/test_rule_map.py` fails CI if the map, the XML, and the
Sigma rules drift apart, and `export_manifest.py` reads it to publish
`wazuh_rule_ids` in the manifest for the ADTE join.

## Setup

1. Copy `.env.example` to `.env` (git-ignored) and fill in the Manager API
   host/user/password. The API user was set at install time (often
   `wazuh-wui`); credentials are in `wazuh-passwords.txt` /
   `wazuh-install-files.tar` on the VM. Note this is the **Manager API**
   (55000), not the Indexer (9200) that ADTE queries.
2. Confirm reachability: `Test-NetConnection <vm-ip> -Port 55000`.

## Sample payload format

Each sample in `tests/samples/**/*.json` opts into Tier 2 with a `wazuh`
block alongside the flat Tier-1 `events`:

```json
{
  "name": "Mimikatz LSASS Access",
  "type": "true_positive",
  "events": [ { "EventID": 10, "TargetImage": "...lsass.exe", "GrantedAccess": "0x1010" } ],
  "wazuh": {
    "log_format": "json",
    "location": "EventChannel",
    "expected_rule_ids": ["100100"],
    "events": ["<raw eventchannel JSON string>"]
  }
}
```

Windows Sysmon events reach Wazuh as eventchannel JSON:
`{"win": {"system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "10", ...}, "eventdata": {"targetImage": "...", "grantedAccess": "0x1010", ...}}}`
and the XML rules match `win.eventdata.<camelCaseField>`.

> **Phase 0 note.** The exact `log_format`/`location` and the built-in
> Sysmon parent rule IDs (`if_sid` in `dac_windows.xml`, expected `61612`
> for Event 10 and `61603` for Event 1) are confirmed against the live
> manager with a one-off logtest spike before the sample payloads are
> finalized:
> ```
> python scripts/wazuh_client.py --check-auth
> python scripts/wazuh_client.py --logtest-event '<candidate payload>' --log-format json
> ```
> Adjust the payloads and `if_sid` values here if the spike reports
> different values for the installed Wazuh version.

## Runbook

```powershell
# 1. Deploy the native rules to the manager (uploads + verifies + restarts once)
python scripts\deploy_wazuh_rules.py --rule-map wazuh\rule_map.yml

# 2. Run the functional suite
python scripts\test_detections_wazuh.py --samples-dir tests\samples --rule-map wazuh\rule_map.yml --output wazuh_results.json --fail-on-fp
$LASTEXITCODE   # 0 pass / 1 detection failure / 2 infra
```

## CI

The `Functional Tests (Wazuh)` job is `workflow_dispatch`-only and targets a
`[self-hosted, wazuh-lab]` runner, with `DAC_WAZUH_API_*` supplied as repo
secrets. It never runs on push/PR, so it can't block merges and stays inert
until such a runner is registered on the lab network.

## Out of scope

`logtest` runs the identical decoder+rule pipeline on the post-transport
payload, so it fully verifies **rule logic**. It does **not** test the agent
side — `ossec.conf` eventchannel subscriptions or Sysmon config coverage on
the endpoint. Those are validated separately with a live agent.
