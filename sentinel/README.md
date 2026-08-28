# Sentinel deployment seam

Turns the pipeline's generated KQL into **runnable Microsoft Sentinel queries**. The
`sigma convert --target kusto` step emits bare predicates over raw Sysmon field names
(`Image`, `CommandLine`, `GrantedAccess`, …); those fields do not exist as columns in the
`Event` table the lab DCR feeds, so the predicates match nothing as-is. This directory
supplies the parser and the wrap step that close that gap — the Sentinel analogue of
`wazuh/`, which does the same job for the Wazuh manager.

Status: **Deployed and live-validated** (2026-08-28). The parser and both analytics rules run in
the lab workspace, and a detection has fired on real telemetry — see
[Live verification](#live-verification--passed-2026-08-28).

## Key Components

- `parsers/Sysmon.kql` — workspace function (alias `Sysmon`) that re-materialises the
  generic `Event` table's Sysmon rows into Sysmon-named columns via `extract()` over the
  `EventData` XML. Covers Sysmon EID 1 (process creation) and EID 10 (process access) fields.
- `rule_map.yml` — the Sigma↔Sentinel contract, keyed by `sigma_id` (shared UUID across
  repos). Every rule under `rules/` is listed with a `target` disposition; nothing is silently
  unaccounted for.
- `../scripts/convert_sentinel.py` — reads the contract and wraps each Sysmon predicate as
  `Sysmon | where <predicate>`, writing runnable queries to `output/sentinel/**`. Skips
  non-deployable rules with a **logged** reason. Runs in CI's convert stage (kusto leg).
- `../scripts/deploy_sentinel_rules.py` + `../scripts/sentinel_client.py` — push the parser
  function (first) and each wrapped query into the workspace as scheduled analytics rules via
  the ARM REST API, verifying each by readback. Mirrors `deploy_wazuh_rules.py` (`--dry-run`,
  `--verify-only`, exit codes 0/1/2). Auth is `az login` by default, or a service principal
  via `DAC_SENTINEL_*`. **Deployed to the lab workspace** — all three artifacts readback-verified.

## Why the parser exists — the `Event`-table trap

The Azure Monitor Agent delivers Sysmon over the `Microsoft-Event` stream (see
[`infra/modules/dcr.bicep`](../infra/modules/dcr.bicep)), which lands rows in the generic
**`Event`** table — not `SysmonEvent`, not `WindowsEvent`. Inside `Event`, Sysmon fields live
in the `EventData` XML string, not as first-class columns. KQL against the wrong table, or
against a column that isn't projected, returns **zero rows with no error** — a silent miss.
`Sysmon.kql` projects the XML back into columns so the generated detections run unchanged.

Native Security-log rules (4625 → `SecurityEvent`) have clean columns and need no parser —
but in this corpus those are the correlation rules, which produce no KQL at all
(`pysigma-backend-kusto` raises `NotImplementedError` on correlations).

## Rule dispositions (what actually deploys to this lab)

| `target` | Meaning | Rules |
|---|---|---|
| `parser` | Sysmon rule; wrapped `Sysmon \| where …` | `powershell_encoded_command`, `lsass_memory_access` |
| `unsupported` | Not collectible here; skipped with reason | `terminated_account_authentication` (enrichment field), `ssh_brute_force`, `ssh_password_spray` (Linux syslog) |
| `none` | No kusto output (correlation) | `bruteforce_failures_then_success`, `password_spray_single_source` |

**2 rules deploy to this lab today** (both Sysmon, parser-fronted). The rest are skipped for
concrete, documented reasons, not omission.

## Live verification — passed (2026-08-28)

`Sysmon.kql` is no longer schema-only. The parser, both analytics rules, and the end-to-end
detection path were confirmed against real rows in the lab workspace (`law-sc200-sentinel`).

| Check | Evidence |
|---|---|
| **Parser projects live rows** | `Sysmon \| summarize count() by EventID` returned EID 1 (197) and EID 10 (136) — both extracted out of the `EventData` XML into columns |
| **Deploy is real, not dry-run** | Parser function + 2 scheduled analytics rules created in the workspace, each confirmed by readback (PUT → GET → compare) and cross-checked in the Azure Activity log |
| **Detection fires on live telemetry** | A benign encoded-PowerShell process was executed on the event-source VM; the deployed rule's *exact* predicate returned the single matching Sysmon EID 1 row (`powershell.exe -nop -w hidden -enc …`). The invocation harness's own wrapper process was correctly excluded by `filter_azure` — a clean `1 of 1` |

The bar held: no Sentinel rule is promoted to "verified" on structural CI alone. The evidence
above is live-row evidence, the same standard `wazuh/rule_map.yml` holds for the Wazuh twins.

**Still open.** Incident generation and the ADTE triage hand-off are not yet captured, so the
honest status of the full loop is **"deployed and detection-validated"** — not yet
"incident-to-triage proven".

## Generate locally

```bash
# 1. Produce the raw kusto predicates (needs sigma-cli + backends)
find rules/ -name '*.yml' | while read r; do
  sigma convert --target kusto --pipeline sysmon "$r" \
    > "output/kusto/${r#rules/}"; done   # (CI does this per-rule with dir creation)

# 2. Wrap the Sysmon ones with the parser
python scripts/convert_sentinel.py        # -> output/sentinel/**
```

`output/` is regenerated and git-ignored; the committed artifacts are the parser, the
contract, and the tooling.

## Deploy

```bash
az login                                        # or set DAC_SENTINEL_CLIENT_ID/... for a SP
cp .env.example .env                            # fill DAC_SENTINEL_SUBSCRIPTION_ID / _RESOURCE_GROUP / _WORKSPACE_NAME
python scripts/deploy_sentinel_rules.py --dry-run     # list artifacts, send nothing
python scripts/deploy_sentinel_rules.py               # deploy parser, then rules; verify each by readback
python scripts/deploy_sentinel_rules.py --verify-only # compare workspace to local
```

The parser deploys first (a rule invoking `Sysmon` before the function exists would fail
validation). Rules deploy **enabled** — they begin evaluating on schedule immediately, so
confirm the data path against live rows before pointing this at a new workspace. The deploy
identity needs Microsoft Sentinel Contributor on the workspace (write), not the Log Analytics
Reader SP that ADTE reads with.

`output/` is git-ignored, so a fresh clone has no generated queries — run the two Generate
steps above before deploying. `--dry-run` needs them too: artifacts load before the dry-run
branch is taken.
