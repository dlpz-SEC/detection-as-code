# Sentinel deployment seam

Turns the pipeline's generated KQL into **runnable Microsoft Sentinel queries**. The
`sigma convert --target kusto` step emits bare predicates over raw Sysmon field names
(`Image`, `CommandLine`, `GrantedAccess`, …); those fields do not exist as columns in the
`Event` table the lab DCR feeds, so the predicates match nothing as-is. This directory
supplies the parser and the wrap step that close that gap — the Sentinel analogue of
`wazuh/`, which does the same job for the Wazuh manager.

Status: In Development. The parser is **schema-built and live-unverified** — see the gate below.

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
  via `DAC_SENTINEL_*`. **Runs at Phase 4** — built and unit-tested, live-unverified.

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

## ⚠️ Live-verification gate (Phase 3 before Phase 4)

`Sysmon.kql` is built to the documented Log Analytics `Event` schema but has **not** been run
against real rows — no VM is ingesting yet. Two assumptions must be confirmed at Phase 3
("prove the data path") before any analytics rule is switched on at Phase 4:

1. **EventData shape** — that Sysmon fields arrive as `<Data Name="…">value</Data>` and the
   attribute-quote style matches (`Sysmon.kql` tolerates both `'` and `"`). Confirm with:
   ```kql
   Event | where Source == "Microsoft-Windows-Sysmon" | take 5
   ```
2. **Field coverage** — that every field a parser-fronted rule references is projected. The
   unit test `tests/test_convert_sentinel.py::test_parser_covers_referenced_fields` enforces
   this statically; live rows confirm the extraction actually populates them.

Do not promote a Sentinel analytics rule to "verified" on structural CI alone — this repo's
bar is live evidence (the same standard `wazuh/rule_map.yml` holds for the Wazuh twins).

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

## Deploy (Phase 4)

```bash
az login                                        # or set DAC_SENTINEL_CLIENT_ID/... for a SP
cp .env.example .env                            # fill DAC_SENTINEL_SUBSCRIPTION_ID / _RESOURCE_GROUP / _WORKSPACE_NAME
python scripts/deploy_sentinel_rules.py --dry-run     # list artifacts, send nothing
python scripts/deploy_sentinel_rules.py               # deploy parser, then rules; verify each by readback
python scripts/deploy_sentinel_rules.py --verify-only # compare workspace to local
```

The parser deploys first (a rule invoking `Sysmon` before the function exists would fail
validation). Rules deploy **enabled** — they begin evaluating on schedule immediately, so
run this only once Phase 3 has confirmed the data path. The deploy identity needs Microsoft
Sentinel Contributor on the workspace (write), not the Log Analytics Reader SP ADTE reads with.
