# infra/ — the lab as code

The Microsoft Sentinel lab this pipeline deploys detections into is **burst
infrastructure**: it exists for a trial window, gets used hard, gets captured,
and gets deleted. Nothing about it is meant to sit idle accruing cost.

That only works if rebuilding is cheap and identical, which is what these
templates are for. **This directory is the lab.** A workspace clicked together in
the portal is working capital — useful today, gone at teardown, and not the
deliverable.

## What it deploys

| File | Deploys |
|---|---|
| `main.bicep` | Subscription-scope entry point: the resource group, then the modules below |
| `modules/workspace.bicep` | Log Analytics workspace with a daily ingestion cap, plus Microsoft Sentinel onboarded onto it |
| `modules/dcr.bicep` | Data Collection Rule skeleton — XPath-filtered Windows security + Sysmon events |
| `main.bicepparam` | Lab defaults (names, region, cap) |

## Cost model

Two controls, and they are not interchangeable:

- **Subscription budget alert** — notifies *after* money is spent. Useful, not protective.
- **`workspaceCapping.dailyQuotaGb` (set to 1 GB/day here)** — stops ingestion once the
  day's quota is hit. This is the actual guardrail, and since 18 September 2023 it applies
  to security tables too, so a misconfigured connector can't quietly run up a bill. Two
  honest caveats: the cap **overshoots** (data ingested past the limit is still billed),
  and it governs **billable** tables only — free tables such as `AzureActivity`,
  `SecurityAlert` and `SecurityIncident` keep flowing regardless.

  During the 31-day Sentinel trial the first 10 GB/day is already free, so a 1 GB cap
  saves nothing in that window — it only makes the lab go collection-blind at a tenth of
  the free allowance. Its real job is the days after the trial.

Retention stays at 90 days — free for as long as Sentinel is onboarded on this workspace
(plain Log Analytics includes 31). Anything beyond 90 bills per GB per month and keeps
billing for as long as the workspace exists. Setting it lower than 90 discards retention
that costs nothing.

The DCR's XPath queries are narrow on purpose — the specific event IDs the rule corpus
actually keys on, verified against `rules/` rather than assumed: Security 4625 (two rules)
and 4624 (investigation context), plus Sysmon EID 1 and 10. A single Windows VM running
attack simulations will exhaust a 1 GB/day cap if you collect everything — collecting the
whole Sysmon Operational channel alone can do it. Widening the XPath list is a spending
decision.

Note the destination tables differ by stream: `Microsoft-SecurityEvent` lands in
`SecurityEvent`, while `Microsoft-Event` puts Sysmon rows in the generic `Event` table —
not `SysmonEvent`, not `WindowsEvent`. KQL written against the wrong table returns zero
rows with no error.

## Deploying

> **Deploying a workspace with Sentinel starts a 31-day trial clock on that workspace.**
> Deploy when you intend to use the window, not to smoke-test the template. Use
> `--what-if` for that.

```bash
# Preview without creating anything
az deployment sub what-if \
  --location westus \
  --parameters infra/main.bicepparam

# Deploy
az deployment sub create \
  --name sentinel-lab \
  --location westus \
  --parameters infra/main.bicepparam
```

The deployment outputs `workspaceId` — the workspace GUID that ADTE reads as
`ADTE_SENTINEL_WORKSPACE_ID`.

## Tearing down

```bash
az group delete --name sc200-lab-rg --yes --no-wait
```

Capture evidence **before** teardown, never after. A deleted workspace takes its
incidents, its analytics rules, and its query history with it.

**Rebuild is not automatically a clean slate.** Log Analytics soft-deletes a workspace for
14 days, and `main.bicepparam` pins the same subscription, resource group, workspace name
and region — exactly the tuple Azure uses to resurrect one. A redeploy inside that window
recovers the old workspace, bringing its data and existing Sentinel trial state back with
it, while installed solutions and linked services stay gone. For a genuinely fresh lab,
wait out the 14 days, change `workspaceName`, or delete with
`az monitor log-analytics workspace delete --force`.

## Validating a change

```bash
az bicep build --file infra/main.bicep
az bicep build-params --file infra/main.bicepparam
```

Compiles to ARM JSON without deploying — no resources created, no trial clock started.
Azure Cloud Shell has the Bicep CLI preinstalled if it isn't installed locally.

Gotcha: both commands default their output to `main.json`, so run back to back the second
silently overwrites the first. Pass `--outfile` if you want to inspect either result.

## What is deliberately not here

- **Analytics rules.** Detections are authored as Sigma in `rules/`, validated by CI, and
  deployed to Sentinel from the pipeline — not hand-written into an infrastructure
  template. Infrastructure creates the workspace; the pipeline fills it.
- **VM and agent resources.** The Windows host used for live-fire testing is created for
  a specific simulation run and deallocated between them; it doesn't belong in the
  always-redeployed base.
- **Secrets of any kind.** The service principal ADTE authenticates with is created out of
  band and its credentials live in a local `.env` file. Nothing here reads or writes one.
