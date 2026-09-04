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
| `modules/vm.bicep` | **Phase 2 (opt-in):** Windows VM + AMA + Sysmon + DCR association — the event source that feeds the DCR |
| `modules/sysmonconfig.xml` | Minimal Sysmon config (EID 1 + 10 only) embedded into the VM's install extension |
| `modules/promote-dc.ps1` | **Phase 2b (opt-in):** promotes that VM to an AD DS domain controller — embedded base64 into a third extension, same pattern as the Sysmon config |
| `scripts/seed-ad.ps1` | Run after promotion: OUs, users, groups, an SPN service account, and the audit policy that makes the DC emit Kerberos events |
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
rows with no error. Sysmon fields land inside the `Event` table's `EventData` XML rather
than as columns, so generated detections need the `Sysmon` parser function to run — see
[`sentinel/`](../sentinel/README.md).

## Phase 2 — the event source (VM)

`deployVm` (default **false**) is off so the identity/infra phase costs nothing. Flip it on
to stand up the Windows VM that actually feeds the DCR — this is where **compute cost
starts**. The `vm.bicep` module wires all three things a stock VM lacks:

1. **Azure Monitor Agent** — the shipper.
2. **DCR association** — binds the VM to `dcr-windows-security-events` so AMA knows what to
   collect. Without it the agent is idle. (So `deployVm` requires `deployDataCollectionRule = true`.)
3. **Sysmon + config** — installed by a Custom Script Extension that embeds
   `sysmonconfig.xml` (base64, no external script host) and pulls the Sysmon binary from the
   official Sysinternals URL. The config logs **only** EID 1 (process create) and EID 10
   (lsass access) to stay under the 1 GB/day cap.

Cost + exposure controls baked in: burstable `Standard_B2s`, a nightly **auto-shutdown**
schedule, and an NSG RDP rule that is **fail-closed** — with no `allowedRdpSourceIp` it locks
3389 to an unroutable address (nobody), never `*`. Set `allowedRdpSourceIp` to your public IP.

```bash
# Preview the VM addition (no cost). Supply a throwaway strong password inline.
az deployment sub what-if \
  --location westus \
  --parameters infra/main.bicepparam \
  --parameters deployVm=true allowedRdpSourceIp='YOUR.PUBLIC.IP/32' \
  --parameters adminPassword='<supplied-securely>'

# Deploy the VM (STARTS COMPUTE COST)
az deployment sub create \
  --name sentinel-lab \
  --location westus \
  --parameters infra/main.bicepparam \
  --parameters deployVm=true allowedRdpSourceIp='YOUR.PUBLIC.IP/32' \
  --parameters adminPassword='<supplied-securely>'
```

The admin password is a `@secure()` param — never put it in `main.bicepparam` (it is
committed). After deploy, confirm the data path (Phase 3) before turning on any detection:

```kql
SecurityEvent | where EventID == 4625 | take 5
Event | where Source == "Microsoft-Windows-Sysmon" | take 5
```

## Phase 2b — promoting the event source to a domain controller

`promoteToDomainController` (default **false**) turns that same VM into the lab's Active
Directory domain controller instead of adding a second machine. One VM is one compute bill,
and a lone DC is still a perfectly good Sysmon event source. The trade is a shared blast
radius between the directory and the event source, which is right for a burst lab and wrong
anywhere real.

What changes when it is on:

| Change | Why |
|---|---|
| Uncached data disk (LUN 0) for `NTDS.dit`, logs and SYSVOL | `caching: 'None'` is a correctness requirement, not tuning. Host write-back caching in front of a directory database can lose an acknowledged write and cause a **USN rollback** — the DC then serves objects the forest has moved past, silently. |
| Private IP goes **static** (`10.20.0.4`) | A DC cannot float: its address is baked into the SRV records it registers. |
| NIC resolver points at itself, with `168.63.129.16` second | A DC must resolve its own SRV records. Azure's platform resolver is listed second because AMA and Sysmon run **before** promotion and would otherwise have no DNS at all. |
| Third extension runs `promote-dc.ps1` | Installs `AD-Domain-Services`, promotes a new forest, schedules the restart. |

**Bump the VM size.** `Standard_B2s` is 4 GB, and AD DS + DNS + AMA + Sysmon together will
page on that. Use `Standard_B2ms` (8 GB) for DC mode.

```bash
# Preview (no cost)
az deployment sub what-if \
  --location westus \
  --parameters infra/main.bicepparam \
  --parameters deployVm=true promoteToDomainController=true vmSize=Standard_B2ms \
  --parameters allowedRdpSourceIp='YOUR.PUBLIC.IP/32' \
  --parameters adminPassword='<supplied-securely>' dsrmPassword='<supplied-securely>'

# Deploy (STARTS COMPUTE COST + one more managed disk)
az deployment sub create \
  --name sentinel-lab \
  --location westus \
  --parameters infra/main.bicepparam \
  --parameters deployVm=true promoteToDomainController=true vmSize=Standard_B2ms \
  --parameters allowedRdpSourceIp='YOUR.PUBLIC.IP/32' \
  --parameters adminPassword='<supplied-securely>' dsrmPassword='<supplied-securely>'
```

> **A green deployment means promotion was *staged*, not that the domain is ready.**
> Promotion needs a reboot, and a reboot kills a Custom Script Extension mid-run — which
> Azure reports as a failed extension even when the promotion worked. So the script promotes
> with `-NoRebootOnCompletion`, exits clean, and schedules the restart 60s later. The domain
> answers roughly 2-4 minutes after that.

Verify before doing anything else — sign in as `LAB\labadmin`:

```powershell
Get-ADDomain                                  # should return lab.dlpz.local
Get-ADDomainController                        # should list this VM
Get-Service NTDS, DNS | Select Name, Status   # both Running
```

Then seed the directory with real structure (OUs, users, groups, an SPN service account and
the audit policy that makes the DC emit Kerberos events):

```bash
az vm run-command invoke -g sc200-lab-rg -n sc200-win-vm \
  --command-id RunPowerShellScript \
  --scripts @infra/scripts/seed-ad.ps1 \
  --parameters "LabUserPasswordPlainText=<throwaway-strong-password>"
```

The password parameter is **mandatory** — omit it and the run-command fails on parameter
binding. `seed-ad.ps1` has two parameter sets for exactly this reason: `-LabUserPassword`
takes a `SecureString` and is the right choice from an interactive session on the DC, but
`az vm run-command` cannot carry a SecureString, so the plaintext set exists for this path
only. That value is visible in the ARM request and in shell history — **use a throwaway, and
never reuse a real password here.**

Promotion changes what the existing DCR sees: `4624/4625` stop being local logons and become
**domain** authentication. The Kerberos events (`4768/4769/4771`) an AD detection needs are a
separate, deliberate spending decision — see the event-ID inventory in `modules/dcr.bicep`.

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
