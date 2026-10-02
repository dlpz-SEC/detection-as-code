# Active Directory lab — build and live-fire evidence

**Captured 2026-09-04 (UTC).** Phase 2b of the Sentinel lab build-out: promoting the
event-source VM to a domain controller, administering the directory, and proving that real
domain authentication reaches Microsoft Sentinel in the shape the rule corpus consumes.

This file is the evidence half of Phase 7. The lab it describes was deliberately deleted
after capture — the infrastructure is burst by design, so this document and the templates in
`infra/` are the deliverable, not a running workspace.

---

## What was built

| Component | Value |
|---|---|
| Forest / domain | `lab.dlpz.local` (NetBIOS `LAB`) |
| Naming context | `DC=lab,DC=dlpz,DC=local` |
| Domain controller | `sc200winvm.lab.dlpz.local`, Global Catalog |
| Functional level | `Windows2016Domain` (`WinThreshold`) |
| OS | Windows Server 2022 Datacenter Azure Edition |
| Provisioning | Azure Bicep — `infra/main.bicep` + `infra/modules/vm.bicep` |
| Promotion | `infra/modules/promote-dc.ps1`, run as a managed Run Command |
| Directory seed | `infra/scripts/seed-ad.ps1` |
| Live fire | `infra/scripts/fire-domain-logons.ps1` |

`NTDS.dit`, its logs and `SYSVOL` sit on a dedicated data disk attached with `caching: 'None'`.
That is a correctness requirement, not tuning: host write-back caching in front of a directory
database can lose an acknowledged write on host failure, which is the classic route to a USN
rollback where the DC silently serves objects the forest has moved past.

### Directory contents after seeding

```
Run result: 31 created, 3 already existed, 0 failed

OUs (6):     Workstations, Servers, ServiceAccounts,
             Employees  ->  IT, Finance
Users (7):   j.reyes, m.okafor          (IT)
             a.chen, p.novak, t.walsh   (Finance)
             svc-backup, svc-sqlreport  (ServiceAccounts)
Groups:      IT-Admins        = j.reyes, m.okafor, svc-backup, svc-sqlreport
             Finance-ReadOnly = a.chen, p.novak, t.walsh
             Domain Admins    = labadmin, m.okafor
SPN:         MSSQLSvc/sqlreport.lab.dlpz.local:1433  on  svc-sqlreport
Audit:       10 subcategories enabled, read back from auditpol
```

`m.okafor` is in Domain Admins deliberately, so privileged and unprivileged logons are
distinguishable in the telemetry itself (via `4672`) rather than by looking the account up
afterwards. The SPN on `svc-sqlreport` is the target a Kerberoasting (T1558.003) detection
needs, and `configs/coverage_config.yml` lists T1558.003 as critical priority with no covering
rule. The target alone does not make Kerberoasting detectable here: the event such a rule fires
on, `4769`, is deliberately not collected by the DCR (see the collection path below).

---

## Collection path

`infra/modules/dcr.bicep` was widened for the domain controller. Verified live against ARM,
not just in the template:

```
Security!*[System[(EventID=4624)]]    successful logon
Security!*[System[(EventID=4625)]]    failed logon
Security!*[System[(EventID=4672)]]    special privileges assigned
Security!*[System[(EventID=4728)]]    member added to global group
Security!*[System[(EventID=4732)]]    member added to local group
Security!*[System[(EventID=4768)]]    Kerberos TGT requested
Security!*[System[(EventID=4771)]]    Kerberos pre-auth failed
Security!*[System[(EventID=4776)]]    NTLM credential validation
Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=10)]]
```

Path: domain controller → Azure Monitor Agent → `dcr-windows-security-events` →
`law-sc200-sentinel` (`da5be621-5078-475e-a864-de10f0c2e1e7`) → `SecurityEvent`.

---

## Live fire

`fire-domain-logons.ps1` ran two attack shapes, each chosen because `rules/` already contains
a detection for it. Window: **2026-09-04T05:23:23Z – 05:23:26Z**.

### Ingestion confirmed

```kql
SecurityEvent
| where TimeGenerated > datetime(2026-09-04T05:20:00Z)
| summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by EventID
| order by EventID asc
```

| EventID | Events | First | Last |
|---|---|---|---|
| 4624 | 102 | 05:20:08.156Z | 05:29:20.293Z |
| **4625** | **8** | **05:23:23.442Z** | **05:23:26.325Z** |
| 4672 | 101 | 05:20:08.156Z | 05:29:20.293Z |

This table is incomplete. The output was captured through `head -40`, which cut it off after
the `4672` row, and the rows are ordered by EventID, so any higher ID was never seen. `4776` was
ingested: `docs/evidence/sentinel-livefire-query.json` (every `SecurityEvent` row from 05:23:00Z
to 05:24:00Z) holds 10 `4776` rows alongside 16 `4624`, 8 `4625` and 15 `4672`. The `4776`
count for the full window since 05:20Z was not captured.

The eight `4625` records bound exactly to the fire window. Both 4625-based rules in the corpus
(`password_spray_single_source`, `bruteforce_failures_then_success`) select `EventID 4625`, so
this is the telemetry they are written against.

### Shape 1 — password spray

Feeds `rules/windows/credential_access/password_spray_single_source.yml`.

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-09-04T05:23:00Z) .. datetime(2026-09-04T05:24:00Z))
| where EventID == 4625
| summarize Failures=count(), DistinctAccounts=dcount(TargetUserName),
            Accounts=make_set(TargetUserName) by Computer
```

```
Computer                    Failures  DistinctAccounts  Accounts
sc200winvm.lab.dlpz.local   8         6                 a.chen, p.novak, t.walsh,
                                                        j.reyes, svc-backup, m.okafor
```

Six distinct accounts from one source: `IpAddress` is 10.20.0.4 on all eight rows in the
evidence export. The query above groups by the logging `Computer`; the spray rule groups by
`IpAddress`. The six mix both shapes: the five spray targets once each, plus the brute-force
target `m.okafor` three times. The five spray accounts alone meet the rule's threshold of 5
distinct `TargetUserName` per `IpAddress` within an hour. That breadth at a low count per
account is the signal spraying produces and lockout-threshold alerting misses.

### Shape 2 — bruteforce then success

Feeds `rules/windows/credential_access/bruteforce_failures_then_success.yml`.

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-09-04T05:23:00Z) .. datetime(2026-09-04T05:24:00Z))
| where TargetUserName == 'm.okafor' or SubjectUserName == 'm.okafor'
| project TimeGenerated, EventID, TargetUserName, SubjectUserName
| order by TimeGenerated asc
```

```
05:23:25.4997  4776  m.okafor    NTLM credential validation
05:23:25.4998  4625  m.okafor    failed logon 1
05:23:25.9199  4776  m.okafor
05:23:25.9200  4625  m.okafor    failed logon 2
05:23:26.3253  4776  m.okafor
05:23:26.3253  4625  m.okafor    failed logon 3
05:23:26.7324  4776  m.okafor    NTLM credential validation
05:23:26.7339  4672  m.okafor    SPECIAL PRIVILEGES ASSIGNED
05:23:26.7340  4624  m.okafor    SUCCESSFUL LOGON
```

The query projected no status column, so the outcome of each `4776` is inferred from the `4625`
or `4624` beside it, not read from the event. The run produced 3 failures for `m.okafor`, below
the rule's threshold of 5 per `TargetUserName` within an hour. This shows the event sequence the
rule keys on, not a sequence that meets its threshold; a run that meets it needs
`-FailuresPerAccount 5`, the script's maximum.

Failures alone are noise. Failures followed by a valid logon from the same source is a
compromised credential, and the `4672` immediately preceding the `4624` makes it a
**privileged** compromise rather than a standard one. This is why the DCR collects `4624` as
investigation context even though no rule selects it: the rule asks the analyst to confirm the
subsequent success, and without `4624` that confirmation is not possible.

### Shape 3 — privileged vs unprivileged contrast

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-09-04T05:23:00Z) .. datetime(2026-09-04T05:24:00Z))
| where EventID == 4672
| summarize Count=count() by SubjectUserName
```

```
SubjectUserName   Count
sc200winvm$       14      (the DC's computer account)
m.okafor          1       (the live-fire success)
```

13 of the 14 computer-account rows fall in the 0.3 s between 05:23:23.148Z and the first spray
failure at 05:23:23.442Z, which points at the fire script's own setup rather than background
activity. The cause was not captured.

`a.chen` authenticated successfully in the same window and produced a `4624` with **no**
`4672`. The distinction is present in the telemetry, not asserted on top of it.

---

## Honest limits of this evidence

Recorded because evidence that overstates itself is worse than none.

- **The authentication went over NTLM, not Kerberos.** `fire-domain-logons.ps1` used
  `PrincipalContext.ValidateCredentials`, which negotiated down to NTLM when binding against
  the DC locally. Consequence: `4776` and `4625` were produced, while **`4768` and `4771` were
  not**. The Kerberos collection path in the DCR is therefore configured and deployed but
  **not yet exercised**. Exercising it needs authentication from a domain-joined member over
  Kerberos, not a local bind on the DC itself.
- **`4769` was emitted locally but never ingested.** A `Get-WinEvent` read of the DC's local
  Security log (via `az vm run-command` at 05:29Z, 20-minute lookback) counted 2 `4769`
  events. Only counts were returned, so their fields and cause were not captured. No
  Kerberoasting was performed. They could not reach Sentinel: `infra/modules/dcr.bicep`
  deliberately excludes 4769 (cost, no consuming rule). The same read found no `4768` or
  `4771`. The SPN exists so that a future T1558.003 rule has a target, and that rule also needs
  4769 added to the DCR before it can fire in Sentinel.
- **No Sentinel analytics rule was fired for these events, and none could have been.** The two
  4625-based rules are Sigma correlation rules, which this pipeline cannot deploy to Sentinel:
  `sentinel/rule_map.yml` marks both `target: none`, because the kusto backend has no
  correlation support. So this evidence proves the *telemetry path* and the event sequence each
  rule keys on (the spray meets its rule's threshold; the brute-force run does not), not an
  end-to-end incident. Incident-to-triage remains Phase 6 and is still unproven.
- **The `UNPROTECTED` reading on the OUs was a reporting bug, and the true state is now
  unverifiable.** This bullet previously recorded it as a real discrepancy between
  `seed-ad.ps1`'s stated intent and its behavior. That was wrong, and the correction is
  itself worth recording. `ProtectedFromAccidentalDeletion` is a *constructed* property that
  the AD module derives from the object's ACL, and it is not in `Get-ADOrganizationalUnit`'s
  default property set. The verification block queried without `-Properties`, so the property
  came back `$null`, and a bare truth test printed `UNPROTECTED` for every OU regardless of
  its actual ACL. `New-LabOu` passes `-ProtectedFromAccidentalDeletion $true` and the seed
  reported `0 failed`, so there is no evidence the creation path ever misbehaved - but the
  lab was torn down the same night, so **the ACLs cannot now be re-read to prove it either
  way.** Fixed in `seed-ad.ps1` (edited 2026-09-04, committed 2026-09-05 as `11812ac`): the
  query requests the property, and `$null`
  now reports as `UNKNOWN (property not returned)` rather than being folded into `false`. Any
  future run produces a real measurement; this one did not.
- The lab used a single shared password across all seven accounts, which is a lab convenience
  and not a model of provisioning.

---

## Cost and teardown

`Standard_D2s_v6` Windows in westus at $0.21/hour, run for just under an hour (deployed from
04:52Z, deleted by 05:47Z), plus a 32 GB `StandardSSD_LRS` data disk and the OS disk prorated.
Estimated total for this exercise: **under $2**. Actual spend was not captured; the Cost
Management query was rate-limited.

Teardown was `az group delete --name sc200-lab-rg`. Note the 14-day Log Analytics soft-delete
window: because the template defaults (and `main.bicepparam`) pin the same resource group,
workspace name and region, a redeploy into the same subscription inside that window
**recovers** the soft-deleted workspace rather than creating a fresh one. The subscription comes
from the `az` CLI context; nothing in the repo pins it.
