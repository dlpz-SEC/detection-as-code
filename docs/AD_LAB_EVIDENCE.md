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
afterwards. The SPN on `svc-sqlreport` is the object a Kerberoasting (T1558.003) detection
would otherwise have nothing to fire on — `configs/coverage_config.yml` lists T1558.003 as
critical priority with no covering rule.

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
```

| EventID | Events | First | Last |
|---|---|---|---|
| 4624 | 102 | 05:20:08.156Z | 05:29:20.293Z |
| **4625** | **8** | **05:23:23.442Z** | **05:23:26.325Z** |
| 4672 | 101 | 05:20:08.156Z | 05:29:20.293Z |

The eight `4625` records bound exactly to the fire window. Both credential-access rules in the
corpus select `EventID 4625`, so this is the telemetry they actually consume.

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

One source, six distinct accounts, low count per account — the breadth signal spraying
produces and lockout-threshold alerting misses.

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
05:23:25.4997  4776  m.okafor    NTLM credential validation (fail)
05:23:25.4998  4625  m.okafor    failed logon 1
05:23:25.9199  4776  m.okafor
05:23:25.9200  4625  m.okafor    failed logon 2
05:23:26.3253  4776  m.okafor
05:23:26.3253  4625  m.okafor    failed logon 3
05:23:26.7324  4776  m.okafor    NTLM credential validation (success)
05:23:26.7339  4672  m.okafor    SPECIAL PRIVILEGES ASSIGNED
05:23:26.7340  4624  m.okafor    SUCCESSFUL LOGON
```

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
sc200winvm$       14      (the computer account, normal DC activity)
m.okafor          1       (the live-fire success)
```

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
- **`4769` appeared (2 events) from ordinary DC activity, not from a Kerberoast.** No
  Kerberoasting was performed. The SPN exists so that a future T1558.003 rule has a target;
  the attack itself was not run.
- **No Sentinel analytics rule was fired for these events.** The two credential-access rules
  live in `rules/` and were not deployed as scheduled analytics rules during this window, so
  this evidence proves the *telemetry path* and the *detection shape*, not an end-to-end
  incident. Incident-to-triage remains Phase 6 and is still unproven.
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
  way.** Fixed in `seed-ad.ps1` on 2026-09-04: the query requests the property, and `$null`
  now reports as `UNKNOWN (property not returned)` rather than being folded into `false`. Any
  future run produces a real measurement; this one did not.
- The lab used a single shared password across all seven accounts, which is a lab convenience
  and not a model of provisioning.

---

## Cost and teardown

`Standard_D2s_v6` Windows in westus at $0.21/hour, run for well under an hour, plus a
32 GB `StandardSSD_LRS` data disk and the OS disk prorated. Total for this exercise was
**under $2**.

Teardown was `az group delete --name sc200-lab-rg`. Note the 14-day Log Analytics soft-delete
window: because `main.bicepparam` pins the same subscription, resource group, workspace name
and region, a redeploy inside that window **recovers** the soft-deleted workspace rather than
creating a fresh one.
