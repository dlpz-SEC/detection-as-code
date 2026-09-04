// Data Collection Rule - Windows security and Sysmon events, XPath-filtered.
//
// This is the cost-engineering surface of the lab. The Azure Monitor Agent sends
// what a DCR tells it to send, and "all security events" from a single Windows
// VM running Atomic Red Team will comfortably exhaust a 1 GB/day cap on its own.
//
// So the XPath queries below are deliberately narrow: the specific event IDs the
// detection corpus keys on, plus a named, justified set of investigation
// context. Widening this is a spending decision, not a config tweak. The events
// added here are the events billed for.
//
// WIDENED FOR THE DOMAIN CONTROLLER (2026-09-03). The original list assumed a
// standalone member server. vm.bicep now has promoteToDomainController (Phase
// 2b, default false), and a DC emits authentication telemetry a member server
// simply does not have. vm.bicep hands the decision here on purpose: "Widening
// the DCR to collect them is a separate, deliberate spending decision - see
// dcr.bicep." This is that decision. Six IDs were added, two of the obvious
// candidates were dropped on cost, and both drops are written down below so
// nobody re-litigates them from scratch.
//
// ---------------------------------------------------------------------------
// COLLECTED, and what consumes each. Verified against rules/ and
// sentinel/rule_map.yml, not assumed. "No rule" below is a statement of fact,
// not an oversight: those IDs are collected for a written investigative
// purpose and are the first things to cut if the cap gets tight.
//
// Logon/Logoff (emitted by every Windows host, DC or not)
//   4624 successful logon
//        No detection selection. Investigation context:
//        bruteforce_failures_then_success asks the analyst to confirm a
//        subsequent success. After promotion these stop being local logons and
//        become domain authentication.
//   4625 failed logon
//        bruteforce_failures_then_success, password_spray_single_source.
//        IMPORTANT on a DC: 4625 covers NTLM and interactive failures only. A
//        Kerberos password failure does not produce 4625, it produces 4771.
//        That gap is the main reason this file was widened.
//   4672 special privileges assigned to new logon
//        No rule. Investigation context, and the single addition here with real
//        volume: it fires alongside a large share of 4624s, including SYSTEM
//        and service logons. Kept because a brute-force success against a
//        privileged account and one against a standard user are different
//        incidents, and 4624 alone does not say which. First candidate to cut.
//
// Account Logon (KDC and credential validation)
//   4768 Kerberos TGT requested (AS-REQ)
//        No rule. On a DC this is the authoritative "authentication happened"
//        record for the domain; 4624 on a DC only shows logons TO the DC, not
//        domain-wide auth. Also carries the AS-REP roasting signal (T1558.004):
//        pre-authentication type 0 on an account flagged "do not require
//        Kerberos preauthentication". DC-ONLY producer.
//   4771 Kerberos pre-authentication failed
//        Named consumers, with a caveat that must not be skipped.
//        password_spray_single_source and bruteforce_failures_then_success both
//        select EventID 4625, and a DC does not emit 4625 for a Kerberos
//        password failure. Collecting 4771 closes the TELEMETRY gap; the rules
//        still need a 4771 selection to fire on it, which is rule work, not
//        collection work. Failure code 0x18 is a bad password (the spray
//        shape), 0x12 a disabled/locked/expired account. Low volume: failures
//        only. DC-ONLY producer.
//   4776 NTLM credential validation
//        Same two rules, same caveat, NTLM path instead of Kerberos. Error
//        0xC000006A is a bad password, 0xC0000064 is no such user. Unlike
//        4768/4771 this ALSO fires on a non-DC for local-account NTLM, so it
//        starts billing on the standalone VM as soon as this DCR updates.
//
// Account Management
//   4728 member added to a security-enabled GLOBAL group (DC-only producer)
//   4732 member added to a security-enabled LOCAL group (any host)
//        No rule. Directory privilege escalation and persistence (T1098,
//        T1078.002): an addition to "Domain Admins" is 4728, an addition to the
//        local "Administrators" group is 4732. Membership changes are rare
//        enough that the volume is effectively zero and every event is worth
//        reading. Best cost-to-value ratio in this file.
//
// Sysmon (Microsoft-Windows-Sysmon/Operational)
//   EID 1  process creation -> powershell_encoded_command
//   EID 10 process access   -> lsass_memory_access
//
// ---------------------------------------------------------------------------
// DELIBERATELY NOT COLLECTED, and why. The original contract was "add one back
// only alongside the rule that needs it". Widening this file for a DC does not
// retire that rule, so each exclusion carries its own reason.
//
//   4769 Kerberos service ticket requested (Kerberoasting, T1558.003).
//        Dropped on cost, and this is the one that would have hurt. 4769 is the
//        highest-volume event a domain controller produces: one per service
//        ticket, so a single interactive logon fans out into several and every
//        share access, LDAP bind and mapped drive adds more. There is no
//        Kerberoasting rule in rules/ to consume it today.
//        The affordable version is a predicate rather than the whole ID, since
//        the Kerberoasting signal is specifically RC4 tickets:
//          Security!*[System[(EventID=4769)]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17']]
//        TODO before shipping that line: confirm the Azure Monitor Agent
//        honours EventData predicates in a DCR XPath (System-level filtering is
//        certain, EventData filtering is NOT verified here). The failure mode
//        is the bad one - an unsupported predicate collects zero rows with no
//        error, the same silent miss the stream/table note below describes.
//        Verify against a live workspace, not against documentation alone.
//
//   5136 directory service object modified.
//        Dropped twice over. It is off by default: it needs the DS Access >
//        "Audit Directory Service Changes" subcategory enabled AND SACLs on the
//        objects you care about, and this repo configures neither. So adding
//        the XPath today collects nothing at all. Enable it without tight SACL
//        scoping and it becomes one of the noisiest events on a DC. No rule
//        consumes it. Revisit only with a directory-change detection in hand
//        and a SACL scoped to the objects that detection names.
//
//   4720 user account created, 4756 member added to a universal group, 4688
//        process creation. No rule matches them. 4688 in particular duplicates
//        Sysmon EID 1, which is richer.
//
// ---------------------------------------------------------------------------
// XPATH FILTERS, IT DOES NOT ENABLE. Every ID above is collected only if the
// host is already auditing the subcategory that produces it. If it is not, the
// channel has no such events and the XPath returns nothing, silently. Mapping:
//   4624/4625 -> Logon/Logoff > Audit Logon
//   4672      -> Logon/Logoff > Audit Special Logon
//   4768/4771 -> Account Logon > Audit Kerberos Authentication Service
//   4776      -> Account Logon > Audit Credential Validation
//   4728/4732 -> Account Management > Audit Security Group Management
// A domain controller's default policy audits Account Logon and Account
// Management for Success, but Failure coverage is per-subcategory and Failure
// is exactly the half that 4771 and 4776 need to be worth collecting. Confirm
// on the host with `auditpol /get /category:*` rather than assuming.
//
// NOT YET SATISFIED: infra/README.md points at infra/scripts/seed-ad.ps1 for
// "the audit policy that makes the DC emit Kerberos events". That script does
// not exist in the repo at the time of this edit. Until it does, or until
// auditpol is set by hand, the Kerberos XPaths below are correctly configured
// and produce nothing. TODO: confirm audit policy on the promoted DC before
// concluding a detection has no hits.
//
// ---------------------------------------------------------------------------
// INGESTION ESTIMATE against dailyQuotaGb = 1. This is an ESTIMATE, not a
// measurement, and it assumes roughly 2 KB billed per SecurityEvent row, which
// puts the cap near 500,000 events/day. Measure it instead of trusting it once
// the DC is running:
//   SecurityEvent
//   | where TimeGenerated > ago(1d)
//   | summarize Events = count(), GB = sum(_BilledSize) / 1024 / 1024 / 1024 by EventID
//   | order by GB desc
//
// Lab DC (a single-VM forest, a handful of seeded accounts, one joined host),
// order of magnitude per day:
//   4768        10^2        a TGT per user logon and renewal, plus machine accounts
//   4771        10^0-10^1   baseline; hundreds during a deliberate spray simulation
//   4776        10^1-10^2
//   4672        10^2-10^3   the dominant addition by a wide margin
//   4728/4732   10^0        effectively free
// Call it low thousands of added events per day, roughly 2-8 MB, comfortably
// under 1% of the cap. THESE ADDITIONS DO NOT THREATEN THE 1 GB CAP ON THIS
// LAB. Sysmon EID 1 remains the larger term and an Atomic Red Team run remains
// the thing that actually blows the cap.
//
// A production-sized DC is a different template, not a bigger version of this
// one. Order of magnitude and explicitly not measured here: in a domain of a
// few thousand accounts, 4768, 4776 and 4672 each run 10^5-10^6/day per DC, and
// 4769 alone runs higher than the rest combined. One busy DC can put several
// GB/day into this list, which is multiples of the entire cap, and at that size
// the answer is a DCR transform, Basic Logs, or a commitment tier - not a 1 GB
// cap and an XPath list. Do not copy this file into a real domain unchanged.
//
// ---------------------------------------------------------------------------
// Stream choice silently decides the destination TABLE, and nothing else
// records this:
//   'Microsoft-SecurityEvent' -> SecurityEvent table
//   'Microsoft-Event'         -> Event table (NOT SysmonEvent, NOT WindowsEvent)
// Sysmon rows land in Event with Source == 'Microsoft-Windows-Sysmon' and their
// fields (Image, CommandLine, TargetImage, GrantedAccess) inside the rendered
// EventData rather than as first-class columns, so KQL against them needs
// parsing. Anything written against a SysmonEvent table returns zero rows with
// no error.
//
// The DCR is inert until a VM is associated with it
// (Microsoft.Insights/dataCollectionRuleAssociations), which vm.bicep does.
// That association is per-VM but this rule is shared: every VM bound to it
// collects this whole list, promoted or not. The DC-only IDs cost nothing on a
// standalone host because nothing produces them; 4672, 4732 and 4776 do fire
// there and do bill there.

@description('Azure region. Must match the region of the destination Log Analytics workspace; VMs associated via a DCRA may live elsewhere.')
param location string

@description('ARM resource ID of the destination Log Analytics workspace.')
param workspaceResourceId string

@description('Name of the data collection rule.')
param dataCollectionRuleName string = 'dcr-windows-security-events'

@description('Collect the Active Directory additions (4672, 4728, 4732, 4768, 4771, 4776). True by default because a promoted DC is blind to Kerberos brute force without them. Set false to fall back to the member-server list. Note main.bicep does not pass this today, so changing it means editing this file or wiring the param through main.bicep.')
param collectDirectoryAuthEvents bool = true

@description('Tags applied to the rule.')
param tags object

// Collected on every associated host, promoted or not. Do not remove: 4625 has
// two named rules and 4624 is the investigation context they depend on.
var memberServerXPaths = [
  'Security!*[System[(EventID=4624)]]'
  'Security!*[System[(EventID=4625)]]'
]

// The Active Directory additions. Justified individually in the header; each
// line is billed ingestion. 4768/4771/4728 have no producer on a non-DC and
// cost nothing there. 4672/4732/4776 fire on a standalone host too.
var directoryAuthXPaths = [
  'Security!*[System[(EventID=4672)]]'
  'Security!*[System[(EventID=4728)]]'
  'Security!*[System[(EventID=4732)]]'
  'Security!*[System[(EventID=4768)]]'
  'Security!*[System[(EventID=4771)]]'
  'Security!*[System[(EventID=4776)]]'
]

// 4769 is deliberately absent from the list above. See the header before adding
// it: it is the highest-volume event on a DC and has no consuming rule.
var securityXPaths = collectDirectoryAuthEvents ? union(memberServerXPaths, directoryAuthXPaths) : memberServerXPaths

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dataCollectionRuleName
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    description: 'XPath-filtered Windows security and Sysmon events for the detection lab, including domain controller authentication and group-management events. Narrow by design: every added event ID is billed ingestion.'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: securityXPaths
        }
        {
          name: 'sysmonEvents'
          streams: [
            'Microsoft-Event'
          ]
          xPathQueries: [
            'Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=10)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'labWorkspace'
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityEvent'
        ]
        destinations: [
          'labWorkspace'
        ]
      }
      {
        streams: [
          'Microsoft-Event'
        ]
        destinations: [
          'labWorkspace'
        ]
      }
    ]
  }
}

@description('ARM resource ID of the DCR - needed to associate a VM with it later.')
output dataCollectionRuleId string = dataCollectionRule.id

@description('DCR name.')
output dataCollectionRuleName string = dataCollectionRule.name
