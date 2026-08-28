using 'main.bicep'

// Lab defaults. These match the workspace the lab has been using by hand, so a
// redeploy lands on the same names rather than accumulating parallel workspaces.
// Note the trade-off: pinning the same name/region/RG is also what makes a
// redeploy within 14 days of teardown RECOVER the soft-deleted workspace instead
// of building a fresh one. See the teardown caveat in main.bicep.

param resourceGroupName = 'sc200-lab-rg'
// westus, not westus2: the existing law-sc200-sentinel workspace lives in westus,
// and a Log Analytics workspace's region is immutable. Deploying at westus2 fails
// with InvalidResourceLocation. The DCR must share the workspace region; the single
// location param already couples them.
param location = 'westus'
param workspaceName = 'law-sc200-sentinel'

// Cost guardrails. Raise deliberately, never casually.
//
// Be honest about what the cap does and when: during the 31-day Sentinel trial
// the first 10 GB/day is already free, so a 1 GB cap saves nothing in that
// window — what it does is make the lab go collection-blind at a tenth of the
// free allowance, at a reset hour you do not control. Its real job is protecting
// the days AFTER the trial, and any window where the workspace is left running
// unattended. If a live-fire day needs the headroom, raise it for that day.
param dailyQuotaGb = 1

// 90 days is free while Sentinel is onboarded here (31 on plain Log Analytics),
// so anything less discards retention that costs nothing.
param retentionInDays = 90

// The DCR only does something once a Windows VM with the Azure Monitor Agent is
// associated with it. Harmless to deploy early; set false to keep the identity
// phase minimal.
param deployDataCollectionRule = true

// --- Phase 2: Windows event source (VM) ------------------------------------
// OFF by default — the identity/infra phase costs nothing. Flip to true to stand
// up the VM (+ AMA + Sysmon + DCR association) that actually feeds the workspace.
// This STARTS COMPUTE COST. See the Phase 2 section in infra/README.md.
param deployVm = false

// Required when deployVm = true (uncomment and set):
//   param adminUsername = 'labadmin'
//   param allowedRdpSourceIp = 'YOUR.PUBLIC.IP/32'   // lock RDP to you; empty = nobody
//   param vmSize = 'Standard_B2s'
//
// NEVER put the admin password in this file (it is committed). Pass it at deploy
// time instead, e.g.:
//   az deployment sub create --name sentinel-lab --location westus \
//     --parameters infra/main.bicepparam deployVm=true \
//     --parameters adminPassword='<supplied-securely>'
