// Sentinel lab — subscription-scope entry point.
//
// Deploys the burst lab: a resource group, a Log Analytics workspace with a
// daily ingestion cap, Sentinel onboarded onto it, and a Data Collection Rule
// skeleton for Windows security events.
//
// The lab is designed to be torn down and rebuilt rather than left running, so
// this file IS the lab — anything created by hand in the portal is working
// capital, not infrastructure. Teardown is `az group delete`.
//
// TEARDOWN CAVEAT — rebuild is not always a clean slate. Log Analytics
// soft-deletes a workspace for 14 days. Because main.bicepparam deliberately
// pins the same subscription, resource group, workspace name and region, a
// redeploy inside that window RECOVERS the soft-deleted workspace rather than
// creating a new one: the old data and the existing Sentinel trial state come
// back with it, while installed solutions and linked services are gone for
// good. For a genuinely fresh lab, either wait out the 14 days or change
// workspaceName. `az monitor log-analytics workspace delete --force` skips the
// soft-delete window if you mean it.
//
// IMPORTANT: deploying a workspace with Sentinel starts a 31-day trial clock on
// that workspace. Do not deploy to "check if it works" — deploy when you intend
// to use the window.
//
//   az deployment sub create \
//     --name sentinel-lab \
//     --location westus \
//     --parameters infra/main.bicepparam
//
// (No --template-file: main.bicepparam's `using` statement supplies the
// template, and passing both is rejected by the CLI.)

targetScope = 'subscription'

@description('Resource group to hold the lab. Deleting this group is the teardown.')
param resourceGroupName string = 'sc200-lab-rg'

@description('Azure region for the resource group and all resources in it. Must match the existing law-sc200-sentinel workspace, whose region is westus and immutable — a Log Analytics workspace cannot be moved, so deploying elsewhere fails with InvalidResourceLocation.')
param location string = 'westus'

@description('Log Analytics workspace name. Sentinel is onboarded onto this workspace.')
param workspaceName string = 'law-sc200-sentinel'

@description('Daily ingestion cap in GB. The cost guardrail: a budget alert only notifies after the fact, this stops ingestion. Applies to billable tables; free tables keep flowing. 1 GB is the deliberate floor for this template — Azure itself allows as low as 0.023.')
@minValue(1)
param dailyQuotaGb int = 1

@description('Data retention in days. With Sentinel onboarded the first 90 days are free (plain Log Analytics includes 31); beyond 90 bills per GB per month.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Deploy the Windows security-events Data Collection Rule skeleton. Only useful once a VM with the Azure Monitor Agent exists.')
param deployDataCollectionRule bool = true

@description('Deploy the Windows event-source VM (Phase 2): VM + AMA + Sysmon + DCR association. STARTS COMPUTE COST. Requires deployDataCollectionRule = true.')
param deployVm bool = false

@description('Local admin username for the lab VM (used only when deployVm = true).')
param adminUsername string = 'labadmin'

@description('Local admin password for the lab VM. Required when deployVm = true — supply securely at deploy time (az prompts, or a Key Vault reference); never commit it.')
@secure()
param adminPassword string = ''

@description('Your public IP/CIDR allowed to RDP into the lab VM, e.g. 203.0.113.4/32. Fail-closed (nobody) if empty. Used only when deployVm = true.')
param allowedRdpSourceIp string = ''

@description('Size of the lab VM. Standard_B2s is the cheap burstable default.')
param vmSize string = 'Standard_B2s'

@description('Tags applied to every resource, so an orphaned lab is identifiable at a glance.')
param tags object = {
  project: 'sc200-detection-lab'
  owner: 'dlpz-SEC'
  lifecycle: 'burst-teardown'
}

resource labResourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module sentinelWorkspace 'modules/workspace.bicep' = {
  name: 'sentinel-workspace'
  scope: labResourceGroup
  params: {
    workspaceName: workspaceName
    location: location
    dailyQuotaGb: dailyQuotaGb
    retentionInDays: retentionInDays
    tags: tags
  }
}

module securityEventsDcr 'modules/dcr.bicep' = if (deployDataCollectionRule) {
  name: 'security-events-dcr'
  scope: labResourceGroup
  params: {
    location: location
    workspaceResourceId: sentinelWorkspace.outputs.workspaceResourceId
    tags: tags
  }
}

// Phase 2 event source. Off by default (deployVm = false) so the identity/infra
// phase costs nothing; flip it on to stand up the VM that feeds the DCR.
module eventSourceVm 'modules/vm.bicep' = if (deployVm) {
  name: 'event-source-vm'
  scope: labResourceGroup
  params: {
    location: location
    vmSize: vmSize
    adminUsername: adminUsername
    adminPassword: adminPassword
    allowedRdpSourceIp: allowedRdpSourceIp
    // Requires deployDataCollectionRule = true; `!` asserts the DCR module ran
    // (deployVm without the DCR is unsupported and documented as such).
    dataCollectionRuleId: securityEventsDcr!.outputs.dataCollectionRuleId
    tags: tags
  }
}

@description('Workspace GUID — this is the value ADTE needs as ADTE_SENTINEL_WORKSPACE_ID.')
output workspaceId string = sentinelWorkspace.outputs.workspaceId

@description('Full ARM resource ID of the workspace.')
output workspaceResourceId string = sentinelWorkspace.outputs.workspaceResourceId

@description('Resource group holding the lab. `az group delete --name <this>` is the teardown.')
output resourceGroupName string = labResourceGroup.name

@description('Public IP of the lab VM (empty unless deployVm = true). RDP here once allowedRdpSourceIp includes you.')
output labVmPublicIp string = deployVm ? eventSourceVm!.outputs.publicIpAddress : ''
