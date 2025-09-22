<#
.SYNOPSIS
    Azure Automation Runbook for Threat Analysis Report Tool Deployment
.DESCRIPTION
    Orchestrates the deployment of HostGuard security monitoring scripts to target Azure VMs 
    or VM Scale Sets using Azure VM Run Command. Supports both single VM deployments and 
    scale set deployments with managed identity authentication and comprehensive error handling.
.NOTES
    Author: Darwin Galao
    Date: 2025-08-13
    Version: 3.0
    Requires: Azure PowerShell modules, Managed Identity with VM Contributor permissions
    
    DEPLOYMENT PROCESS:
    1. Authenticate using Managed Identity
    2. Validate input parameters (VM or VMSS)
    3. Download hostguard.ps1 from Azure Storage
    4. Execute deployment script on target VMs using Run Command
    5. Monitor and report deployment status
.PARAMETER ResourceGroupName
    The Azure resource group containing the target VMs or VM Scale Sets
.PARAMETER VMName
    Specific VM name for single VM deployment (mutually exclusive with VMSSName)
.PARAMETER VMSSName
    VM Scale Set name for scale set deployment (requires InstanceID)
.PARAMETER InstanceID
    Specific instance ID within VM Scale Set (required when using VMSSName)
.PARAMETER TargetSubscription
    Azure subscription ID containing the target resources
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "[PLACEHOLDER-RESOURCE-GROUP]",

    [Parameter(Mandatory = $false)]
    [string]$VMName,

    [Parameter(Mandatory = $false)]
    [string]$VMSSName,

    [Parameter(Mandatory = $false)]
    [int]$InstanceID,

    [Parameter(Mandatory = $false)]
    [string]$TargetSubscription = "[PLACEHOLDER-SUBSCRIPTION-ID]"
)

# Logging utility
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

# Azure login using UAMI
function Connect-ToAzure {
    Write-Log "Authenticating using managed identity..."
    try {
        Connect-AzAccount -Identity | Out-Null
        Write-Log "Connected to Azure successfully."
        Set-AzContext -Subscription $TargetSubscription | Out-Null
        Write-Log "Azure context set to subscription: $TargetSubscription"
    } catch {
        Write-Log "Failed to authenticate with Azure. $_" "ERROR"
        throw
    }
}

# Validate input parameters
function Validate-Input {
    if ([string]::IsNullOrWhiteSpace($VMName) -and [string]::IsNullOrWhiteSpace($VMSSName)) {
        throw "You must specify either -VMName or -VMSSName."
    }
    if (-not [string]::IsNullOrWhiteSpace($VMName) -and -not [string]::IsNullOrWhiteSpace($VMSSName)) {
        throw "You can only specify one of -VMName or -VMSSName, not both."
    }
    if (-not [string]::IsNullOrWhiteSpace($VMSSName) -and $InstanceID -eq $null) {
        throw "When specifying -VMSSName, you must also provide -InstanceID."
    }
}

# Run command on VM
function Handle-VM {
    param (
        [string]$ScriptFileName
    )

    Write-Log "Targeting Azure VM: $VMName in resource group $ResourceGroupName"
    $Output = Invoke-AzVMRunCommand `
        -ResourceGroupName $ResourceGroupName `
        -VMName $VMName `
        -CommandId 'RunPowerShellScript' `
        -ScriptPath "$env:TEMP\$ScriptFileName"

    Write-Log "Script Result: "
    Write-Log "`n "
    $Output.Value.Message
}

# Run command on VMSS
function Handle-VMSS {
    param (
        [string]$ScriptFileName
    )

    Write-Log "Targeting VMSS: $VMSSName / Instance ID: $InstanceID in resource group $ResourceGroupName"
    $Output = Invoke-AzVmssVMRunCommand `
        -ResourceGroupName $ResourceGroupName `
        -VMScaleSetName $VMSSName `
        -InstanceId $InstanceID `
        -CommandId 'RunPowerShellScript' `
        -ScriptPath "$env:TEMP\$ScriptFileName"

    Write-Log "Script Result: "
    Write-Log "`n "
    $Output.Value.Message
}

# === MAIN EXECUTION ===

try {
    Connect-ToAzure
    Validate-Input

    # Script Storage Info
    $ScriptStorageAccount = "[PLACEHOLDER-STORAGE-ACCOUNT]"
    $ScriptStorageKey = "[PLACEHOLDER-STORAGE-KEY]"
    $ScriptStorageContainer = "scheduled-operations"
    $ScriptFileName = "hostguard.ps1"

    # Create Storage Context
    $storage_context = New-AzStorageContext -StorageAccountName $ScriptStorageAccount -StorageAccountKey $ScriptStorageKey

    # Download script to TEMP
    $scriptFile = Get-AzStorageBlobContent `
        -Container $ScriptStorageContainer `
        -Blob $ScriptFileName `
        -Destination "$env:TEMP" `
        -Context $storage_context `
        -Force

    $downloadedFileName = $scriptFile.Name
    Write-Log "Downloaded script to: $env:TEMP\$downloadedFileName"

    # Execute the script remotely
    if ($VMName) {
        Handle-VM -ScriptFileName $downloadedFileName
    } elseif ($VMSSName) {
        Handle-VMSS -ScriptFileName $downloadedFileName
    }

    Write-Log "Script completed successfully."
} catch {
    Write-Log "Script failed: $_" "ERROR"
    throw
}
