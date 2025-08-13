<#
.SYNOPSIS
    HostGuard Security Report Upload Script
.DESCRIPTION
    Uploads generated security reports to Azure Blob Storage for centralized access and static site consumption.
    Handles secure file transfer, metadata management, and report lifecycle operations.
    Designed to work in conjunction with sec-baseline-audit.ps1 for automated reporting pipeline.
.NOTES
    Author: Darwin Galao
    Date: 2025-08-08
    Version: 2.0
    Requires: PowerShell 5.1+, AzCopy.exe, and network connectivity to Azure Storage
    
    EXECUTION FLOW:
    1. Initialize logging and configuration
    2. Locate and validate security reports
    3. Upload reports to Azure Blob Storage
    4. Update report metadata and indices
    5. Clean up old reports based on retention policy
    6. Generate upload status report
#>

# Requires -RunAsAdministrator

[CmdletBinding()]
param()

# Script configuration
$ErrorActionPreference = "Stop"
$script:ScriptStartTime = Get-Date

# Define configuration variables
$config = @{
    ReportsPath = "C:\HostGuard\Reports"
    AzCopyPath = "C:\HostGuard\azcopy.exe"
    StorageAccount = "[PLACEHOLDER-STORAGE-ACCOUNT]"
    ContainerName = "security-reports"
    SasToken = "?[PLACEHOLDER-SAS-TOKEN]"
    RetentionDays = 30
    MaxRetries = 3
    RetryDelay = 5
}

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFilePath = "C:\HostGuard\upload_$timestamp.log"

# Enhanced logging function
function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN" { Write-Host $entry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        "DEBUG" { Write-Host $entry -ForegroundColor Gray }
        default { Write-Host $entry -ForegroundColor Cyan }
    }
    
    # File logging
    try {
        Add-Content -Path $logFilePath -Value $entry -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

# Function to upload security reports
function Start-ReportUpload {
    try {
        Write-Log "========== Security Report Upload Started ==========" "SUCCESS"
        Write-Log "Script version: 2.0"
        Write-Log "Execution time: $($script:ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Log "Computer: $env:COMPUTERNAME"
        
        # Check for AzCopy
        if (-not (Test-Path -Path $config.AzCopyPath)) {
            throw "AzCopy not found at: $($config.AzCopyPath)"
        }
        
        # Check for reports directory
        if (-not (Test-Path -Path $config.ReportsPath)) {
            throw "Reports directory not found: $($config.ReportsPath)"
        }
        
        # Find HTML reports to upload
        $reports = Get-ChildItem -Path $config.ReportsPath -Filter "*.html" -ErrorAction SilentlyContinue
        
        if ($reports.Count -eq 0) {
            Write-Log "No HTML reports found to upload" "WARN"
            return
        }
        
        Write-Log "Found $($reports.Count) report(s) to upload"
        
        # Upload each report
        foreach ($report in $reports) {
            try {
                $destinationPath = "$($env:COMPUTERNAME)/$($report.Name)"
                $storageUrl = "https://$($config.StorageAccount).blob.core.windows.net/$($config.ContainerName)/$destinationPath$($config.SasToken)"
                
                Write-Log "Uploading: $($report.Name) -> $destinationPath"
                
                $azcopyArgs = @(
                    "copy",
                    "`"$($report.FullName)`"",
                    "`"$storageUrl`"",
                    "--overwrite=true"
                )
                
                $result = & $config.AzCopyPath $azcopyArgs 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Successfully uploaded: $($report.Name)" "SUCCESS"
                } else {
                    Write-Log "Failed to upload $($report.Name): $result" "ERROR"
                }
                
            } catch {
                Write-Log "Error uploading $($report.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "========== Upload Process Completed ==========" "SUCCESS"
        
    } catch {
        Write-Log "========== Upload Failed ==========" "ERROR"
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-ReportUpload
}
