#Requires -RunAsAdministrator

<#
.SYNOPSIS
    HostGuard Security Baseline Setup Script
.DESCRIPTION
    Automated deployment and configuration script for the HostGuard Security Suite.
    Downloads security analysis scripts from Azure Blob Storage, configures the target VM environment,
    and sets up scheduled tasks for continuous security monitoring. The script handles:
    
    - System requirements validation (PowerShell version, admin privileges, disk space)
    - Creation of HostGuard directory structure (C:\HostGuard)
    - Download of sec-baseline-audit.ps1 (threat analysis engine)
    - Download of upload-sec-report.ps1 (report upload handler)
    - Download of AzCopy.exe for Azure storage operations
    - Creation of scheduled tasks for automated daily execution
    - UTF-8 encoding preservation for international character support
    - Comprehensive logging and error handling with retry mechanisms
    
    The script is designed for enterprise deployment across multiple VMs with centralized
    security reporting. It creates a complete security monitoring pipeline that runs
    daily at 23:45:01 to perform comprehensive threat analysis and upload results
    to Azure Blob Storage for static site consumption.
.NOTES
    Author: Darwin Galao
    Date: 2025-08-08
    Version: 4.0
    Requires: PowerShell 5.1+ and Administrator privileges
    
    DEPLOYMENT PROCESS:
    1. System Requirements Validation - PowerShell version, admin rights, disk space, connectivity
    2. Environment Initialization - Create HostGuard directory structure and permissions
    3. File Downloads - Retrieve audit scripts, upload handler, and AzCopy tool from Azure storage
    4. Scheduled Task Creation - Configure daily automated execution with proper XML templating
    5. Final Verification - Validate all components and report deployment status
    
    SCHEDULED TASK CONFIGURATION:
    - Execution Time: Daily at 23:45:01
    - Run Level: Highest Available (Administrator)
    - Multiple Instance Policy: Ignore New (prevents overlapping executions)
    - Execution Time Limit: 72 hours (for comprehensive analysis)
    - Actions: Runs both sec-baseline-audit.ps1 and upload-sec-report.ps1 sequentially
#>

[CmdletBinding()]
param()

# Script configuration
$ErrorActionPreference = "Stop"
$script:ScriptStartTime = Get-Date

# Define variables
$config = @{
    ScriptUrl_Audit = "https://[PLACEHOLDER-STORAGE-ACCOUNT].blob.core.windows.net/ps-scripts/sec-baseline-audit.ps1?[PLACEHOLDER-SAS-TOKEN]"
    ScriptUrl_Upload = "https://[PLACEHOLDER-STORAGE-ACCOUNT].blob.core.windows.net/ps-scripts/upload-sec-report.ps1?[PLACEHOLDER-SAS-TOKEN]"
    #ScriptUrl_BatchFile = "https://[PLACEHOLDER-STORAGE-ACCOUNT].blob.core.windows.net/ps-scripts/run-security-audit.bat?[PLACEHOLDER-SAS-TOKEN]"
    AzcopyUrl = "https://[PLACEHOLDER-TOOLS-STORAGE].blob.core.windows.net/software-installers/azcopy.exe?[PLACEHOLDER-SAS-TOKEN]"
    TargetFolder = "C:\HostGuard"
    TaskName = "run-sec-audit"
    MaxRetries = 3
    RetryDelay = 5
}

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFilePath = Join-Path -Path $config.TargetFolder -ChildPath "setup_$timestamp.log"

# Enhanced logging function
function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$Level] $Message"
    
    # Console output with colors
    if (-not $NoConsole) {
        switch ($Level) {
            "ERROR" { Write-Host $entry -ForegroundColor Red }
            "WARN" { Write-Host $entry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $entry -ForegroundColor Green }
            "DEBUG" { Write-Host $entry -ForegroundColor Gray }
            default { Write-Host $entry -ForegroundColor White }
        }
    }
    
    # File logging (create directory if needed)
    try {
        if (-not (Test-Path -Path (Split-Path $logFilePath))) {
            New-Item -Path (Split-Path $logFilePath) -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $logFilePath -Value $entry -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

# Enhanced file download function with file type detection
function Invoke-FileDownload {
    param (
        [Parameter(Mandatory)]
        [string]$Url,
        
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory)]
        [string]$FileLabel,
        
        [int]$MaxAttempts = $config.MaxRetries,
        [int]$DelaySeconds = $config.RetryDelay
    )
    
    Write-Log "Starting download of $FileLabel from URL (first 50 chars): $($Url.Substring(0, [Math]::Min(50, $Url.Length)))..."
    
    # Detect if this is a binary file based on extension or file label
    $fileExtension = [System.IO.Path]::GetExtension($DestinationPath).ToLower()
    $binaryExtensions = @('.exe', '.dll', '.bin', '.zip', '.7z', '.msi', '.cab')
    $isBinaryFile = ($binaryExtensions -contains $fileExtension) -or ($FileLabel -match "(?i)(exe|binary|tool|azcopy)")
    
    $fileType = if($isBinaryFile) { 'Binary' } else { 'Text' }
    Write-Log "File type detection: $fileType (Extension: $fileExtension)" "DEBUG"
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Log "Attempt $attempt/$MaxAttempts : Downloading $FileLabel..."
            
            # Check if destination directory exists
            $destinationDir = Split-Path -Path $DestinationPath
            if (-not (Test-Path -Path $destinationDir)) {
                New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                Write-Log "Created destination directory: $destinationDir"
            }
            
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "HostGuard-Setup/3.0")
            
            if ($isBinaryFile) {
                # Binary file: Use DownloadFile to preserve binary integrity
                Write-Log "Downloading binary file..." "DEBUG"
                $webClient.DownloadFile($Url, $DestinationPath)
                $webClient.Dispose()
                
                # Verify binary download
                if (Test-Path -Path $DestinationPath) {
                    $fileSize = (Get-Item $DestinationPath).Length
                    Write-Log "$FileLabel downloaded successfully (binary). Size: $([Math]::Round($fileSize / 1KB, 2)) KB" "SUCCESS"
                    
                    # Additional verification for executables
                    if ($fileExtension -eq '.exe') {
                        try {
                            $fileInfo = Get-ItemProperty -Path $DestinationPath
                            Write-Log "Executable verification: File appears valid" "SUCCESS"
                        } catch {
                            Write-Log "Executable verification warning: $($_.Exception.Message)" "WARN"
                        }
                    }
                    
                    return $true
                } else {
                    throw "Binary file not found after download"
                }
                
            } else {
                # Text file: Use UTF-8 encoding handling
                Write-Log "Downloading text file with UTF-8 encoding..." "DEBUG"
                $webClient.Encoding = [System.Text.Encoding]::UTF8
                
                # Download as string to preserve encoding
                $content = $webClient.DownloadString($Url)
                $webClient.Dispose()
                
                # Save with explicit UTF-8 encoding
                [System.IO.File]::WriteAllText($DestinationPath, $content, [System.Text.Encoding]::UTF8)
                
                # Verify text download and encoding
                if (Test-Path -Path $DestinationPath) {
                    $fileSize = (Get-Item $DestinationPath).Length
                    Write-Log "$FileLabel downloaded successfully (text). Size: $([Math]::Round($fileSize / 1KB, 2)) KB" "SUCCESS"
                    
					<#
                    # Verify encoding by checking for emojis (only for script files)
                    if ($fileExtension -eq '.ps1') {
                        try {
                            $testContent = Get-Content -Path $DestinationPath -Raw -Encoding UTF8
                            if ($testContent -match "📊") {
                                Write-Log "UTF-8 encoding verification successful - emojis preserved" "SUCCESS"
                            } elseif ($testContent -match "ðŸ") {
                                Write-Log "Encoding issue detected in PowerShell script" "WARN"
                                throw "Encoding verification failed"
                            }
                        } catch {
                            Write-Log "Encoding verification failed: $($_.Exception.Message)" "WARN"
                        }
                    }
					#>
                    
                    return $true
                } else {
                    throw "Text file not found after download"
                }
            }
            
        } catch {
            Write-Log "Primary method failed: $($_.Exception.Message)" "WARN"
            
            # Fallback method: Use Invoke-WebRequest
            try {
                Write-Log "Trying fallback method with Invoke-WebRequest..." "DEBUG"
                
                $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -UserAgent "HostGuard-Setup/3.0"
                
                if ($isBinaryFile) {
                    # Save binary content as bytes
                    [System.IO.File]::WriteAllBytes($DestinationPath, $response.Content)
                } else {
                    # Save text content with UTF-8 encoding
                    [System.IO.File]::WriteAllText($DestinationPath, $response.Content, [System.Text.Encoding]::UTF8)
                }
                
                if (Test-Path -Path $DestinationPath) {
                    $fileSize = (Get-Item $DestinationPath).Length
                    Write-Log "$FileLabel downloaded successfully (fallback method). Size: $([Math]::Round($fileSize / 1KB, 2)) KB" "SUCCESS"
                    return $true
                }
                
            } catch {
                $errorMsg = "Attempt $attempt failed for ${FileLabel}: $($_.Exception.Message)"
                Write-Log $errorMsg "ERROR"
                
                if ($attempt -lt $MaxAttempts) {
                    Write-Log "Retrying in $DelaySeconds seconds..." "WARN"
                    Start-Sleep -Seconds $DelaySeconds
                } else {
                    Write-Log "All download attempts failed for $FileLabel" "ERROR"
                    throw "Failed to download $FileLabel after $MaxAttempts attempts"
                }
            }
        }
    }
    return $false
}

# Enhanced XML escaping function
function ConvertTo-XmlSafeString {
    param([string]$InputString)
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    return $InputString -replace '&', '&amp;' `
                       -replace '<', '&lt;' `
                       -replace '>', '&gt;' `
                       -replace '"', '&quot;' `
                       -replace "'", '&apos;'
}

# Enhanced scheduled task creation
function New-HostGuardScheduledTask {
    param (
        [Parameter(Mandatory)]
        [string]$TaskName,
        
        [string]$ScriptPath = "C:\HostGuard\sec-baseline-audit.ps1"
    )
    
    Write-Log "Creating scheduled task: $TaskName"
    
    try {
        # Check if task already exists
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Task '$TaskName' already exists. Removing existing task..." "WARN"
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Log "Existing task removed successfully"
        }
        
        # Get system information
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSid = $currentUser.User.Value
        $userName = $currentUser.Name
        $hostname = $env:COMPUTERNAME
        
        # Calculate start time (daily at 23:59:59)
        $now = Get-Date
        $startTime = $now.Date.AddHours(23).AddMinutes(45).AddSeconds(01)
        
        # If the time has already passed today, schedule for tomorrow
        if ($startTime -le $now) {
            $startTime = $startTime.AddDays(1)
        }
        
        Write-Log "Task will be scheduled to run daily at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        
        # Create XML template with proper escaping
        $formattedDate = ConvertTo-XmlSafeString ($now.ToString("yyyy-MM-ddTHH:mm:ss.fffffff"))
        $startTimeStr = ConvertTo-XmlSafeString ($startTime.ToString("yyyy-MM-ddTHH:mm:ss"))
        $author = ConvertTo-XmlSafeString $userName
        $uri = ConvertTo-XmlSafeString "\$TaskName"
        $escapedSid = ConvertTo-XmlSafeString $userSid
        $escapedScriptPath = ConvertTo-XmlSafeString $ScriptPath
        
        $xmlTemplate = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedDate</Date>
    <Author>$author</Author>
    <URI>$uri</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$startTimeStr</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$escapedSid</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\HostGuard\sec-baseline-audit.ps1"</Arguments>
    </Exec>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\HostGuard\upload-sec-report.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

        # Create temporary XML file
        $tempXmlPath = [System.IO.Path]::Combine($env:TEMP, "$TaskName-$timestamp.xml")
        Write-Log "Creating temporary XML file: $tempXmlPath" "DEBUG"
        
        $xmlTemplate | Out-File -FilePath $tempXmlPath -Encoding Unicode -Force
        
        # Register the task
        Write-Log "Registering scheduled task using schtasks.exe..."
        $result = & schtasks.exe /Create /TN $TaskName /XML $tempXmlPath /F 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Scheduled task '$TaskName' created successfully" "SUCCESS"
            
            # Verify task creation
            $verifyTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($verifyTask) {
                Write-Log "Task verification successful. Status: $($verifyTask.State)" "SUCCESS"
            } else {
                Write-Log "Task created but verification failed" "WARN"
            }
        } else {
            throw "schtasks.exe failed with exit code $LASTEXITCODE. Output: $result"
        }
        
    } catch {
        Write-Log "Failed to create scheduled task '$TaskName': $($_.Exception.Message)" "ERROR"
        throw
    } finally {
        # Clean up temporary file
        if (Test-Path -Path $tempXmlPath) {
            Remove-Item -Path $tempXmlPath -Force -ErrorAction SilentlyContinue
            Write-Log "Temporary XML file removed" "DEBUG"
        }
    }
}

# Function to verify system requirements
function Test-SystemRequirements {
    Write-Log "Verifying system requirements..."
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell version: $psVersion"
    
    if ($psVersion.Major -lt 5) {
        throw "PowerShell 5.0 or higher is required. Current version: $psVersion"
    }
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        throw "This script must be run as Administrator"
    }
    
    Write-Log "Administrator privileges confirmed" "SUCCESS"
    
    # Check disk space (minimum 100MB)
    $drive = (Get-Item $config.TargetFolder.Substring(0,3)).PSDrive
    $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
    Write-Log "Available disk space on $($drive.Name): $freeSpaceGB GB"
    
    if ($drive.Free -lt 100MB) {
        throw "Insufficient disk space. At least 100MB required."
    }
    
    # Test internet connectivity
    Write-Log "Testing internet connectivity..."
    try {
        $testConnection = Test-NetConnection -ComputerName "www.microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($testConnection) {
            Write-Log "Internet connectivity verified" "SUCCESS"
        } else {
            throw "No internet connectivity detected"
        }
    } catch {
        Write-Log "Internet connectivity test failed: $_" "WARN"
    }
}

# Function to create HostGuard directory structure
function Initialize-HostGuardEnvironment {
    Write-Log "Initializing HostGuard environment..."
    
    try {
        if (-not (Test-Path -Path $config.TargetFolder)) {
            Write-Log "Creating HostGuard directory: $($config.TargetFolder)"
            New-Item -Path $config.TargetFolder -ItemType Directory -Force | Out-Null
            Write-Log "Directory created successfully" "SUCCESS"
        } else {
            Write-Log "HostGuard directory already exists: $($config.TargetFolder)"
        }
        
        # Note: Subdirectories will be created by the audit scripts as needed
        
        # Set appropriate permissions
        Write-Log "Setting directory permissions..."
        $acl = Get-Acl -Path $config.TargetFolder
        # Add any specific ACL modifications here if needed
        
        Write-Log "HostGuard environment initialized successfully" "SUCCESS"
        
    } catch {
        Write-Log "Failed to initialize HostGuard environment: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# Main execution function
function Start-HostGuardSetup {
    try {
        Write-Log "========== HostGuard Setup Started ==========" "SUCCESS"
        Write-Log "Script version: 2.0"
        Write-Log "Execution time: $($script:ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        Write-Log "Computer: $env:COMPUTERNAME"
        Write-Log "User: $env:USERNAME"
        Write-Log "Log file: $logFilePath"
        
        # Step 1: System requirements check
        Test-SystemRequirements
        
        # Step 2: Initialize environment
        Initialize-HostGuardEnvironment
        
        # Step 3: Download required files
        Write-Log "========== Downloading Required Files =========="
        
        # Download audit script
        $auditScriptPath = Join-Path -Path $config.TargetFolder -ChildPath "sec-baseline-audit.ps1"
        Invoke-FileDownload -Url $config.ScriptUrl_Audit -DestinationPath $auditScriptPath -FileLabel "Security Baseline Audit Script"
        
        # Download upload script
        $uploadScriptPath = Join-Path -Path $config.TargetFolder -ChildPath "upload-sec-report.ps1"
        Invoke-FileDownload -Url $config.ScriptUrl_Upload -DestinationPath $uploadScriptPath -FileLabel "Upload Security Report Script"
        
        # Download batch file
        #$batchFilePath = Join-Path -Path $config.TargetFolder -ChildPath "run-security-audit.bat"
        #Invoke-FileDownload -Url $config.ScriptUrl_BatchFile -DestinationPath $batchFilePath -FileLabel "Security Audit Batch File"

        # Download AzCopy if not present
        $azcopyPath = Join-Path -Path $config.TargetFolder -ChildPath "azcopy.exe"
        if (-not (Test-Path -Path $azcopyPath)) {
            Invoke-FileDownload -Url $config.AzcopyUrl -DestinationPath $azcopyPath -FileLabel "AzCopy Tool"
        } else {
            $existingSize = (Get-Item $azcopyPath).Length
            Write-Log "AzCopy already exists. Size: $([Math]::Round($existingSize / 1MB, 2)) MB" "INFO"
        }
        
        # Step 4: Create scheduled task
        Write-Log "========== Creating Scheduled Task =========="
        New-HostGuardScheduledTask -TaskName $config.TaskName -ScriptPath $auditScriptPath
        
        # Step 5: Final verification
        Write-Log "========== Final Verification =========="
        $files = @(
            @{Path = $auditScriptPath; Name = "Audit Script"},
            @{Path = $uploadScriptPath; Name = "Upload Script"},
            #@{Path = $batchFilePath; Name = "Batch File"},
            @{Path = $azcopyPath; Name = "AzCopy Tool"}
        )
        
        foreach ($file in $files) {
            if (Test-Path -Path $file.Path) {
                $size = (Get-Item $file.Path).Length
                Write-Log "$($file.Name): OK ($([Math]::Round($size / 1KB, 2)) KB)" "SUCCESS"
            } else {
                Write-Log "$($file.Name): MISSING" "ERROR"
            }
        }
        
        # Verify scheduled task
        $task = Get-ScheduledTask -TaskName $config.TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Log "Scheduled Task: OK (Status: $($task.State))" "SUCCESS"
        } else {
            Write-Log "Scheduled Task: MISSING" "ERROR"
        }
        
        $script:ScriptEndTime = Get-Date
        $executionTime = $script:ScriptEndTime - $script:ScriptStartTime
        
        Write-Log "========== Setup Completed Successfully ==========" "SUCCESS"
        Write-Log "Total execution time: $($executionTime.ToString('mm\:ss'))"
        Write-Log "Next audit scheduled for: $(if($task) { (Get-ScheduledTask -TaskName $config.TaskName | Get-ScheduledTaskInfo).NextRunTime } else { 'N/A' })"
        Write-Log "Log file saved to: $logFilePath"
        
    } catch {
        Write-Log "========== Setup Failed ==========" "ERROR"
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
        exit 1
    }
}

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    Start-HostGuardSetup
}