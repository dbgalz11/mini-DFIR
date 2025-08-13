<#
.SYNOPSIS
    HostGuard Security Baseline Audit Script - Enhanced Threat Analysis v5.1
.DESCRIPTION
    Performs comprehensive security analysis and threat detection on Windows hosts.
    Generates detailed HTML reports covering logon events, IIS logs, file modifications,
    web shell detection, process analysis, network connections, and system health checks.
    Designed for automated execution via scheduled tasks with centralized reporting.
.NOTES
    Author: Darwin Galao
    Date: 2025-08-04
    Version: 5.1
    Requires: PowerShell 5.1+ and Administrator privileges
    
    EXECUTION FLOW:
    1. Script Initialization - Set configuration, paths, and global variables
    2. Utility Functions - Logging, error tracking, security findings management
    3. Computer Details Collection - Gather system information first
    4. Security Analysis Functions - Core threat detection capabilities (run in order)
    5. HTML Report Generation - Dashboard and section generators
    6. Main Execution - Orchestrates all checks and generates final report

    The script follows a hybrid time window approach:
    - Log Analysis: Daily window (00:00 to current time)
    - File Monitoring: Rolling 25-hour window
    - Security Events: Rolling 24-hour window
    - Critical Events: Rolling 26-hour window (buffer)
#>

# ==============================================================================
# 1. SCRIPT INITIALIZATION AND CONFIGURATION
# ==============================================================================

cd "C:\HostGuard"

$script:ScriptStartTime = Get-Date
$script:Config = @{
    LogAnalysisStart = (Get-Date -Hour 0 -Minute 0 -Second 0)
    LogAnalysisEnd = Get-Date
    FileModificationWindow = (Get-Date).AddHours(-25)
    SecurityEventWindow = (Get-Date).AddHours(-24)
    CriticalEventWindow = (Get-Date).AddHours(-26)
    LogPath = "C:\inetpub\logs\LogFiles"
    WebRoot = "C:\inetpub\wwwroot"
    DirsToCheck = @("C:\inetpub\wwwroot", "$env:TEMP", "C:\Windows\Temp", "C:\Users\*\Downloads", "C:\Users\*\Desktop")
    MaxFileSize = 500MB
    LineLimit = 1000
    ThreadCount = 4
    ReportRetentionDays = 30
    HashBaselineRefreshHours = 168
    NumberOfLogons = 50
}

$script:LogEntries = ""
$script:ErrorEntries = ""
$script:SecurityFindings = @()
$script:ErrorDetails = @()

# ==============================================================================
# 2. UTILITY FUNCTIONS - LOGGING AND ERROR MANAGEMENT
# ==============================================================================

function Write-EnhancedLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "CRITICAL", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp [$Level] $Message"
    
    $color = switch ($Level) {
        "INFO" { "Cyan" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "CRITICAL" { "Magenta" }
        "SUCCESS" { "Green" }
    }
    
    Write-Host $entry -ForegroundColor $color
    
    $cssClass = switch ($Level) {
        "ERROR" { "error" }
        "WARN" { "warning" }
        "CRITICAL" { "suspicious" }
        "SUCCESS" { "success" }
        default { "timestamp" }
    }
    
    if ($Level -in @("ERROR", "CRITICAL")) {
        $script:ErrorEntries += "<div class='$cssClass'>$entry</div>"
    }
    $script:LogEntries += "<div class='$cssClass'>$entry</div>"
}

function Add-ErrorDetail {
    param(
        [string]$Component,
        [string]$Operation,
        [string]$ErrorMessage,
        [string]$FileName = "",
        [string]$LineNumber = ""
    )
    
    $script:ErrorDetails += [PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Component = $Component
        Operation = $Operation
        ErrorMessage = $ErrorMessage
        FileName = $FileName
        LineNumber = $LineNumber
    }
}

function Add-SecurityFinding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description,
        [hashtable]$Details
    )
    
    $detailsString = ""
    if ($Details -and $Details.Count -gt 0) {
        $detailsArray = @()
        foreach ($key in $Details.Keys) {
            $detailsArray += "$key`: $($Details[$key])"
        }
        $detailsString = $detailsArray -join "; "
    }
    
    $script:SecurityFindings += [PSCustomObject]@{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category = $Category
        Severity = $Severity
        Description = $Description
        Details = $detailsString
    }
}

# ==============================================================================
# 3. COMPUTER DETAILS COLLECTION (First Analysis Step)
# ==============================================================================

function Get-ComputerDetails {
    try {
        Write-EnhancedLog "Gathering computer details..." "INFO"
        $computerDetails = @()
        
        $computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
        
        $ipAddresses = @()
        foreach ($adapter in $networkAdapters) {
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                Where-Object { $_.IPAddress -ne "127.0.0.1" }
            if ($ipConfig) {
                $ipAddresses += $ipConfig.IPAddress
            }
        }
        
        $isDomainJoined = $false
        $domainName = "WORKGROUP"
        try {
            $domain = Get-WmiObject -Class Win32_ComputerSystem
            if ($domain.PartOfDomain) {
                $isDomainJoined = $true
                $domainName = $domain.Domain
            }
        } catch {
            Write-EnhancedLog "Could not determine domain status" "WARN"
        }
        
        $osVersion = "Unknown"
        $buildNumber = "Unknown"
        if ($computerInfo) {
            $osVersion = $computerInfo.WindowsProductName
            $buildNumber = $computerInfo.WindowsBuildLabEx
        }
        
        $lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $uptime = (Get-Date) - $lastBootTime
        $timeZone = (Get-TimeZone).DisplayName
        
        $antivirusStatus = "Unknown"
        try {
            $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
            if ($antivirus) {
                $antivirusStatus = ($antivirus | Select-Object -First 1).displayName
            }
        } catch {
            $antivirusStatus = "Unable to detect"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Computer Name"
            Value = $env:COMPUTERNAME
            Category = "Identity"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "IP Addresses"
            Value = ($ipAddresses -join ", ")
            Category = "Network"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Domain Status"
            Value = if ($isDomainJoined) { "Domain-joined: $domainName" } else { "Workgroup: $domainName" }
            Category = "Security"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Operating System"
            Value = $osVersion
            Category = "System"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Build Number"
            Value = $buildNumber
            Category = "System"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Last Boot Time"
            Value = $lastBootTime.ToString('yyyy-MM-dd HH:mm:ss')
            Category = "System"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Uptime"
            Value = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
            Category = "System"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Time Zone"
            Value = $timeZone
            Category = "System"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Antivirus"
            Value = $antivirusStatus
            Category = "Security"
        }
        
        $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
        $computerDetails += [PSCustomObject]@{
            Property = "Remote Desktop"
            Value = if ($rdpEnabled) { "Enabled" } else { "Disabled" }
            Category = "Security"
        }
        
        $firewallProfiles = Get-NetFirewallProfile
        $firewallStatus = @()
        foreach ($profile in $firewallProfiles) {
            $firewallStatus += "$($profile.Name): $($profile.Enabled)"
        }
        
        $computerDetails += [PSCustomObject]@{
            Property = "Windows Firewall"
            Value = ($firewallStatus -join "; ")
            Category = "Security"
        }
        
        return $computerDetails
        
    } catch {
        Write-EnhancedLog "Error gathering computer details: $_" "ERROR"
        Add-ErrorDetail -Component "Computer Details" -Operation "Get-ComputerDetails" -ErrorMessage $_.Exception.Message
        return @()
    }
}

# ==============================================================================
# 4. SECURITY ANALYSIS FUNCTIONS (In Execution Order)
# ==============================================================================

function Get-LastLogonEvents {
    try {
        Write-EnhancedLog "Analyzing last $($script:Config.NumberOfLogons) logon events..." "INFO"
        $logonResults = @()
        
        $logonEvents = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4624 or EventID=4648]]" -MaxEvents $script:Config.NumberOfLogons -ErrorAction SilentlyContinue
        
        if (-not $logonEvents) {
            Write-EnhancedLog "No logon events found" "WARN"
            return @()
        }
        
        foreach ($logonEvent in $logonEvents) {
            try {
                $eventXml = [xml]$logonEvent.ToXml()
                $eventData = $eventXml.Event.EventData.Data
                
                $logonType = ""
                $targetUser = ""
                $sourceIP = ""
                $logonProcess = ""
                $authPackage = ""
                $workstation = ""
                
                if ($logonEvent.Id -eq 4624) {
                    $logonTypeCode = ($eventData | Where-Object { $_.Name -eq "LogonType" }).'#text'
                    $logonType = switch ($logonTypeCode) {
                        "2" { "Interactive (Local)" }
                        "3" { "Network" }
                        "4" { "Batch" }
                        "5" { "Service" }
                        "7" { "Unlock" }
                        "8" { "NetworkCleartext" }
                        "9" { "NewCredentials" }
                        "10" { "RemoteInteractive (RDP)" }
                        "11" { "CachedInteractive" }
                        default { "Unknown ($logonTypeCode)" }
                    }
                    
                    $targetUser = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    $sourceIP = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                    $workstation = ($eventData | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
                    $logonProcess = ($eventData | Where-Object { $_.Name -eq "LogonProcessName" }).'#text'
                    $authPackage = ($eventData | Where-Object { $_.Name -eq "AuthenticationPackageName" }).'#text'
                    
                } elseif ($logonEvent.Id -eq 4648) {
                    $logonType = "Explicit Credential Use"
                    $targetUser = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    $sourceIP = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                    $workstation = ($eventData | Where-Object { $_.Name -eq "TargetServerName" }).'#text'
                }
                
                $riskLevel = "Low"
                $riskReason = ""
                $isLocalIP = $false
                
                if ($sourceIP -and $sourceIP -ne "-" -and $sourceIP -ne "::1" -and ![string]::IsNullOrWhiteSpace($sourceIP)) {
                    $ipv4Local = @(
                        '^127\.','^10\.','^192\.168\.','^172\.1[6-9]\.','^172\.2[0-9]\.','^172\.3[0-1]\.','^169\.254\.','^224\.','^0\.0\.0\.0$'
                    )
                    
                    $ipv6Local = @(
                        '^::1$','^::ffff:127\.','^fe80:','^fc00:','^fd00:','^::$','^::ffff:192\.168\.','^::ffff:10\.','^::ffff:172\.1[6-9]\.','^::ffff:172\.2[0-9]\.','^::ffff:172\.3[0-1]\.'
                    )
                    
                    $isLocalIP = $false
                    foreach ($pattern in ($ipv4Local + $ipv6Local)) {
                        if ($sourceIP -match $pattern) {
                            $isLocalIP = $true
                            break
                        }
                    }
                } else {
                    $isLocalIP = $true
                }
                
                if (-not $isLocalIP) {
                    $riskLevel = "High"
                    $riskReason = "External IP address"
                } 
                elseif ($targetUser -match '\$$') {
                    $riskLevel = "Low"
                    $riskReason = "Computer account authentication"
                }
                elseif ($targetUser -match "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-[0-9]+|UMFD-[0-9]+)$") {
                    $riskLevel = "Low"
                    $riskReason = "System account"
                }
                elseif ($targetUser -match "(admin|root|administrator)") {
                    $riskLevel = "Medium"
                    $riskReason = "Administrative account"
                }
                elseif ($logonType -match "RemoteInteractive|Network" -and $targetUser -notmatch "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$)") {
                    $riskLevel = "Medium"  
                    $riskReason = "Remote logon"
                }
                elseif ($logonType -match "Batch|Service" -and $targetUser -notmatch "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$)" -and $targetUser -notmatch "(admin|root|administrator)") {
                    $riskLevel = "Medium"
                    $riskReason = "User account in automated context"
                }
                elseif ($logonType -match "NetworkCleartext") {
                    $riskLevel = "Medium"
                    $riskReason = "Clear text password authentication"
                }
                
                $contextualInfo = @{
                    IsComputerAccount = $targetUser -match '\$$'
                    IsSystemAccount = $targetUser -match "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-[0-9]+|UMFD-[0-9]+)$"
                    IsAdminAccount = $targetUser -match "(admin|root|administrator)"
                    IsExternalIP = -not $isLocalIP
                    IsInteractive = $logonType -match "Interactive|RemoteInteractive"
                    IsAutomated = $logonType -match "Batch|Service"
                    UsesNTLM = $authPackage -match "NTLM"
                    IsExplicitCredUse = $logonEvent.Id -eq 4648
                }
                
                $riskFactors = @()
                if ($contextualInfo.IsExternalIP) { $riskFactors += "External IP" }
                if ($contextualInfo.IsAdminAccount) { $riskFactors += "Admin Account" }
                if ($contextualInfo.UsesNTLM) { $riskFactors += "NTLM Auth" }
                if ($contextualInfo.IsExplicitCredUse) { $riskFactors += "Explicit Creds" }
                if ($logonType -match "NetworkCleartext") { $riskFactors += "Clear Text" }
                
                if ($riskFactors.Count -ge 3 -and $riskLevel -ne "High") {
                    $riskLevel = "High"
                    $riskReason = "Multiple risk factors: $($riskFactors -join ', ')"
                } elseif ($riskFactors.Count -ge 2 -and $riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                    $riskReason = "Multiple risk factors: $($riskFactors -join ', ')"
                }
                
                $hoursAgo = [math]::Round(((Get-Date) - $logonEvent.TimeCreated).TotalHours, 2)
                
                $logonResults += [PSCustomObject]@{
                    Timestamp = $logonEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    EventID = $logonEvent.Id
                    LogonType = $logonType
                    TargetUser = $targetUser
                    SourceIP = if ($sourceIP -eq "-" -or [string]::IsNullOrWhiteSpace($sourceIP)) { "Local" } else { $sourceIP }
                    Workstation = $workstation
                    LogonProcess = $logonProcess
                    AuthPackage = $authPackage
                    RiskLevel = $riskLevel
                    RiskReason = $riskReason
                    HoursAgo = $hoursAgo
                    IsLocalIP = $isLocalIP
                    AccountType = if ($contextualInfo.IsComputerAccount) { "Computer" } 
                                 elseif ($contextualInfo.IsSystemAccount) { "System" }
                                 elseif ($contextualInfo.IsAdminAccount) { "Administrative" }
                                 else { "User" }
                    RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
                }
                
                if ($riskLevel -eq "High") {
                    Add-SecurityFinding -Category "Suspicious Logon" -Severity "High" -Description "High-risk logon detected: $riskReason" -Details @{
                        User = $targetUser
                        SourceIP = $sourceIP
                        LogonType = $logonType
                        Timestamp = $logonEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        Workstation = $workstation
                        AuthPackage = $authPackage
                        RiskFactors = $riskFactors -join ", "
                        AccountType = if ($contextualInfo.IsComputerAccount) { "Computer" } 
                                     elseif ($contextualInfo.IsSystemAccount) { "System" }
                                     elseif ($contextualInfo.IsAdminAccount) { "Administrative" }
                                     else { "User" }
                    }
                }
                
                elseif ($riskLevel -eq "Medium" -and ($contextualInfo.IsAdminAccount -or $contextualInfo.IsExplicitCredUse)) {
                    Add-SecurityFinding -Category "Administrative Access" -Severity "Medium" -Description "Administrative account activity: $riskReason" -Details @{
                        User = $targetUser
                        SourceIP = $sourceIP
                        LogonType = $logonType
                        Timestamp = $logonEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        RiskReason = $riskReason
                        AuthPackage = $authPackage
                    }
                }
                
            } catch {
                Write-EnhancedLog "Error parsing logon event: $_" "WARN"
                Add-ErrorDetail -Component "Logon Analysis" -Operation "Parse Event" -ErrorMessage $_.Exception.Message
            }
        }
        
        Write-EnhancedLog "Analyzed $($logonResults.Count) logon events" "SUCCESS"
        
        $riskSummary = $logonResults | Group-Object RiskLevel | Select-Object Name, Count
        foreach ($risk in $riskSummary) {
            $color = switch ($risk.Name) {
                "High" { "CRITICAL" }
                "Medium" { "WARN" }
                "Low" { "SUCCESS" }
            }
            Write-EnhancedLog "Risk Level '$($risk.Name)': $($risk.Count) events" $color
        }
        
        $externalIPs = $logonResults | Where-Object { -not $_.IsLocalIP -and $_.SourceIP -ne "Local" }
        if ($externalIPs.Count -gt 0) {
            Write-EnhancedLog "WARNING: $($externalIPs.Count) logons from external IP addresses detected!" "CRITICAL"
        }
        
        $adminLogons = $logonResults | Where-Object { $_.AccountType -eq "Administrative" }
        if ($adminLogons.Count -gt 0) {
            Write-EnhancedLog "INFO: $($adminLogons.Count) administrative account logons detected" "INFO"
        }
        
        return $logonResults
        
    } catch {
        Write-EnhancedLog "Error analyzing logon events: $_" "ERROR"
        Add-ErrorDetail -Component "Logon Analysis" -Operation "Get-WinEvent" -ErrorMessage $_.Exception.Message
        return @()
    }
}

function Get-EnhancedIISLogs {
    try {
        Write-EnhancedLog "Starting IIS logs analysis (Daily Window: $($script:Config.LogAnalysisStart) to $($script:Config.LogAnalysisEnd))..." "INFO"
        $results = @()
        
        $threatPatterns = @{
            "SQL Injection" = @{
                Pattern = "('|(select|union|insert|update|delete|drop|exec|xp_))"
                Severity = "Critical"
                Exclusions = @("__VIEWSTATE", "select option", "insert into temp")
            }
            "XSS Attempt" = @{
                Pattern = "(<script|javascript:|onload=|onerror=|alert\()"
                Severity = "High"
                Exclusions = @("application/javascript", "text/javascript")
            }
            "Command Injection" = @{
                Pattern = "(cmd\.exe|powershell\.exe|bash|sh)\s"
                Severity = "Critical"
                Exclusions = @()
            }
            "Path Traversal" = @{
                Pattern = "(\.\.\/|\.\.\\|%2e%2e)"
                Severity = "High"
                Exclusions = @("../css/", "../js/", "../images/")
            }
            "Web Shell Activity" = @{
                Pattern = "(eval\(|base64_decode|frombase64string|shell_exec)"
                Severity = "Critical"
                Exclusions = @()
            }
            "Malicious Scanners" = @{
                Pattern = "(sqlmap|nmap|burp|nikto|dirb|gobuster)"
                Severity = "Medium"
                Exclusions = @()
            }
        }
        
        $jwtApiExclusions = @(
            "accesstoken=eyJ",
            "AuthorizationService",
            "QNETCommerce",
            "/api/validatetoken",
            "/api/token",
            "__VIEWSTATE",
            "__EVENTVALIDATION"
        )
        
        $logs = Get-ChildItem -Recurse -Path $script:Config.LogPath -Include *.log -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -ge $script:Config.LogAnalysisStart -and $_.LastWriteTime -le $script:Config.LogAnalysisEnd }

        if ($logs.Count -eq 0) {
            Write-EnhancedLog "No IIS logs found in daily analysis window" "INFO"
            $script:htmlTabs.IISLogs += "<p class='success'>✅ No IIS logs found in the specified time window</p>"
            return
        }

        Write-EnhancedLog "Found $($logs.Count) IIS log files to analyze" "INFO"
        $totalExcluded = 0

        foreach ($log in $logs) {
            Write-EnhancedLog "Analyzing log: $($log.Name)" "INFO"
            
            foreach ($threatType in $threatPatterns.Keys) {
                $threatInfo = $threatPatterns[$threatType]
                $pattern = $threatInfo.Pattern
                $matches = Select-String -Path $log.FullName -Pattern $pattern -AllMatches -ErrorAction SilentlyContinue

                foreach ($match in $matches) {
                    $isJwtApiExcluded = $false
                    foreach ($jwtExclusion in $jwtApiExclusions) {
                        if ($match.Line -match [regex]::Escape($jwtExclusion)) {
                            $isJwtApiExcluded = $true
                            $totalExcluded++
                            Write-EnhancedLog "Excluding JWT/API pattern in $($log.Name) line $($match.LineNumber): $jwtExclusion" "INFO"
                            break
                        }
                    }
                    
                    if ($isJwtApiExcluded) {
                        continue
                    }
                    
                    $isExcluded = $false
                    foreach ($exclusion in $threatInfo.Exclusions) {
                        if ($match.Line -match [regex]::Escape($exclusion)) {
                            $isExcluded = $true
                            break
                        }
                    }
                    
                    if (-not $isExcluded) {
                        $logFields = $match.Line -split '\s+'
                        $clientIP = if ($logFields.Count -gt 8) { $logFields[8] } else { "Unknown" }
                        $httpMethod = if ($logFields.Count -gt 3) { $logFields[3] } else { "Unknown" }
                        $uri = if ($logFields.Count -gt 4) { $logFields[4] } else { "Unknown" }
                        $httpStatus = if ($logFields.Count -gt 5) { $logFields[5] } else { "Unknown" }
                        $userAgent = if ($logFields.Count -gt 9) { $logFields[9..($logFields.Count-1)] -join " " } else { "Unknown" }
                        
                        $results += [PSCustomObject]@{
                            Timestamp = (Get-Item $log.FullName).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            ThreatType = $threatType
                            Severity = $threatInfo.Severity
                            LogFile = $log.Name
                            LineNumber = $match.LineNumber
                            ClientIP = $clientIP
                            HttpMethod = $httpMethod
                            RequestURI = $uri
                            HttpStatus = $httpStatus
                            UserAgent = $userAgent
                            MatchedPattern = $pattern
                            Risk = $threatInfo.Severity
                        }
                        
                        Add-SecurityFinding -Category "Web Attack" -Severity $threatInfo.Severity -Description "Detected $threatType in IIS logs" -Details @{
                            LogFile = $log.Name
                            LineNumber = $match.LineNumber
                            ClientIP = $clientIP
                            HttpMethod = $httpMethod
                            RequestURI = $uri
                            ThreatType = $threatType
                            HttpStatus = $httpStatus
                        }
                    }
                }
            }
        }

        Write-EnhancedLog "IIS Log Analysis Complete - JWT/API exclusions: $totalExcluded" "INFO"

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) potential threats in IIS logs after filtering" "WARN"
            Add-EnhancedHtmlSection -TabName "IISLogs" -Data $results -AddSearch -RiskColumn "Risk"
        } else {
            Write-EnhancedLog "No suspicious patterns detected in IIS logs" "SUCCESS"
            $script:htmlTabs.IISLogs += "<p class='success'>✅ No suspicious patterns detected in IIS logs after applying filters</p>"
            if ($totalExcluded -gt 0) {
                $script:htmlTabs.IISLogs += "<p class='info'>ℹ️ Excluded $totalExcluded JWT/API related matches</p>"
            }
        }
    } catch {
        Write-EnhancedLog "Error in IIS log analysis: $_" "ERROR"
        $script:htmlTabs.IISLogs += "<p class='error'>❌ Error analyzing IIS logs: $_</p>"
    }
}

function Get-AdminUsers {
    try {
        Write-EnhancedLog "Analyzing administrative users..." "INFO"
        $results = Get-LocalGroupMember -Group "Administrators" | 
            Select-Object @{Name="AccountType";Expression={$_.GetType().Name}},
                         @{Name="Name";Expression={$_.Name}},
                         @{Name="SID";Expression={$_.SID}},
                         @{Name="Source";Expression={$_.Source}}
        
        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) administrative users" "INFO"
            Add-EnhancedHtmlSection -TabName "AdminUsers" -Data $results
        }
    } catch {
        Write-EnhancedLog "Error analyzing admin users: $_" "ERROR"
        $script:htmlTabs.AdminUsers += "<p class='error'>❌ Error: $_</p>"
    }
}

function Get-RecentLocalAccounts {
    try {
        Write-EnhancedLog "Checking for recently created local accounts (24-hour window)..." "INFO"
        $results = Get-LocalUser | Where-Object { $_.WhenCreated -ge $script:Config.SecurityEventWindow } |
            Select-Object Name, Enabled, LastLogon, WhenCreated, Description, SID
            
        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) recently created accounts" "WARN"
            foreach ($account in $results) {
                Add-SecurityFinding -Category "New User Account" -Severity "Medium" -Description "New local account created: $($account.Name)" -Details @{
                    AccountName = $account.Name
                    CreatedDate = $account.WhenCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Enabled = $account.Enabled
                    Description = $account.Description
                }
            }
            Add-EnhancedHtmlSection -TabName "LocalAccounts" -Data $results
        } else {
            Write-EnhancedLog "No recently created local accounts found" "SUCCESS"
            $script:htmlTabs.LocalAccounts += "<p class='success'>✅ No recently created local accounts</p>"
        }
    } catch {
        Write-EnhancedLog "Error checking local accounts: $_" "ERROR"
        $script:htmlTabs.LocalAccounts += "<p class='error'>❌ Error: $_</p>"
    }
}

function Get-RecentFiles {
    try {
        Write-EnhancedLog "Scanning for recently modified files (25-hour window)..." "INFO"
        $results = @()
        $suspiciousExtensions = @('.asp', '.aspx', '.php', '.jsp', '.exe', '.bat', '.cmd', '.ps1', '.vbs')

        foreach ($dir in $script:Config.DirsToCheck) {
            if (Test-Path $dir) {
                Write-EnhancedLog "Scanning directory: $dir" "INFO"
                $files = Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $script:Config.FileModificationWindow -and -not $_.PSIsContainer } |
                    Select-Object FullName, LastWriteTime, Length, Extension, @{Name="Directory";Expression={$dir}}

                foreach ($file in $files) {
                    $suspicious = $file.Extension -in $suspiciousExtensions
                    $severity = if ($suspicious) { "Medium" } else { "Low" }
                    $hoursOld = [math]::Round(((Get-Date) - $file.LastWriteTime).TotalHours, 2)
                    
                    $results += $file | Select-Object *, 
                        @{Name="Suspicious";Expression={$suspicious}}, 
                        @{Name="Severity";Expression={$severity}},
                        @{Name="HoursOld";Expression={$hoursOld}}
                    
                    if ($suspicious) {
                        Add-SecurityFinding -Category "Suspicious File" -Severity $severity -Description "Recently modified suspicious file: $($file.FullName)" -Details @{
                            FilePath = $file.FullName
                            LastModified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            Extension = $file.Extension
                            HoursOld = $hoursOld
                            FileSize = $file.Length
                        }
                    }
                }
            }
        }

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) recently modified files" "INFO"
            Add-EnhancedHtmlSection -TabName "RecentFiles" -Data $results -AddSearch -RiskColumn "Severity"
        } else {
            $script:htmlTabs.RecentFiles += "<p class='success'>✅ No recently modified files in monitored directories</p>"
        }
    } catch {
        Write-EnhancedLog "Error scanning recent files: $_" "ERROR"
        $script:htmlTabs.RecentFiles += "<p class='error'>❌ Error: $_</p>"
    }
}

function Detect-WebShells {
    try {
        Write-EnhancedLog "Scanning for web shells with enhanced detection..." "INFO"
        $results = @()
        
        $webShellPatterns = @{
            "Command Execution" = @{
                Patterns = @(
                    'shell_exec\s*\(',           
                    'system\s*\(',               
                    'exec\s*\(',                 
                    'passthru\s*\(',             
                    'popen\s*\(',                
                    'proc_open\s*\(',            
                    'Process\.Start\s*\(',       
                    'cmd\.exe.*?/c',             
                    'powershell\.exe.*?-c',      
                    'CreateProcess\s*\(',        
                    'WScript\.Shell.*?Run',      
                    'Server\.CreateObject.*?WScript\.Shell'  
                )
                Severity = "Critical"
                Description = "Direct system command execution capability"
            }
            
            "Code Evaluation" = @{
                Patterns = @(
                    'eval\s*\(',                 
                    'assert\s*\(',               
                    'create_function\s*\(',      
                    'call_user_func\s*\(',       
                    'ReflectionClass.*?newInstance',  
                    'Activator\.CreateInstance',      
                    'ScriptEngine.*?Eval',            
                    'ExecuteGlobal\s*\('              
                )
                Severity = "Critical"
                Description = "Dynamic code evaluation - classic web shell technique"
            }
            
            "Obfuscation Techniques" = @{
                Patterns = @(
                    'base64_decode\s*\(',        
                    'FromBase64String\s*\(',     
                    'gzinflate\s*\(',            
                    'str_rot13\s*\(',            
                    'chr\s*\(\s*\d+\s*\)',       
                    'char\s*\(\s*\d+\s*\)',      
                    'pack\s*\(\s*["''][H\\*]',   
                    'unhex\s*\(',                
                    'unescape\s*\(',             
                    'String\.fromCharCode'       
                )
                Severity = "High"
                Description = "Code obfuscation techniques commonly used in web shells"
            }
            
            "File Operations" = @{
                Patterns = @(
                    'file_put_contents\s*\(',    
                    'fwrite\s*\(',               
                    'fputs\s*\(',                
                    'file_get_contents\s*\(',    
                    'readfile\s*\(',             
                    'include\s*\(\s*["''][^"'']*\.txt', 
                    'require\s*\(\s*["''][^"'']*\.txt', 
                    'FileStream.*?Write',        
                    'File\.WriteAllText',        
                    'StreamWriter.*?Write',      
                    'Response\.WriteFile'        
                )
                Severity = "High"
                Description = "Suspicious file operations that could modify system files"
            }
            
            "Network Operations" = @{
                Patterns = @(
                    'curl_exec\s*\(',            
                    'file_get_contents\s*\(\s*["'']https?://', 
                    'fsockopen\s*\(',            
                    'socket_connect\s*\(',       
                    'WebClient.*?Download',      
                    'HttpWebRequest.*?GetResponse', 
                    'XMLHttpRequest',            
                    'fetch\s*\(',                
                    'wget\s+',                   
                    'curl\s+'                    
                )
                Severity = "Medium"
                Description = "Network operations that could exfiltrate data or download malware"
            }
            
            "Suspicious Input Handling" = @{
                Patterns = @(
                    '_POST\s*\[\s*["''][^"'']*cmd',     
                    '_GET\s*\[\s*["''][^"'']*cmd',      
                    '_REQUEST\s*\[\s*["''][^"'']*exec', 
                    'Request\s*\[\s*["''][^"'']*cmd',   
                    'Request\.Form\s*\[\s*["''][^"'']*cmd', 
                    'Request\.QueryString\s*\[\s*["''][^"'']*cmd', 
                    'HttpContext\.Current\.Request.*?cmd', 
                    '\$_[A-Z]+\[["''][^"'']*\]\s*\)\s*;' 
                )
                Severity = "High"  
                Description = "Input parameters commonly used for command injection"
            }
        }
        
        $legitimatePatterns = @(
            'System\.Web\.HttpContext',      
            'System\.IO\.File',              
            'System\.Diagnostics\.Debug',    
            'System\.Environment',           
            'System\.Configuration',         
            'System\.Text\.Encoding',        
            'System\.Security',              
            'Microsoft\.Win32\.Registry',    
            'HttpContext\.Current\.Server',  
            'Server\.CreateObject\("Scripting\.FileSystemObject"\)', 
            'eval\s*\(\s*["'']return\s+false', 
            'base64_decode\s*\(\s*["''][A-Za-z0-9+/=]{8,}\s*["'']', 
            'chr\s*\(\s*ord\s*\(',           
            'System\.Convert\.FromBase64String\s*\(\s*["''][A-Za-z0-9+/=]+["'']' 
        )
        
        $files = Get-ChildItem -Path $script:Config.WebRoot -Recurse -Include "*.aspx", "*.asp", "*.php", "*.jsp", "*.ashx", "*.asmx" -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -lt $script:Config.MaxFileSize }
        
        Write-EnhancedLog "Scanning $($files.Count) web files for threats..." "INFO"

        foreach ($file in $files) {
            try {
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $fileThreats = @()
                    
                    foreach ($category in $webShellPatterns.Keys) {
                        $categoryInfo = $webShellPatterns[$category]
                        
                        foreach ($pattern in $categoryInfo.Patterns) {
                            if ($content -match $pattern) {
                                $isLegitimate = $false
                                foreach ($legitPattern in $legitimatePatterns) {
                                    if ($content -match $legitPattern) {
                                        $matchContext = ($content | Select-String -Pattern $pattern -Context 2, 2).Context
                                        if ($matchContext -and ($matchContext -join " " -match $legitPattern)) {
                                            $isLegitimate = $true
                                            Write-EnhancedLog "Excluding legitimate pattern in $($file.Name): $legitPattern" "INFO"
                                            break
                                        }
                                    }
                                }
                                
                                if (-not $isLegitimate) {
                                    $fileThreats += [PSCustomObject]@{
                                        Category = $category
                                        Pattern = $pattern
                                        Severity = $categoryInfo.Severity
                                        Description = $categoryInfo.Description
                                    }
                                    
                                    Add-SecurityFinding -Category "Web Shell" -Severity $categoryInfo.Severity -Description "$category detected in web file" -Details @{
                                        FilePath = $file.FullName
                                        Category = $category
                                        Pattern = $pattern
                                        FileSize = $file.Length
                                        LastModified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                                        Description = $categoryInfo.Description
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($fileThreats.Count -gt 0) {
                        $highestSeverity = "Low"
                        $threatCategories = ($fileThreats.Category | Sort-Object -Unique) -join ", "
                        $detectedPatterns = ($fileThreats.Pattern | Sort-Object -Unique) -join "; "
                        
                        foreach ($threat in $fileThreats) {
                            if ($threat.Severity -eq "Critical") { $highestSeverity = "Critical"; break }
                            elseif ($threat.Severity -eq "High" -and $highestSeverity -ne "Critical") { $highestSeverity = "High" }
                            elseif ($threat.Severity -eq "Medium" -and $highestSeverity -notin @("Critical", "High")) { $highestSeverity = "Medium" }
                        }
                        
                        $results += [PSCustomObject]@{
                            FilePath = $file.FullName
                            LastWriteTime = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            FileSizeBytes = $file.Length
                            ThreatCategories = $threatCategories
                            DetectedPatterns = $detectedPatterns
                            Severity = $highestSeverity
                            Risk = $highestSeverity
                            ThreatCount = $fileThreats.Count
                            FileExtension = $file.Extension
                        }
                    }
                }
            } catch {
                Write-EnhancedLog "Could not scan file: $($file.FullName) - $_" "WARN"
                Add-ErrorDetail -Component "Web Shell Detection" -Operation "File Scan" -ErrorMessage $_.Exception.Message -FileName $file.FullName
            }
        }

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) files with potential web shell characteristics" "WARN"
            $criticalCount = ($results | Where-Object { $_.Severity -eq "Critical" }).Count
            $highCount = ($results | Where-Object { $_.Severity -eq "High" }).Count
            
            if ($criticalCount -gt 0) {
                Write-EnhancedLog "$criticalCount files with CRITICAL threats detected!" "CRITICAL"
            }
            if ($highCount -gt 0) {
                Write-EnhancedLog "$highCount files with HIGH risk threats detected!" "ERROR"
            }
            
            Add-EnhancedHtmlSection -TabName "WebShells" -Data $results -AddSearch -RiskColumn "Risk"
        } else {
            Write-EnhancedLog "No web shells detected after enhanced filtering" "SUCCESS"
            $script:htmlTabs.WebShells += "<div style='text-align: center; padding: 40px; color: #28a745;'>"
            $script:htmlTabs.WebShells += "<div style='font-size: 64px; margin-bottom: 20px;'>🛡️</div>"
            $script:htmlTabs.WebShells += "<h3>No Web Shells Detected</h3>"
            $script:htmlTabs.WebShells += "<p>Enhanced scanning found no malicious web files after applying contextual filtering.</p>"
            $script:htmlTabs.WebShells += "</div>"
        }
        
    } catch {
        Write-EnhancedLog "Error in enhanced web shell detection: $_" "ERROR"
        Add-ErrorDetail -Component "Web Shell Detection" -Operation "Enhanced Scan" -ErrorMessage $_.Exception.Message
        $script:htmlTabs.WebShells += "<p class='error'>❌ Error in enhanced web shell detection: $_</p>"
    }
}

function Get-EnhancedProcessAnalysis {
    try {
        Write-EnhancedLog "Performing enhanced process analysis..." "INFO"
        $results = @()
        $suspiciousPatterns = @(
            'cmd\.exe.*powershell',
            'powershell.*-enc',
            'powershell.*-hidden',
            'powershell.*downloadstring',
            'certutil.*-decode',
            'regsvr32.*scrobj\.dll',
            'mshta.*http',
            'wmic.*process.*call.*create'
        )
        
        $allProcesses = Get-CimInstance Win32_Process
        $processStats = @{}
        
        foreach ($proc in $allProcesses) {
            if ($processStats.ContainsKey($proc.Name)) {
                $processStats[$proc.Name]++
            } else {
                $processStats[$proc.Name] = 1
            }
            
            $suspicious = $false
            $reason = ""
            
            if ($proc.CommandLine) {
                foreach ($pattern in $suspiciousPatterns) {
                    if ($proc.CommandLine -match $pattern) {
                        $suspicious = $true
                        $reason = "Suspicious command pattern: $pattern"
                        break
                    }
                }
            }
            
            if ($proc.ExecutablePath -and $proc.ExecutablePath -match "(temp|downloads|appdata)" -and $proc.Name -match "\.(exe|com|scr|bat|cmd)$") {
                $suspicious = $true
                $reason = "Process running from suspicious location"
            }
            
            if ($suspicious -or $proc.Name -match "(cmd|powershell|wmic|certutil|regsvr32|mshta)") {
                $owner = try { $proc.GetOwner().User } catch { 'Unknown' }
                $parentProc = $allProcesses | Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
                
                $severity = if ($suspicious) { "High" } else { "Medium" }
                
                $cmdLine = if ($proc.CommandLine -and $proc.CommandLine.Length -gt 100) {
                    $proc.CommandLine.Substring(0, 97) + "..."
                } else {
                    $proc.CommandLine
                }
                
                $results += [PSCustomObject]@{
                    ProcessId = $proc.ProcessId
                    Name = $proc.Name
                    CommandLine = $cmdLine
                    Owner = $owner
                    ParentPID = $proc.ParentProcessId
                    ParentName = if ($parentProc) { $parentProc.Name } else { 'N/A' }
                    ExecutablePath = $proc.ExecutablePath
                    CreationDate = if ($proc.CreationDate) { $proc.CreationDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unknown' }
                    Severity = $severity
                    Reason = $reason
                    Suspicious = $suspicious
                }
                
                if ($suspicious) {
                    Add-SecurityFinding -Category "Suspicious Process" -Severity $severity -Description $reason -Details @{
                        ProcessName = $proc.Name
                        ProcessId = $proc.ProcessId
                        CommandLine = $proc.CommandLine
                        Owner = $owner
                        ExecutablePath = $proc.ExecutablePath
                    }
                }
            }
        }
        
        foreach ($processName in $processStats.Keys) {
            if ($processStats[$processName] -gt 10 -and $processName -match "(svchost|dllhost|rundll32)") {
                Write-EnhancedLog "Potential process anomaly: $processName has $($processStats[$processName]) instances" "WARN"
            }
        }
        
        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) processes of interest" "INFO"
            Add-EnhancedHtmlSection -TabName "ProcessAnalysis" -Data $results -AddSearch -RiskColumn "Severity"
        } else {
            Write-EnhancedLog "No suspicious processes detected" "SUCCESS"
            $script:htmlTabs.ProcessAnalysis += "<p class='success'>✅ No suspicious processes detected</p>"
        }
        
    } catch {
        Write-EnhancedLog "Error in process analysis: $_" "ERROR"
        $script:htmlTabs.ProcessAnalysis += "<p class='error'>❌ Error in process analysis: $_</p>"
    }
}

function Get-NetworkConnections {
    try {
        Write-EnhancedLog "Analyzing network connections..." "INFO"
        $results = @()
        $netstatOutput = netstat -ano
        $suspiciousPorts = @(4444, 1337, 8081, 9001, 6666)

        foreach ($line in $netstatOutput) {
            if ($line -match '^\s*(TCP|UDP)\s+([\[\]\.:0-9a-fA-F]+)\s+([\[\]\.:0-9a-fA-F]+)\s+(\w+)\s+(\d+)\s*$') {
                $protocol = $matches[1]
                $localAddress = $matches[2]
                $remoteAddress = $matches[3]
                $state = $matches[4]
                $processId = [int]$matches[5]

                if ($state -eq "ESTABLISHED") {
                    $remotePort = ($remoteAddress -split ':')[-1]
                    $suspicious = $remotePort -in $suspiciousPorts
                    $severity = if ($suspicious) { "High" } else { "Low" }
                    
                    $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    
                    $results += [PSCustomObject]@{
                        Protocol = $protocol
                        LocalAddress = $localAddress
                        RemoteAddress = $remoteAddress
                        State = $state
                        ProcessId = $processId
                        ProcessName = if ($proc) { $proc.ProcessName } else { 'Unknown' }
                        Severity = $severity
                        Suspicious = $suspicious
                    }
                    
                    if ($suspicious) {
                        Add-SecurityFinding -Category "Suspicious Network" -Severity $severity -Description "Connection to suspicious port: $remotePort" -Details @{
                            RemoteAddress = $remoteAddress
                            ProcessId = $processId
                            ProcessName = if ($proc) { $proc.ProcessName } else { 'Unknown' }
                            Protocol = $protocol
                            LocalAddress = $localAddress
                        }
                    }
                }
            }
        }

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) established connections" "INFO"
            Add-EnhancedHtmlSection -TabName "NetworkConnections" -Data $results -AddSearch -RiskColumn "Severity"
        } else {
            $script:htmlTabs.NetworkConnections += "<p class='success'>✅ No established network connections</p>"
        }
    } catch {
        Write-EnhancedLog "Error analyzing network connections: $_" "ERROR"
        $script:htmlTabs.NetworkConnections += "<p class='error'>❌ Error: $_</p>"
    }
}

function Generate-FileHashes {
    try {
        Write-EnhancedLog "Generating file hashes for integrity monitoring..." "INFO"
        $results = @()
        $hashCount = 0

        foreach ($dir in $script:Config.DirsToCheck) {
            if (Test-Path $dir) {
                $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -le 50MB } | Select-Object -First 100

                foreach ($file in $files) {
                    try {
                        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
                        $results += [PSCustomObject]@{
                            Path = $file.FullName
                            Hash = $hash.Hash
                            Algorithm = $hash.Algorithm
                            LastWriteTime = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            FileSizeBytes = $file.Length
                        }
                        $hashCount++
                    } catch {
                        Write-EnhancedLog "Failed to hash: $($file.FullName)" "WARN"
                    }
                }
            }
        }

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Generated $hashCount file hashes" "SUCCESS"
            Add-EnhancedHtmlSection -TabName "FileHashes" -Data $results -AddSearch
        } else {
            $script:htmlTabs.FileHashes += "<p class='warning'>⚠️ No files could be hashed</p>"
        }
    } catch {
        Write-EnhancedLog "Error generating file hashes: $_" "ERROR"
        $script:htmlTabs.FileHashes += "<p class='error'>❌ Error: $_</p>"
    }
}

function Get-LogTamperingEvents {
    try {
        Write-EnhancedLog "Checking for log tampering events (26-hour critical window)..." "INFO"
        $results = @()
        $tamperingEventIds = @{
            "Security" = @(1102, 4719, 4906, 4907)
            "System" = @(104)
        }

        $isDomainJoined = $false
        $domainName = "WORKGROUP"
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($computerSystem.PartOfDomain) {
                $isDomainJoined = $true
                $domainName = $computerSystem.Domain
                Write-EnhancedLog "System is domain-joined to: $domainName" "INFO"
            } else {
                Write-EnhancedLog "System is in workgroup: $($computerSystem.Workgroup)" "INFO"
            }
        } catch {
            Write-EnhancedLog "Could not determine domain membership status" "WARN"
        }

        foreach ($logName in $tamperingEventIds.Keys) {
            foreach ($eventId in $tamperingEventIds[$logName]) {
                try {
                    $events = Get-WinEvent -FilterHashtable @{
                        LogName = $logName
                        Id = $eventId
                        StartTime = $script:Config.CriticalEventWindow
                        EndTime = $script:Config.LogAnalysisEnd
                    } -ErrorAction Stop

                    foreach ($event in $events) {
                        $contextAnalysis = Analyze-EventContext -Event $event -IsDomainJoined $isDomainJoined -EventId $eventId
                        
                        $results += [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                            EventID = $event.Id
                            LogName = $event.LogName
                            Computer = $event.MachineName
                            Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                            Severity = $contextAnalysis.Severity
                            Context = $contextAnalysis.Context
                            Likelihood = $contextAnalysis.Likelihood
                            UserAccount = $contextAnalysis.UserAccount
                            BusinessHours = $contextAnalysis.BusinessHours
                            Domain = $domainName
                            IsDomainJoined = $isDomainJoined
                            RiskFactors = $contextAnalysis.RiskFactors
                            RecommendedAction = $contextAnalysis.RecommendedAction
                        }
                        
                        Add-SecurityFinding -Category "Log Tampering" -Severity $contextAnalysis.Severity -Description $contextAnalysis.Description -Details @{
                            EventId = $event.Id
                            LogName = $event.LogName
                            TimeCreated = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                            Computer = $event.MachineName
                            Context = $contextAnalysis.Context
                            Likelihood = $contextAnalysis.Likelihood
                            UserAccount = $contextAnalysis.UserAccount
                            BusinessHours = $contextAnalysis.BusinessHours
                            Domain = $domainName
                            RiskFactors = $contextAnalysis.RiskFactors
                        }
                    }
                } catch {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Write-EnhancedLog "Error checking event ID $eventId in $logName`: $_" "WARN"
                        Add-ErrorDetail -Component "Log Tampering Detection" -Operation "Get-WinEvent" -ErrorMessage $_.Exception.Message
                    }
                }
            }
        }

        if ($results.Count -gt 0) {
            Write-EnhancedLog "Found $($results.Count) log tampering events" "INFO"
            
            $contextSummary = $results | Group-Object Context | Select-Object Name, Count
            foreach ($context in $contextSummary) {
                $logLevel = switch ($context.Name) {
                    "Malicious Activity" { "CRITICAL" }
                    "Suspicious Activity" { "ERROR" }
                    "System Initiated" { "INFO" }
                    "Routine Administration" { "SUCCESS" }
                    default { "WARN" }
                }
                Write-EnhancedLog "$($context.Name): $($context.Count) events" $logLevel
            }
            
            $criticalEvents = ($results | Where-Object { $_.Severity -eq "Critical" }).Count
            $highEvents = ($results | Where-Object { $_.Severity -eq "High" }).Count
            
            if ($criticalEvents -gt 0) {
                Write-EnhancedLog "ALERT: $criticalEvents critical tampering events require immediate investigation!" "CRITICAL"
            }
            if ($highEvents -gt 0) {
                Write-EnhancedLog "WARNING: $highEvents high-priority tampering events detected" "ERROR"
            }
            
            Add-EnhancedHtmlSection -TabName "LogTampering" -Data $results -AddSearch -RiskColumn "Severity"
        } else {
            Write-EnhancedLog "No log tampering events detected" "SUCCESS"
            $script:htmlTabs.LogTampering += "<div style='text-align: center; padding: 40px; color: #28a745;'>"
            $script:htmlTabs.LogTampering += "<div style='font-size: 64px; margin-bottom: 20px;'>✅</div>"
            $script:htmlTabs.LogTampering += "<h3>No Log Tampering Events Detected</h3>"
            $script:htmlTabs.LogTampering += "<p>No evidence of log manipulation or audit policy tampering found in the critical window.</p>"
            $script:htmlTabs.LogTampering += "</div>"
        }
    } catch {
        Write-EnhancedLog "Error checking log tampering: $_" "ERROR"
        Add-ErrorDetail -Component "Log Tampering Detection" -Operation "Enhanced Analysis" -ErrorMessage $_.Exception.Message
        $script:htmlTabs.LogTampering += "<p class='error'>❌ Error in log tampering detection: $_</p>"
    }
}

function Analyze-EventContext {
    param(
        [Parameter(Mandatory=$true)]$Event,
        [Parameter(Mandatory=$true)][bool]$IsDomainJoined,
        [Parameter(Mandatory=$true)][int]$EventId
    )
    
    $analysis = @{
        Severity = "Critical"
        Context = "Unknown"
        Likelihood = "High"
        UserAccount = "Unknown"
        BusinessHours = $false
        RiskFactors = @()
        RecommendedAction = "Immediate investigation required"
        Description = "Log tampering event detected"
    }
    
    try {
        $eventXml = [xml]$Event.ToXml()
        $eventData = $eventXml.Event.EventData.Data
        $userSid = $null
        $userName = $null
        
        switch ($EventId) {
            1102 { 
                $subjectNode = $eventXml.Event.UserData.LogFileCleared
                if ($subjectNode) {
                    $userName = $subjectNode.SubjectUserName
                }
            }
            104 { 
                $subjectNode = $eventXml.Event.UserData.LogFileCleared
                if ($subjectNode) {
                    $userName = $subjectNode.SubjectUserName
                }
            }
            4719 { 
                $userSid = ($eventData | Where-Object { $_.Name -eq "SubjectUserSid" }).'#text'
                $userName = ($eventData | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
            }
            { $_ -in @(4906, 4907) } { 
                $userSid = ($eventData | Where-Object { $_.Name -eq "ModifyingUser" }).'#text'
                if (-not $userSid) {
                    $userName = ($eventData | Where-Object { $_.Name -eq "ModifyingApplication" }).'#text'
                }
            }
        }
        
        $eventTime = $Event.TimeCreated
        $analysis.BusinessHours = (
            $eventTime.DayOfWeek -notin @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday) -and
            $eventTime.Hour -ge 8 -and 
            $eventTime.Hour -le 18
        )
        
        $analysis.UserAccount = if ($userName) { $userName } elseif ($userSid) { $userSid } else { "Unknown" }
        
        # Account type analysis - streamlined
        $isSystemAccount = (
            $userSid -eq "S-1-5-18" -or                                    # SYSTEM
            $userSid -eq "S-1-5-19" -or                                    # LOCAL SERVICE  
            $userSid -eq "S-1-5-20" -or                                    # NETWORK SERVICE
            $userName -match "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$" -or # Named system accounts
            $userName -match '\$'                                          # Computer accounts end with $
        )
        
        $isBuiltinAdmin = (
            $userSid -eq "S-1-5-32-544" -or                               
            $userName -match "^(Administrator|Admin)$"                     
        )
        
        if ($EventId -in @(1102, 104)) {
            if ($isSystemAccount) {
                $analysis.Context = "System Initiated"
                $analysis.Severity = "Medium"
                $analysis.Likelihood = "Low"
                $analysis.Description = "System-initiated log clearing detected"
                $analysis.RecommendedAction = "Verify with system administrator - may be routine maintenance"
            } elseif ($isBuiltinAdmin) {
                $analysis.Context = "Administrative Activity"
                $analysis.Severity = "High"
                $analysis.Likelihood = "Medium"
                $analysis.Description = "Administrator manually cleared logs"
                $analysis.RecommendedAction = "Verify legitimate administrative activity - document justification"
            } else {
                $analysis.Context = "Malicious Activity"
                $analysis.Severity = "Critical"
                $analysis.Likelihood = "High"
                $analysis.Description = "Manual log clearing detected - possible evidence tampering"
                $analysis.RecommendedAction = "Immediate forensic investigation required"
            }
        } elseif ($EventId -eq 4719) {
            if ($isSystemAccount -and $IsDomainJoined -and $analysis.BusinessHours) {
                try {
                    $simultaneousEvents = Get-WinEvent -FilterHashtable @{
                        LogName = "Security"
                        Id = 4719
                        StartTime = $Event.TimeCreated.AddSeconds(-30)
                        EndTime = $Event.TimeCreated.AddSeconds(30)
                    } -ErrorAction SilentlyContinue
                    
                    $simultaneousCount = if ($simultaneousEvents) { $simultaneousEvents.Count } else { 1 }
                } catch {
                    $simultaneousCount = 1
                }
                
                if ($simultaneousCount -gt 3) {
                    $analysis.Context = "Routine Administration"
                    $analysis.Severity = "Low"
                    $analysis.Likelihood = "Very Low"
                    $analysis.Description = "Group Policy audit policy refresh detected ($simultaneousCount simultaneous events)"
                    $analysis.RecommendedAction = "Monitor for patterns - likely routine Group Policy application"
                } else {
                    $analysis.Context = "System Initiated"
                    $analysis.Severity = "Medium"
                    $analysis.Likelihood = "Low"
                    $analysis.Description = "System-initiated audit policy change"
                    $analysis.RecommendedAction = "Verify system changes with administrator"
                }
            } elseif ($isSystemAccount -and -not $analysis.BusinessHours) {
                $analysis.Context = "Suspicious Activity"
                $analysis.Severity = "High"
                $analysis.Likelihood = "Medium"
                $analysis.Description = "Off-hours system audit policy change"
                $analysis.RecommendedAction = "Investigate automated processes or scheduled tasks"
            } elseif (-not $isSystemAccount) {
                if ($isBuiltinAdmin) {
                    $analysis.Context = "Suspicious Activity"
                    $analysis.Severity = "High"
                    $analysis.Likelihood = "Medium"
                    $analysis.Description = "Administrator account audit policy manipulation"
                    $analysis.RecommendedAction = "Verify administrative activity - may be legitimate but requires validation"
                } else {
                    $analysis.Context = "Malicious Activity"
                    $analysis.Severity = "Critical"
                    $analysis.Likelihood = "High"
                    $analysis.Description = "Manual audit policy manipulation detected"
                    $analysis.RecommendedAction = "Immediate investigation - possible attack preparation"
                }
            } else {
                $analysis.Context = "System Initiated"
                $analysis.Severity = "Medium"
                $analysis.Likelihood = "Low"
                $analysis.Description = "System audit policy change"
                $analysis.RecommendedAction = "Review system configuration changes"
            }
        } elseif ($EventId -in @(4906, 4907)) {
            if ($isSystemAccount -and $analysis.BusinessHours) {
                $analysis.Context = "System Initiated"
                $analysis.Severity = "Low"
                $analysis.Likelihood = "Low"
                $analysis.Description = "System-initiated firewall policy change"
                $analysis.RecommendedAction = "Verify with network administrator"
            } elseif ($isBuiltinAdmin -and $analysis.BusinessHours) {
                $analysis.Context = "Administrative Activity"
                $analysis.Severity = "Medium"
                $analysis.Likelihood = "Low"
                $analysis.Description = "Administrator firewall policy change"
                $analysis.RecommendedAction = "Verify legitimate administrative activity"
            } else {
                $analysis.Context = "Suspicious Activity"
                $analysis.Severity = "High"
                $analysis.Likelihood = "Medium"
                $analysis.Description = "Firewall policy modification detected"
                $analysis.RecommendedAction = "Review firewall rules and network security"
            }
        }
        
        $riskFactors = @()
        if (-not $analysis.BusinessHours) { $riskFactors += "Off-hours timing" }
        if (-not $isSystemAccount -and -not $isBuiltinAdmin) { $riskFactors += "Non-administrative user" }
        if ($isBuiltinAdmin) { $riskFactors += "Built-in administrator account" }
        if (-not $IsDomainJoined) { $riskFactors += "Standalone system" }
        if ($EventId -in @(1102, 104)) { $riskFactors += "Log destruction" }
        
        $analysis.RiskFactors = $riskFactors
        
        if ($IsDomainJoined -and $analysis.Severity -eq "Low") {
            $analysis.Description += " (Domain-joined system)"
        }
        
    } catch {
        Write-EnhancedLog "Error analyzing event context: $_" "WARN"
    }
    
    return $analysis
}

function Get-SystemHealthCheck {
    try {
        Write-EnhancedLog "Performing system health assessment..." "INFO"
        $healthChecks = @()
        
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($disk in $disks) {
            $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
            $status = if ($freeSpacePercent -lt 10) { "Critical" } 
                     elseif ($freeSpacePercent -lt 20) { "Warning" } 
                     else { "Good" }
            
            $healthChecks += [PSCustomObject]@{
                Component = "Disk Space"
                Item = "Drive $($disk.DeviceID)"
                Status = $status
                Value = "$freeSpacePercent% free"
                Details = "$([math]::Round($disk.FreeSpace/1GB, 2)) GB free of $([math]::Round($disk.Size/1GB, 2)) GB"
            }
        }
        
        $memory = Get-WmiObject -Class Win32_OperatingSystem
        $memoryUsagePercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
        $memoryStatus = if ($memoryUsagePercent -gt 90) { "Critical" } 
                       elseif ($memoryUsagePercent -gt 80) { "Warning" } 
                       else { "Good" }
        
        $healthChecks += [PSCustomObject]@{
            Component = "Memory"
            Item = "Physical Memory"
            Status = $memoryStatus
            Value = "$memoryUsagePercent% used"
            Details = "$([math]::Round(($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory)/1MB, 2)) MB used of $([math]::Round($memory.TotalVisibleMemorySize/1MB, 2)) MB"
        }
        
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
            
            $updateStatus = if ($pendingUpdates -gt 10) { "Critical" } 
                           elseif ($pendingUpdates -gt 5) { "Warning" } 
                           else { "Good" }
            
            $healthChecks += [PSCustomObject]@{
                Component = "Windows Updates"
                Item = "Pending Updates"
                Status = $updateStatus
                Value = "$pendingUpdates pending"
                Details = "Check Windows Update for security patches"
            }
        } catch {
            $healthChecks += [PSCustomObject]@{
                Component = "Windows Updates"
                Item = "Update Check"
                Status = "Warning"
                Value = "Unable to check"
                Details = "Could not access Windows Update service"
            }
        }
        
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $defenderStatus = if (-not $defender.RealTimeProtectionEnabled) { "Critical" }
                             elseif ($defender.AntivirusSignatureAge -gt 7) { "Warning" }
                             else { "Good" }
            
            $healthChecks += [PSCustomObject]@{
                Component = "Windows Defender"
                Item = "Real-time Protection"
                Status = $defenderStatus
                Value = if ($defender.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
                Details = "Signature age: $($defender.AntivirusSignatureAge) days"
            }
        } catch {
            $healthChecks += [PSCustomObject]@{
                Component = "Windows Defender"
                Item = "Status Check"
                Status = "Warning"
                Value = "Unable to check"
                Details = "Windows Defender module not available"
            }
        }
        
        Add-EnhancedHtmlSection -TabName "SystemHealth" -Data $healthChecks
        
        $criticalIssues = ($healthChecks | Where-Object { $_.Status -eq "Critical" }).Count
        if ($criticalIssues -gt 0) {
            Write-EnhancedLog "Found $criticalIssues critical system health issues" "CRITICAL"
        } else {
            Write-EnhancedLog "System health check completed - no critical issues" "SUCCESS"
        }
        
    } catch {
        Write-EnhancedLog "Error in system health check: $_" "ERROR"
        $script:htmlTabs.SystemHealth += "<p class='error'>❌ Error performing system health check: $_</p>"
    }
}

# ==============================================================================
# 5. HTML REPORT GENERATION FUNCTIONS
# ==============================================================================

function Add-EnhancedHtmlSection {
    param(
        [string]$TabName,
        [object]$Data,
        [string]$EmptyMessage = "No items found",
        [switch]$AddSearch,
        [string]$RiskColumn = $null
    )
    
    if ($Data -and $Data.Count -gt 0) {
        $tableId = "$TabName" + "Table"
        $searchId = "$TabName" + "Search"
        
        if ($AddSearch) {
            $script:htmlTabs[$TabName] += "<input type='text' id='$searchId' class='search-box' placeholder='🔍 Search $TabName...' onkeyup='searchTable(`"$searchId`", `"$tableId`")'>"
        }
        
        $script:htmlTabs[$TabName] += "<div class='table-container'>"
        $htmlTable = "<table id='$tableId'><tr>"
        $properties = $Data[0].PSObject.Properties.Name
        
        foreach ($prop in $properties) {
            $htmlTable += "<th>$prop</th>"
        }
        $htmlTable += "</tr>"
        
        foreach ($item in $Data) {
            $rowClass = ""
            if ($item.Severity -eq "Critical" -or $item.Risk -eq "High" -or $item.RiskLevel -eq "High") { $rowClass = "class='critical'" }
            elseif ($item.Severity -eq "High" -or $item.Suspicious -eq $true -or $item.RiskLevel -eq "Medium") { $rowClass = "class='suspicious'" }
            elseif ($item.Severity -eq "Medium" -or $item.Status -eq "Warning" -or $item.RiskLevel -eq "Low") { $rowClass = "class='warning'" }
            elseif ($item.Severity -eq "Low") { $rowClass = "class='success'" }
            
            $htmlTable += "<tr $rowClass>"
            foreach ($prop in $properties) {
                $value = $item.$prop
                
                if ($value -and $value.ToString().Length -gt 100) {
                    $truncatedValue = $value.ToString().Substring(0, 97) + "..."
                    $value = "<div class='truncate' title='$($value.ToString().Replace("'", "&apos;"))'>$truncatedValue</div>"
                }
                
                if ($prop -eq $RiskColumn -and $value) {
                    $riskClass = switch ($value) {
                        "High" { "risk-high" }
                        "Medium" { "risk-medium" }
                        "Low" { "risk-low" }
                        default { "" }
                    }
                    if ($riskClass) {
                        $value = "<span class='risk-indicator $riskClass'>$value</span>"
                    }
                }
                $htmlTable += "<td>$value</td>"
            }
            $htmlTable += "</tr>"
        }
        
        $htmlTable += "</table>"
        $script:htmlTabs[$TabName] += $htmlTable
        $script:htmlTabs[$TabName] += "</div>"
        $script:htmlTabs[$TabName] += "<p><strong>📊 Total items:</strong> $($Data.Count)</p>"
    } else {
        $script:htmlTabs[$TabName] += "<div style='text-align: center; padding: 40px; color: #6c757d;'>"
        $script:htmlTabs[$TabName] += "<div style='font-size: 48px; margin-bottom: 10px;'>✅</div>"
        $script:htmlTabs[$TabName] += "<h3>$EmptyMessage</h3>"
        $script:htmlTabs[$TabName] += "</div>"
    }
}

function Generate-SecurityDashboard {
    try {
        Write-EnhancedLog "Generating security dashboard..." "INFO"
        
        $totalFindings = $script:SecurityFindings.Count
        $criticalFindings = ($script:SecurityFindings | Where-Object { $_.Severity -eq "Critical" }).Count
        $highFindings = ($script:SecurityFindings | Where-Object { $_.Severity -eq "High" }).Count
        $mediumFindings = ($script:SecurityFindings | Where-Object { $_.Severity -eq "Medium" }).Count
        
        $riskLevel = if ($criticalFindings -gt 0) { "CRITICAL" }
                    elseif ($highFindings -gt 5) { "HIGH" }
                    elseif ($highFindings -gt 0 -or $mediumFindings -gt 10) { "MEDIUM" }
                    else { "LOW" }
        
        $riskColor = switch ($riskLevel) {
            "CRITICAL" { "#dc3545" }
            "HIGH" { "#fd7e14" }
            "MEDIUM" { "#ffc107" }
            "LOW" { "#28a745" }
        }
        
        $riskIcon = switch ($riskLevel) {
            "CRITICAL" { "🚨" }
            "HIGH" { "⚠️" }
            "MEDIUM" { "🔶" }
            "LOW" { "✅" }
        }
        
        $script:htmlTabs.Dashboard += @"
<div class="summary-grid">
    <div class="summary-card" style="border-left-color: $riskColor;">
        <h3>$riskIcon Overall Risk Level</h3>
        <div class="value" style="color: $riskColor">$riskLevel</div>
    </div>
    <div class="summary-card">
        <h3>🚨 Total Findings</h3>
        <div class="value">$totalFindings</div>
    </div>
    <div class="summary-card">
        <h3>💀 Critical Issues</h3>
        <div class="value" style="color: #dc3545">$criticalFindings</div>
    </div>
    <div class="summary-card">
        <h3>⚠️ High Priority</h3>
        <div class="value" style="color: #fd7e14">$highFindings</div>
    </div>
</div>

<h3 style="color: #2a5885; margin-top: 30px;">📈 Security Findings Summary</h3>
"@
        
        if ($script:SecurityFindings.Count -gt 0) {
            $findingsSummary = $script:SecurityFindings | Group-Object Category | 
                Select-Object @{Name="Category";Expression={$_.Name}}, @{Name="Count";Expression={$_.Count}}, 
                @{Name="HighestSeverity";Expression={($_.Group | Sort-Object Severity -Descending)[0].Severity}}
            
            Add-EnhancedHtmlSection -TabName "Dashboard" -Data $findingsSummary
            Add-EnhancedHtmlSection -TabName "SecurityFindings" -Data $script:SecurityFindings -AddSearch -RiskColumn "Severity"
        } else {
            $script:htmlTabs.Dashboard += "<div style='text-align: center; padding: 40px; color: #28a745;'>"
            $script:htmlTabs.Dashboard += "<div style='font-size: 64px; margin-bottom: 20px;'>🛡️</div>"
            $script:htmlTabs.Dashboard += "<h3>No Security Issues Detected</h3>"
            $script:htmlTabs.Dashboard += "<p>Based on automatic checks, system does not appear to be compromised.</p>"
            $script:htmlTabs.Dashboard += "</div>"
            
            $script:htmlTabs.SecurityFindings += "<div style='text-align: center; padding: 40px; color: #28a745;'>"
            $script:htmlTabs.SecurityFindings += "<div style='font-size: 64px; margin-bottom: 20px;'>✅</div>"
            $script:htmlTabs.SecurityFindings += "<h3>No Security Findings Detected</h3>"
            $script:htmlTabs.SecurityFindings += "</div>"
        }
        
    } catch {
        Write-EnhancedLog "Error generating dashboard: $_" "ERROR"
    }
}

# ==============================================================================
# 6. MAIN EXECUTION ORCHESTRATOR
# ==============================================================================

function Run-EnhancedInvestigation {
    Write-EnhancedLog "=== Enhanced Threat Analysis Started ===" "INFO"
    Write-EnhancedLog "Target: $vmName" "INFO"
    Write-EnhancedLog "Log Analysis Window: $($script:Config.LogAnalysisStart) to $($script:Config.LogAnalysisEnd)" "INFO"
    Write-EnhancedLog "File Monitoring Window: Last 25 hours" "INFO"
    Write-EnhancedLog "Security Events Window: Last 24 hours" "INFO"
    
    # Execute all security checks in logical order
    $lastLogons = Get-LastLogonEvents
    Get-EnhancedIISLogs
    Get-AdminUsers
    Get-RecentLocalAccounts  
    Get-RecentFiles
    Detect-WebShells
    Get-EnhancedProcessAnalysis
    Get-NetworkConnections
    Generate-FileHashes
    Get-LogTamperingEvents
    Get-SystemHealthCheck
    
    # Add Last Logons to HTML
    if ($lastLogons.Count -gt 0) {
        Add-EnhancedHtmlSection -TabName "LastLogons" -Data $lastLogons -AddSearch -RiskColumn "RiskLevel"
    } else {
        $script:htmlTabs.LastLogons += "<div style='text-align: center; padding: 40px; color: #6c757d;'>"
        $script:htmlTabs.LastLogons += "<div style='font-size: 48px; margin-bottom: 10px;'>⚠️</div>"
        $script:htmlTabs.LastLogons += "<h3>No logon events found in the specified timeframe</h3>"
        $script:htmlTabs.LastLogons += "</div>"
    }
    
    # Add Error Details to HTML
    if ($script:ErrorDetails.Count -gt 0) {
        Add-EnhancedHtmlSection -TabName "ErrorDetails" -Data $script:ErrorDetails -AddSearch
    } else {
        $script:htmlTabs.ErrorDetails += "<div style='text-align: center; padding: 40px; color: #28a745;'>"
        $script:htmlTabs.ErrorDetails += "<div style='font-size: 48px; margin-bottom: 10px;'>✅</div>"
        $script:htmlTabs.ErrorDetails += "<h3>No errors encountered during execution</h3>"
        $script:htmlTabs.ErrorDetails += "</div>"
    }
    
    # Generate dashboard last
    Generate-SecurityDashboard
    
    Write-EnhancedLog "=== Enhanced Threat Analysis Completed ===" "SUCCESS"
}

# ==============================================================================
# 7. SCRIPT EXECUTION AND REPORT GENERATION
# ==============================================================================

# VM and folder setup
$vmName = $env:ComputerName
$outputFolder = ".\$vmName"
$date = Get-Date -Format "yyyy-MM-dd"
$htmlReportName = "$date.html"
$htmlReport = Join-Path $outputFolder $htmlReportName

if (-not (Test-Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# Get computer details first
$computerDetails = Get-ComputerDetails

# HTML Template with complete styling and layout
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Threat Analysis Report - $vmName - $date</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1500px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header-section {
            background: linear-gradient(135deg, #2a5885 0%, #1e3a5f 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header-section h1 { 
            margin: 0; 
            font-size: 2.5em; 
            font-weight: 300;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .header-section .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
            margin-top: 10px;
        }
        
        .main-content { padding: 30px; }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        
        .info-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #007bff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        
        .info-section h3 {
            margin-top: 0;
            color: #2a5885;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
            transition: background-color 0.2s;
        }
        .detail-item:hover {
            background-color: rgba(0,123,255,0.05);
            border-radius: 4px;
            padding-left: 8px;
            padding-right: 8px;
        }
        .detail-item:last-child { border-bottom: none; }
        
        .detail-label {
            font-weight: 600;
            color: #495057;
            min-width: 120px;
        }
        .detail-value {
            color: #6c757d;
            text-align: right;
            flex: 1;
        }
        
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .summary-card { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px; 
            border-radius: 8px; 
            border-left: 4px solid #007bff;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
        }
        .summary-card h3 { 
            margin: 0 0 10px 0; 
            color: #495057; 
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-card .value { 
            font-size: 28px; 
            font-weight: bold; 
            color: #007bff;
            text-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        
        .tab { 
            display: flex;
            flex-wrap: wrap;
            background: linear-gradient(135deg, #f1f3f4 0%, #e8eaed 100%);
            border-radius: 8px 8px 0 0;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .tab button { 
            background: transparent;
            border: none; 
            padding: 15px 18px; 
            cursor: pointer; 
            transition: all 0.3s ease;
            font-weight: 500; 
            font-size: 13px;
            color: #5f6368;
            border-bottom: 3px solid transparent;
        }
        .tab button:hover { 
            background: rgba(66, 133, 244, 0.1);
            color: #4285f4;
        }
        .tab button.active { 
            background: #4285f4;
            color: white;
            border-bottom: 3px solid #1a73e8;
            box-shadow: 0 2px 8px rgba(66, 133, 244, 0.3);
        }
        
        .tabcontent { 
            display: none; 
            padding: 30px; 
            background: white;
            border: 1px solid #e8eaed; 
            border-top: none; 
            min-height: 400px; 
            border-radius: 0 0 8px 8px;
        }
        
        h2 { 
            color: #2a5885; 
            border-bottom: 2px solid #e8eaed; 
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .table-container { 
            overflow-x: auto; 
            margin-bottom: 20px; 
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
            font-size: 12px;
            background: white;
        }
        th, td { 
            border: 1px solid #e8eaed; 
            padding: 12px 8px; 
            text-align: left; 
            word-wrap: break-word; 
            max-width: 200px; 
        }
        th { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            font-weight: 600; 
            position: sticky; 
            top: 0;
            color: #2a5885;
        }
        tr:nth-child(even) { background-color: #fafbfc; }
        tr:hover { 
            background-color: rgba(66, 133, 244, 0.05);
            transition: background-color 0.2s;
        }
        
        .suspicious { background-color: #fce8e6 !important; border-left: 4px solid #ea4335; }
        .warning { background-color: #fef7e0 !important; border-left: 4px solid #fbbc04; }
        .success { background-color: #e6f4ea !important; border-left: 4px solid #34a853; }
        .critical { background-color: #fce8e6 !important; border-left: 4px solid #d93025; }
        
        .risk-indicator { 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 11px; 
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .risk-high { background: linear-gradient(135deg, #ea4335 0%, #d93025 100%); color: white; }
        .risk-medium { background: linear-gradient(135deg, #fbbc04 0%, #f9ab00 100%); color: #1a1a1a; }
        .risk-low { background: linear-gradient(135deg, #34a853 0%, #137333 100%); color: white; }
        
        .search-box { 
            margin-bottom: 20px; 
            padding: 12px 16px; 
            border: 2px solid #e8eaed; 
            border-radius: 25px; 
            width: 300px;
            font-size: 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .search-box:focus {
            outline: none;
            border-color: #4285f4;
            box-shadow: 0 0 0 3px rgba(66, 133, 244, 0.1);
        }
        
        .truncate { 
            max-width: 150px; 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap; 
        }
        .truncate:hover { 
            white-space: normal; 
            overflow: visible; 
            background: #f8f9fa;
            padding: 4px;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            z-index: 10;
            position: relative;
        }
        
        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            .tab {
                flex-direction: column;
            }
            .tab button {
                width: 100%;
                text-align: left;
            }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .container {
            animation: fadeIn 0.6s ease-out;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header-section">
        <h1>🛡️ Threat Analysis Report</h1>
        <div class="subtitle">Comprehensive Security Assessment for $vmName</div>
    </div>
    
    <div class="main-content">
        <div class="info-grid">
            <div class="info-section">
                <h3>💻 Computer Information</h3>
"@

# Add computer details to HTML
foreach ($detail in $computerDetails) {
    $htmlHeader += @"
                <div class="detail-item">
                    <span class="detail-label">$($detail.Property):</span>
                    <span class="detail-value">$($detail.Value)</span>
                </div>
"@
}

$htmlHeader += @"
            </div>
            
            <div class="info-section">
                <h3>📋 Scan Window Details</h3>
                <div class="detail-item">
                    <span class="detail-label">Log Analysis:</span>
                    <span class="detail-value">$($script:Config.LogAnalysisStart.ToString('yyyy-MM-dd HH:mm')) to $($script:Config.LogAnalysisEnd.ToString('yyyy-MM-dd HH:mm'))</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Window Type:</span>
                    <span class="detail-value">Daily Window</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">File Changes:</span>
                    <span class="detail-value">Last 25 hours (Rolling Window)</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Security Events:</span>
                    <span class="detail-value">Last 24 hours (Rolling Window)</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Critical Events:</span>
                    <span class="detail-value">Last 26 hours (Buffer Window)</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Analysis Coverage:</span>
                    <span class="detail-value">$([math]::Round(($script:Config.LogAnalysisEnd - $script:Config.LogAnalysisStart).TotalHours, 1)) hours</span>
                </div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Computer Name</h3>
                <div class="value">$vmName</div>
            </div>
            <div class="summary-card">
                <h3>Report Date</h3>
                <div class="value">$date</div>
            </div>
            <div class="summary-card">
                <h3>Analysis Window</h3>
                <div class="value">$($script:Config.LogAnalysisStart.ToString('HH:mm')) - $($script:Config.LogAnalysisEnd.ToString('HH:mm'))</div>
            </div>
            <div class="summary-card">
                <h3>Execution Time</h3>
                <div class="value" id="executionTimeValue">PLACEHOLDER_EXECUTION_TIME</div>
            </div>
        </div>

        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'Dashboard')">📊 Dashboard</button>
            <button class="tablinks" onclick="openTab(event, 'SecurityFindings')">🚨 Security Findings</button>
            <button class="tablinks" onclick="openTab(event, 'LastLogons')">🔐 Last Logons</button>
            <button class="tablinks" onclick="openTab(event, 'IISLogs')">📋 IIS Logs</button>
            <button class="tablinks" onclick="openTab(event, 'AdminUsers')">👤 Admin Users</button>
            <button class="tablinks" onclick="openTab(event, 'LocalAccounts')">🆕 Local Accounts</button>
            <button class="tablinks" onclick="openTab(event, 'RecentFiles')">📁 Recent Files</button>
            <button class="tablinks" onclick="openTab(event, 'WebShells')">🐚 Web Shells</button>
            <button class="tablinks" onclick="openTab(event, 'ProcessAnalysis')">⚙️ Process Analysis</button>
            <button class="tablinks" onclick="openTab(event, 'NetworkConnections')">🌐 Network</button>
            <button class="tablinks" onclick="openTab(event, 'FileHashes')">🔒 File Integrity</button>
            <button class="tablinks" onclick="openTab(event, 'LogTampering')">📝 Log Tampering</button>
            <button class="tablinks" onclick="openTab(event, 'SystemHealth')">💊 System Health</button>
            <button class="tablinks" onclick="openTab(event, 'ErrorDetails')">❌ Error Details</button>
            <button class="tablinks" onclick="openTab(event, 'Logs')">📄 Execution Logs</button>
        </div>
"@

$htmlFooter = @"
    </div>
</div>

<script>
    function openTab(evt, tabName) {
        var i, tabcontent, tablinks;
        
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
        
        document.getElementById(tabName).scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    function searchTable(inputId, tableId) {
        var input = document.getElementById(inputId);
        var filter = input.value.toLowerCase();
        var table = document.getElementById(tableId);
        
        if (!table) return;
        
        var tr = table.getElementsByTagName("tr");
        var visibleRows = 0;
        
        for (var i = 1; i < tr.length; i++) {
            var td = tr[i].getElementsByTagName("td");
            var found = false;
            
            for (var j = 0; j < td.length; j++) {
                if (td[j] && td[j].innerHTML.toLowerCase().indexOf(filter) > -1) {
                    found = true;
                    break;
                }
            }
            
            if (found) {
                tr[i].style.display = "";
                visibleRows++;
            } else {
                tr[i].style.display = "none";
            }
        }
        
        var resultsInfo = document.querySelector('#' + inputId + '_results');
        if (!resultsInfo) {
            resultsInfo = document.createElement('div');
            resultsInfo.id = inputId + '_results';
            resultsInfo.style.fontSize = '12px';
            resultsInfo.style.color = '#6c757d';
            resultsInfo.style.marginTop = '5px';
            input.parentNode.appendChild(resultsInfo);
        }
        
        if (filter) {
            resultsInfo.textContent = visibleRows + ' rows match your search';
        } else {
            resultsInfo.textContent = '';
        }
    }
    
    document.addEventListener('DOMContentLoaded', function() {
        var tables = document.querySelectorAll('table');
        tables.forEach(function(table) {
            var rows = table.querySelectorAll('tr');
            rows.forEach(function(row, index) {
                if (index === 0) return;
                
                row.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.02)';
                    this.style.transition = 'transform 0.2s ease';
                });
                
                row.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1)';
                });
            });
        });
        
        document.getElementById("Dashboard").style.display = "block";
        
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key >= '1' && e.key <= '9') {
                e.preventDefault();
                var tabIndex = parseInt(e.key) - 1;
                var tabs = document.querySelectorAll('.tablinks');
                if (tabs[tabIndex]) {
                    tabs[tabIndex].click();
                }
            }
        });
    });
    
    function updateExecutionTime() {
        var executionElement = document.getElementById('executionTimeValue');
        if (executionElement && executionElement.textContent !== 'PLACEHOLDER_EXECUTION_TIME') {
            executionElement.style.animation = 'fadeIn 0.5s ease-in';
        }
    }
    
    setInterval(updateExecutionTime, 1000);
</script>
</body>
</html>
"@

# Initialize HTML tabs
$htmlTabs = @{
    Dashboard = "<div id='Dashboard' class='tabcontent'><h2>📊 Security Dashboard</h2>"
    SecurityFindings = "<div id='SecurityFindings' class='tabcontent'><h2>🚨 Critical Security Findings</h2>"
    LastLogons = "<div id='LastLogons' class='tabcontent'><h2>🔐 Last Logon Events</h2>"
    IISLogs = "<div id='IISLogs' class='tabcontent'><h2>📋 IIS Log Analysis</h2>"
    AdminUsers = "<div id='AdminUsers' class='tabcontent'><h2>👤 Administrative Users</h2>"
    LocalAccounts = "<div id='LocalAccounts' class='tabcontent'><h2>🆕 Recently Created Local Accounts</h2>"
    RecentFiles = "<div id='RecentFiles' class='tabcontent'><h2>📁 Recently Modified Files</h2>"
    WebShells = "<div id='WebShells' class='tabcontent'><h2>🐚 Web Shell Detection</h2>"
    ProcessAnalysis = "<div id='ProcessAnalysis' class='tabcontent'><h2>⚙️ Process Analysis</h2>"
    NetworkConnections = "<div id='NetworkConnections' class='tabcontent'><h2>🌐 Network Connections</h2>"
    FileHashes = "<div id='FileHashes' class='tabcontent'><h2>🔒 File Integrity Monitoring</h2>"
    LogTampering = "<div id='LogTampering' class='tabcontent'><h2>📝 Log Tampering Detection</h2>"
    SystemHealth = "<div id='SystemHealth' class='tabcontent'><h2>💊 System Health Check</h2>"
    ErrorDetails = "<div id='ErrorDetails' class='tabcontent'><h2>❌ Error Details</h2>"
    Logs = "<div id='Logs' class='tabcontent'><h2>📄 Execution Logs</h2>"
}

# ==============================================================================
# 8. MAIN SCRIPT EXECUTION
# ==============================================================================

Write-EnhancedLog "Starting Enhanced Threat Analysis Script v5.1" "INFO"
Run-EnhancedInvestigation

# Finalize timing and generate report
$script:ScriptEndTime = Get-Date
$executionTime = $script:ScriptEndTime - $script:ScriptStartTime
$executionTimeFormatted = "{0:hh\:mm\:ss}" -f $executionTime

Write-EnhancedLog "Investigation completed in $executionTimeFormatted" "SUCCESS"

# Add logs to the Logs tab
$script:htmlTabs.Logs += $script:LogEntries

# Generate final HTML report
$htmlContent = $htmlHeader
foreach ($tabContent in $htmlTabs.Values) {
    $htmlContent += $tabContent + "</div>"
}

$htmlContent = $htmlContent -replace "PLACEHOLDER_EXECUTION_TIME", $executionTimeFormatted
$htmlContent += $htmlFooter

$htmlContent | Out-File -FilePath $htmlReport -Force -Encoding UTF8

Write-EnhancedLog "Enhanced HTML report generated: $htmlReport" "SUCCESS"
Write-EnhancedLog "Total security findings: $($script:SecurityFindings.Count)" "INFO"
Write-EnhancedLog "Total errors encountered: $($script:ErrorDetails.Count)" "INFO"

# Create manifest.json
$manifestPath = "C:\HostGuard\$vmName\manifest.json"
$manifest = @{ dates = @() }
$manifest | ConvertTo-Json -Depth 2 | Set-Content -Path $manifestPath -Encoding UTF8

Write-EnhancedLog "Manifest created: $manifestPath" "SUCCESS"