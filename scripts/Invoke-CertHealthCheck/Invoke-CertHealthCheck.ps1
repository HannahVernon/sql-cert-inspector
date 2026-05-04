<#
.SYNOPSIS
    Automated SQL Server TLS certificate health check using sql-cert-inspector.

.DESCRIPTION
    Reads a pipe-delimited server list, runs sql-cert-inspector against each server,
    classifies certificate health, generates an HTML report, and optionally emails it.

.PARAMETER InputFile
    Path to a pipe-delimited file listing SQL Servers to inspect.
    Required unless -Setup is specified.

.PARAMETER ExePath
    Path to the sql-cert-inspector executable. Defaults to the current directory.

.PARAMETER OutputPath
    File path where the HTML report will be saved.

.PARAMETER Timeout
    Global connection timeout in seconds. Can be overridden per-server in the input file.

.PARAMETER AlwaysSendEmail
    Send the report email on every run, even when no issues are found.

.PARAMETER Setup
    Interactive setup for SMTP email configuration.

.PARAMETER WhatIf
    Show what would be executed without actually running inspections.

.EXAMPLE
    .\Invoke-CertHealthCheck.ps1 -InputFile servers.txt -OutputPath report.html

.EXAMPLE
    .\Invoke-CertHealthCheck.ps1 -Setup

.EXAMPLE
    .\Invoke-CertHealthCheck.ps1 -InputFile servers.txt -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Position = 0)]
    [string]$InputFile

  , [Parameter()]
    [string]$ExePath = '.'

  , [Parameter()]
    [string]$OutputPath

  , [Parameter()]
    [int]$Timeout

  , [Parameter()]
    [switch]$AlwaysSendEmail

  , [Parameter()]
    [switch]$ValidateDns

  , [Parameter()]
    [switch]$Setup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:SmtpConfigPath = Join-Path $script:ScriptDir 'smtp-config.json'
$script:CredentialTarget = 'Invoke-CertHealthCheck-Smtp'

#region Helper Functions

function Get-SafeProperty {
    <#
    .SYNOPSIS
        Safely gets a property value from a PSCustomObject, returning $null
        if the property does not exist. Avoids strict mode errors when JSON
        properties are omitted by WhenWritingNull serialization.
    #>
    param (
        [PSCustomObject]$Object
      , [string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }
    return $null
}

function Test-Interactive {
    <#
    .SYNOPSIS
        Returns $true when the session is interactive (has a console window).
    #>
    try {
        return [Environment]::UserInteractive -and [Console]::WindowHeight -gt 0
    }
    catch {
        return $false
    }
}

function Get-SmtpConfig {
    <#
    .SYNOPSIS
        Loads SMTP configuration from the json file, or returns $null.
    #>
    if (Test-Path $script:SmtpConfigPath) {
        return Get-Content $script:SmtpConfigPath -Raw | ConvertFrom-Json
    }
    return $null
}

function Initialize-CredManagerNative {
    <#
    .SYNOPSIS
        Loads the native Credential Manager P/Invoke signatures (advapi32.dll).
        Returns the type containing the static methods.
    #>
    if (-not ('CredManagerNative.Api' -as [Type])) {
        # All fields are primitive/IntPtr for .NET 7+ blittability.
        # FILETIME replaced with two uint fields to avoid ComTypes dependency.
        $sig = @'
[StructLayout(LayoutKind.Sequential)]
public struct CREDENTIAL
{
    public uint Flags;
    public uint Type;
    public IntPtr TargetName;
    public IntPtr Comment;
    public uint LastWrittenLow;
    public uint LastWrittenHigh;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    public IntPtr TargetAlias;
    public IntPtr UserName;
}

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CredRead(
    string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CredWrite(
    ref CREDENTIAL credential, uint flags);

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CredDelete(
    string target, uint type, uint flags);

[DllImport("advapi32.dll")]
public static extern void CredFree(IntPtr cred);
'@
        Add-Type -MemberDefinition $sig -Namespace 'CredManagerNative' -Name 'Api'
    }
    return [CredManagerNative.Api]
}

function Get-StoredCredential {
    <#
    .SYNOPSIS
        Retrieves the SMTP credential from Windows Credential Manager via P/Invoke.
        Uses manual Marshal offset reads to avoid PtrToStructure blittability issues.
    #>
    param ([string]$Target)

    $api = Initialize-CredManagerNative

    $ptr = [IntPtr]::Zero
    $success = $api::CredRead($Target, 1, 0, [ref]$ptr)
    if (-not $success) {
        return $null
    }

    try {
        # Read CredentialBlobSize and CredentialBlob at their struct offsets.
        # CREDENTIAL layout (x64): Flags(4) Type(4) TargetName(8) Comment(8)
        #   LastWritten(8) CredentialBlobSize(4) pad(4) CredentialBlob(8)
        $ptrSize = [IntPtr]::Size
        $blobSizeOffset = 4 + 4 + $ptrSize + $ptrSize + 8   <# 24 on x86, 32 on x64 #>
        $blobPtrOffset  = $blobSizeOffset + 4
        if ($ptrSize -eq 8) { $blobPtrOffset += 4 }         <# alignment padding on x64 #>

        $blobSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($ptr, $blobSizeOffset)
        if ($blobSize -gt 0) {
            $blobPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $blobPtrOffset)
            $rawBytes = New-Object byte[] $blobSize
            [System.Runtime.InteropServices.Marshal]::Copy($blobPtr, $rawBytes, 0, $blobSize)
            $passwordText = [System.Text.Encoding]::Unicode.GetString($rawBytes)
            $securePass = ConvertTo-SecureString $passwordText -AsPlainText -Force
            return $securePass
        }
        return $null
    }
    finally {
        $api::CredFree($ptr)
    }
}

function Set-StoredCredential {
    <#
    .SYNOPSIS
        Stores SMTP credential in Windows Credential Manager via P/Invoke.
    #>
    param (
        [string]$Target
      , [string]$Username
      , [SecureString]$Password
    )

    $api = Initialize-CredManagerNative

    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    )
    $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($plain)

    $cred = New-Object CredManagerNative.Api+CREDENTIAL
    $cred.Type = 1          <# CRED_TYPE_GENERIC #>
    $cred.Persist = 2       <# CRED_PERSIST_LOCAL_MACHINE #>
    $cred.CredentialBlobSize = [uint32]$passwordBytes.Length
    $cred.CredentialBlob = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($passwordBytes.Length)

    $pTarget   = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Target)
    $pUsername  = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Username)
    $cred.TargetName = $pTarget
    $cred.UserName   = $pUsername

    try {
        [System.Runtime.InteropServices.Marshal]::Copy($passwordBytes, 0, $cred.CredentialBlob, $passwordBytes.Length)

        $success = $api::CredWrite([ref]$cred, 0)
        if (-not $success) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Failed to store credential in Windows Credential Manager (Win32 error $errorCode)."
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cred.CredentialBlob)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pTarget)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pUsername)
    }
}

function Remove-StoredCredential {
    <#
    .SYNOPSIS
        Removes a credential from Windows Credential Manager via P/Invoke.
    #>
    param ([string]$Target)

    $api = Initialize-CredManagerNative
    $api::CredDelete($Target, 1, 0) | Out-Null
}

function Read-HostWithDefault {
    <#
    .SYNOPSIS
        Prompts the user with a default value shown in brackets.
    #>
    param (
        [string]$Prompt
      , [string]$Default = ''
    )

    if ($Default) {
        $response = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($response)) { return $Default }
        return $response.Trim()
    }
    else {
        $val = Read-Host $Prompt
        return $val.Trim()
    }
}

function Send-SmtpEmail {
    <#
    .SYNOPSIS
        Sends an HTML email using configured SMTP settings.
    #>
    param (
        [object]$Config
      , [string]$Subject
      , [string]$Body
      , [SecureString]$Password = $null
    )

    $smtpClient = New-Object System.Net.Mail.SmtpClient($Config.smtpServer, $Config.smtpPort)
    $smtpClient.EnableSsl = [bool]$Config.enableTls

    if ($Config.useAuthentication -and $Password) {
        $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        )
        $smtpClient.Credentials = New-Object System.Net.NetworkCredential($Config.smtpUsername, $plainPass)
    }

    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $Config.fromAddress
    $message.Subject = $Subject
    $message.Body = $Body
    $message.IsBodyHtml = $true

    foreach ($addr in ($Config.toAddress -split ';' | Where-Object { $_.Trim() })) {
        $message.To.Add($addr.Trim())
    }
    $ccAddr = Get-SafeProperty $Config 'ccAddress'
    if ($ccAddr) {
        foreach ($addr in ($ccAddr -split ';' | Where-Object { $_.Trim() })) {
            $message.CC.Add($addr.Trim())
        }
    }
    $bccAddr = Get-SafeProperty $Config 'bccAddress'
    if ($bccAddr) {
        foreach ($addr in ($bccAddr -split ';' | Where-Object { $_.Trim() })) {
            $message.Bcc.Add($addr.Trim())
        }
    }

    try {
        $smtpClient.Send($message)
    }
    finally {
        $message.Dispose()
        $smtpClient.Dispose()
    }
}

function Get-MachineFqdn {
    <#
    .SYNOPSIS
        Returns the FQDN of the local machine.
    #>
    try {
        return [System.Net.Dns]::GetHostEntry([Environment]::MachineName).HostName
    }
    catch {
        return [Environment]::MachineName
    }
}

#endregion

#region Setup Mode

function Invoke-Setup {
    <#
    .SYNOPSIS
        Interactive configuration wizard for exe path and SMTP email settings.
    #>
    Write-Host ''
    Write-Host '=== Invoke-CertHealthCheck Configuration Setup ===' -ForegroundColor Cyan
    Write-Host ''

    $existing = Get-SmtpConfig

    Write-Host '--- sql-cert-inspector Location ---' -ForegroundColor White
    $exePathDefault = if ($existing -and ($existing.PSObject.Properties.Name -contains 'exePath') -and $existing.exePath) { $existing.exePath } else { '.' }
    $exePathInput = Read-HostWithDefault -Prompt 'Directory containing sql-cert-inspector.exe' -Default $exePathDefault

    if ($exePathInput -match '(?i)sql-cert-inspector(\.exe)?$') {
        $trimmedDir = Split-Path $exePathInput -Parent
        $trimmedExe = Join-Path $trimmedDir 'sql-cert-inspector.exe'
        $trimmedResolved = if ([System.IO.Path]::IsPathRooted($trimmedDir)) { $trimmedDir } else { Join-Path (Get-Location) $trimmedDir }
        $trimmedExeResolved = Join-Path $trimmedResolved 'sql-cert-inspector.exe'
        if (Test-Path $trimmedExeResolved) {
            Write-Host "  Note: You specified the full executable path. Using the directory instead: $trimmedDir" -ForegroundColor Yellow
            $exePathInput = $trimmedDir
        }
    }

    $exePathResolved = if ([System.IO.Path]::IsPathRooted($exePathInput)) { $exePathInput } else { Join-Path (Get-Location) $exePathInput }
    $testExe = Join-Path $exePathResolved 'sql-cert-inspector.exe'
    if (Test-Path $testExe) {
        Write-Host "  Found: $testExe" -ForegroundColor Green
    }
    else {
        Write-Host "  WARNING: sql-cert-inspector.exe not found at $testExe" -ForegroundColor Yellow
        Write-Host "  You can fix this later by re-running -Setup or using the -ExePath parameter." -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host '--- SMTP Email Configuration ---' -ForegroundColor White
    $smtpServer = Read-HostWithDefault -Prompt 'SMTP Server' -Default $(if ($existing) { $existing.smtpServer } else { '' })
    $smtpPort = Read-HostWithDefault -Prompt 'SMTP Port' -Default $(if ($existing) { [string]$existing.smtpPort } else { '587' })
    $enableTlsStr = Read-HostWithDefault -Prompt 'Enable TLS (true/false)' -Default $(if ($existing) { [string]$existing.enableTls } else { 'true' })
    $fromAddress = Read-HostWithDefault -Prompt 'From Address' -Default $(if ($existing) { $existing.fromAddress } else { '' })
    $toAddress = Read-HostWithDefault -Prompt 'To Address (semicolon-separated for multiple)' -Default $(if ($existing) { $existing.toAddress } else { '' })
    $ccAddress = Read-HostWithDefault -Prompt 'CC Address (optional, semicolon-separated)' -Default $(if ($existing) { $existing.ccAddress } else { '' })
    $bccAddress = Read-HostWithDefault -Prompt 'BCC Address (optional, semicolon-separated)' -Default $(if ($existing) { $existing.bccAddress } else { '' })
    $useAuthStr = Read-HostWithDefault -Prompt 'Use SMTP Authentication (true/false)' -Default $(if ($existing) { [string]$existing.useAuthentication } else { 'false' })

    $enableTls = $enableTlsStr -match '^(true|yes|1)$'
    $useAuth = $useAuthStr -match '^(true|yes|1)$'

    $smtpUsername = ''
    $smtpPassword = $null

    if ($useAuth) {
        $smtpUsername = Read-HostWithDefault -Prompt 'SMTP Username' -Default $(if ($existing) { $existing.smtpUsername } else { '' })
        $smtpPassword = Read-Host 'SMTP Password' -AsSecureString
    }

    $config = [PSCustomObject]@{
        exePath           = $exePathInput
        smtpServer        = $smtpServer
        smtpPort          = [int]$smtpPort
        enableTls         = $enableTls
        fromAddress       = $fromAddress
        toAddress         = $toAddress
        ccAddress         = $ccAddress
        bccAddress        = $bccAddress
        useAuthentication = $useAuth
        smtpUsername       = $smtpUsername
    }

    Write-Host ''
    Write-Host 'Sending test email...' -ForegroundColor Yellow

    $testSubject = "sql-cert-inspector Health Check — SMTP Test"
    $testBody = @"
<html><body>
<p>This is a test email from <strong>Invoke-CertHealthCheck</strong>.</p>
<p>SMTP configuration is working correctly.</p>
<p>Sent from: <code>$(Get-MachineFqdn)</code></p>
</body></html>
"@

    $retryLoop = $true
    while ($retryLoop) {
        try {
            Send-SmtpEmail -Config $config -Subject $testSubject -Body $testBody -Password $smtpPassword
            Write-Host 'Test email sent successfully!' -ForegroundColor Green
            $retryLoop = $false
        }
        catch {
            Write-Host "Test email failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ''
            $retry = Read-Host 'Retry? (Y/N)'
            if ($retry -notmatch '^[Yy]') {
                Write-Host 'Setup aborted. Configuration was NOT saved.' -ForegroundColor Yellow
                return
            }
            Write-Host ''
            Write-Host 'Re-enter SMTP settings:' -ForegroundColor Cyan
            $smtpServer = Read-HostWithDefault -Prompt 'SMTP Server' -Default $config.smtpServer
            $smtpPort = Read-HostWithDefault -Prompt 'SMTP Port' -Default ([string]$config.smtpPort)
            $enableTlsStr = Read-HostWithDefault -Prompt 'Enable TLS (true/false)' -Default ([string]$config.enableTls)
            $fromAddress = Read-HostWithDefault -Prompt 'From Address' -Default $config.fromAddress
            $toAddress = Read-HostWithDefault -Prompt 'To Address' -Default $config.toAddress
            $useAuthStr = Read-HostWithDefault -Prompt 'Use SMTP Authentication (true/false)' -Default ([string]$config.useAuthentication)

            $config.smtpServer = $smtpServer
            $config.smtpPort = [int]$smtpPort
            $config.enableTls = $enableTlsStr -match '^(true|yes|1)$'
            $config.fromAddress = $fromAddress
            $config.toAddress = $toAddress
            $config.useAuthentication = $useAuthStr -match '^(true|yes|1)$'

            if ($config.useAuthentication) {
                $config.smtpUsername = Read-HostWithDefault -Prompt 'SMTP Username' -Default $config.smtpUsername
                $smtpPassword = Read-Host 'SMTP Password' -AsSecureString
            }
        }
    }

    $config | ConvertTo-Json -Depth 4 | Set-Content -Path $script:SmtpConfigPath -Encoding UTF8
    Write-Host "Configuration saved to: $($script:SmtpConfigPath)" -ForegroundColor Green

    if ($useAuth -and $smtpPassword) {
        Set-StoredCredential -Target $script:CredentialTarget -Username $config.smtpUsername -Password $smtpPassword
        Write-Host "Credential stored in Windows Credential Manager (target: $($script:CredentialTarget))." -ForegroundColor Green
    }
    else {
        Remove-StoredCredential -Target $script:CredentialTarget
    }

    Write-Host ''
    Write-Host 'Setup complete.' -ForegroundColor Cyan
}

#endregion

#region Input File Parsing

function New-SampleInputFile {
    <#
    .SYNOPSIS
        Creates a sample pipe-delimited input file with commented examples.
    #>
    param ([string]$Path)

    $content = @(
        'server-name|port|tds-version|full-spn-diagnostics|test-san-connectivity|timeout'
        '# myserver\SQLEXPRESS|1434||||'
        '# myserver2.example.com||tds8|true|true|'
        '# myserver3||||||15'
    )

    $content -join "`r`n" | Set-Content -Path $Path -Encoding UTF8
}

function Read-ServerList {
    <#
    .SYNOPSIS
        Parses the pipe-delimited input file into an array of server objects.
        Validates all fields defensively and skips malformed lines with warnings.
    #>
    param (
        [string]$Path
      , [switch]$ValidateDns
    )

    $maxLineLength = 1024
    $maxServerNameLength = 255
    $validTdsVersions = @('', 'tds7', 'tds8')

    # Valid hostname: starts with letter, alphanumeric/hyphens/dots, ends with alphanumeric. Min 2 chars.
    $validHostnamePattern = '^[a-zA-Z][a-zA-Z0-9.-]*[a-zA-Z0-9]$'
    # Valid IPv4: four octets 0-255
    $validIpv4Pattern = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

    $lines = Get-Content -Path $Path -Encoding UTF8

    $dataLines = @($lines | Where-Object {
        $_.Trim() -and -not $_.TrimStart().StartsWith('#')
    })

    if ($dataLines.Count -lt 2) {
        throw "Input file '$Path' contains no server entries (only header or comments found)."
    }

    $header = ($dataLines | Select-Object -First 1).Trim()
    $expectedHeader = 'server-name|port|tds-version|full-spn-diagnostics|test-san-connectivity|timeout'
    if ($header -ne $expectedHeader) {
        throw "Invalid header row. Expected:`r`n  $expectedHeader`r`nGot:`r`n  $header"
    }

    $servers = @()
    $seen = @{}
    $lineNum = 0
    $skippedCount = 0

    foreach ($line in ($dataLines | Select-Object -Skip 1)) {
        $lineNum++

        try {
            if ($line.Length -gt $maxLineLength) {
                Write-Warning "Skipping line $lineNum — exceeds maximum length of $maxLineLength characters ($($line.Length) chars)."
                $skippedCount++
                continue
            }

            $parts = $line.Split('|')
            if ($parts.Count -lt 1 -or [string]::IsNullOrWhiteSpace($parts[0])) {
                Write-Warning "Skipping line $lineNum — missing server-name."
                $skippedCount++
                continue
            }

            $serverName = $parts[0].Trim()

            if ($serverName.Length -gt $maxServerNameLength) {
                Write-Warning "Skipping line $lineNum — server name exceeds $maxServerNameLength characters."
                $skippedCount++
                continue
            }

            # Detect forward-slash typo: server/INSTANCE instead of server\INSTANCE
            if ($serverName.Contains('/') -and -not $serverName.Contains('\')) {
                $corrected = $serverName.Replace('/', '\')
                Write-Warning "Line $lineNum — '$serverName' uses forward-slash. Did you mean '$corrected'? Auto-correcting."
                $serverName = $corrected
            }

            # Parse server name into host, instance, and comma-port components.
            # Supported formats:
            #   hostname
            #   hostname\INSTANCE
            #   hostname,port
            #   hostname\INSTANCE,port   (port from comma overrides port column)
            #   192.168.0.1
            #   192.168.0.1\INSTANCE
            #   192.168.0.1,port
            $hostPart = $serverName
            $instancePart = $null
            $commaPort = $null

            # Extract instance name (before comma-port, if any)
            if ($hostPart.Contains('\')) {
                $bsIndex = $hostPart.IndexOf('\')
                $instancePart = $hostPart.Substring($bsIndex + 1)
                $hostPart = $hostPart.Substring(0, $bsIndex)

                # Instance name might contain comma-port: INSTANCE,port
                if ($instancePart.Contains(',')) {
                    $commaIndex = $instancePart.IndexOf(',')
                    $commaPort = $instancePart.Substring($commaIndex + 1)
                    $instancePart = $instancePart.Substring(0, $commaIndex)
                }
            }
            elseif ($hostPart.Contains(',')) {
                # host,port format (no instance)
                $commaIndex = $hostPart.IndexOf(',')
                $commaPort = $hostPart.Substring($commaIndex + 1)
                $hostPart = $hostPart.Substring(0, $commaIndex)
            }

            # Validate host part: must be a valid hostname or IPv4 address
            if ($hostPart.Length -lt 2) {
                Write-Warning "Skipping line $lineNum — server name '$serverName' is too short (host part must be at least 2 characters)."
                $skippedCount++
                continue
            }

            $isValidHostname = $hostPart -match $validHostnamePattern
            $isValidIpv4 = $false
            if ($hostPart -match $validIpv4Pattern) {
                $octets = $hostPart.Split('.')
                $isValidIpv4 = ($octets | Where-Object { $_ -as [int] -ne $null -and [int]$_ -ge 0 -and [int]$_ -le 255 }).Count -eq 4
            }

            if (-not $isValidHostname -and -not $isValidIpv4) {
                Write-Warning "Skipping line $lineNum — '$hostPart' is not a valid hostname or IPv4 address."
                $skippedCount++
                continue
            }

            # Validate instance name if present (alphanumeric and underscores only)
            if ($instancePart -and $instancePart -notmatch '^[a-zA-Z0-9_]+$') {
                Write-Warning "Skipping line $lineNum — invalid instance name '$instancePart' for server '$hostPart'."
                $skippedCount++
                continue
            }

            # Determine port: comma-port in server name takes priority over port column
            $portValue = 0
            if ($commaPort) {
                $portParsed = 0
                if (-not [int]::TryParse($commaPort, [ref]$portParsed) -or $portParsed -lt 1 -or $portParsed -gt 65535) {
                    Write-Warning "Skipping line $lineNum — invalid comma-port '$commaPort' in server name '$serverName'. Must be 1-65535."
                    $skippedCount++
                    continue
                }
                $portValue = $portParsed

                # Rebuild server name without comma-port (port goes to dedicated field)
                if ($instancePart) {
                    $serverName = "$hostPart\$instancePart"
                }
                else {
                    $serverName = $hostPart
                }
            }

            if ($portValue -eq 0 -and $parts.Count -gt 1 -and $parts[1].Trim()) {
                $portParsed = 0
                if (-not [int]::TryParse($parts[1].Trim(), [ref]$portParsed) -or $portParsed -lt 0 -or $portParsed -gt 65535) {
                    Write-Warning "Skipping line $lineNum — invalid port '$($parts[1].Trim())' for server '$serverName'. Must be 0-65535."
                    $skippedCount++
                    continue
                }
                $portValue = $portParsed
            }

            $tdsVersion = ''
            if ($parts.Count -gt 2 -and $parts[2].Trim()) {
                $tdsVersion = $parts[2].Trim().ToLower()
                if ($tdsVersion -notin $validTdsVersions) {
                    Write-Warning "Skipping line $lineNum — invalid tds-version '$($parts[2].Trim())' for server '$serverName'. Valid values: tds7, tds8, or blank."
                    $skippedCount++
                    continue
                }
            }

            $timeoutValue = 0
            if ($parts.Count -gt 5 -and $parts[5].Trim()) {
                $timeoutParsed = 0
                if (-not [int]::TryParse($parts[5].Trim(), [ref]$timeoutParsed) -or $timeoutParsed -lt 0 -or $timeoutParsed -gt 300) {
                    Write-Warning "Skipping line $lineNum — invalid timeout '$($parts[5].Trim())' for server '$serverName'. Must be 0-300."
                    $skippedCount++
                    continue
                }
                $timeoutValue = $timeoutParsed
            }

            # DNS pre-flight check (opt-in, skip on failure)
            if ($ValidateDns) {
                try {
                    [void][System.Net.Dns]::GetHostEntry($hostPart)
                    Write-Verbose "DNS resolved: $hostPart"
                }
                catch {
                    Write-Warning "Skipping line $lineNum — DNS resolution failed for '$hostPart'. Check the hostname or remove -ValidateDns to skip this check."
                    $skippedCount++
                    continue
                }
            }

            $entry = [PSCustomObject]@{
                ServerName          = $serverName
                Port                = $portValue
                TdsVersion          = $tdsVersion
                FullSpnDiagnostics  = if ($parts.Count -gt 3 -and $parts[3].Trim() -match '^(true|yes|1)$') { $true } else { $false }
                TestSanConnectivity = if ($parts.Count -gt 4 -and $parts[4].Trim() -match '^(true|yes|1)$') { $true } else { $false }
                Timeout             = $timeoutValue
            }

            $key = "$($entry.ServerName)|$($entry.Port)|$($entry.TdsVersion)|$($entry.FullSpnDiagnostics)|$($entry.TestSanConnectivity)|$($entry.Timeout)"
            if ($seen.ContainsKey($key)) {
                Write-Warning "Duplicate entry skipped: $serverName (all columns identical)."
                $skippedCount++
                continue
            }
            $seen[$key] = $true
            $servers += $entry
        }
        catch {
            Write-Warning "Skipping line $lineNum — unexpected parse error: $($_.Exception.Message)"
            $skippedCount++
            continue
        }
    }

    if ($skippedCount -gt 0) {
        Write-Warning "$skippedCount line(s) skipped due to validation errors."
    }

    if ($servers.Count -eq 0) {
        throw "Input file '$Path' contains no valid server entries after parsing."
    }

    return $servers
}

#endregion

#region Build Command Line

function Build-InspectorArgs {
    <#
    .SYNOPSIS
        Builds the command-line argument array for sql-cert-inspector.
    #>
    param (
        [PSCustomObject]$Server
      , [int]$GlobalTimeout
      , [switch]$IncludeJson
    )

    $cmdArgs = @('--server', $Server.ServerName)

    if ($Server.Port -gt 0) {
        $cmdArgs += '--port'
        $cmdArgs += [string]$Server.Port
    }

    if ($Server.TdsVersion -eq 'tds8') {
        $cmdArgs += '--encrypt-strict'
    }

    if ($Server.FullSpnDiagnostics) {
        $cmdArgs += '--full-spn-diagnostics'
    }

    if ($Server.TestSanConnectivity) {
        $cmdArgs += '--test-san-connectivity'
    }

    $effectiveTimeout = if ($Server.Timeout -gt 0) { $Server.Timeout } elseif ($GlobalTimeout -gt 0) { $GlobalTimeout } else { 0 }
    if ($effectiveTimeout -gt 0) {
        $cmdArgs += '--timeout'
        $cmdArgs += [string]$effectiveTimeout
    }

    if ($IncludeJson) {
        $cmdArgs += '--json'
        $cmdArgs += '--no-color'
    }

    return $cmdArgs
}

function Format-DisplayCommandLine {
    <#
    .SYNOPSIS
        Builds a display-friendly command line string (without --json/--no-color).
    #>
    param (
        [string]$ExeFullPath
      , [PSCustomObject]$Server
      , [int]$GlobalTimeout
    )

    $displayArgs = Build-InspectorArgs -Server $Server -GlobalTimeout $GlobalTimeout
    $quotedArgs = $displayArgs | ForEach-Object {
        if ($_ -match '\s|\\') { "`"$_`"" } else { $_ }
    }
    return "$ExeFullPath $($quotedArgs -join ' ')"
}

#endregion

#region Certificate Health Classification

function Get-HealthStatus {
    <#
    .SYNOPSIS
        Classifies the health of an inspection result.
        Returns: Critical, Warning, Healthy, or Error.
    #>
    param (
        [object]$JsonResult
      , [int]$ExitCode
    )

    if ($ExitCode -ne 0) {
        return 'Error'
    }

    if (-not $JsonResult -or -not ($JsonResult.PSObject.Properties.Name -contains 'certificate') -or -not $JsonResult.certificate) {
        return 'Error'
    }

    $cert = $JsonResult.certificate

    $daysLeft = Get-SafeProperty $cert 'daysUntilExpiry'
    if ($null -ne $daysLeft -and $daysLeft -le 0) {
        return 'Critical'
    }
    if ($null -ne $daysLeft -and $daysLeft -le 7) {
        return 'Critical'
    }

    $issues = @()
    if ($null -ne $daysLeft -and $daysLeft -le 30) {
        $issues += 'Expiring soon'
    }
    if (Get-SafeProperty $cert 'isSelfSigned') {
        $issues += 'Self-signed'
    }
    $keySize = Get-SafeProperty $cert 'keySizeBits'
    if ($null -ne $keySize -and $keySize -lt 2048) {
        $issues += 'Weak key'
    }
    $sigAlg = Get-SafeProperty $cert 'signatureAlgorithm'
    if ($sigAlg -and $sigAlg -match '(?i)(sha1|md5)') {
        $issues += 'Deprecated signature algorithm'
    }

    if ($JsonResult.PSObject.Properties.Name -contains 'warnings' -and $JsonResult.warnings) {
        $issues += $JsonResult.warnings | ForEach-Object { Get-SafeProperty $_ 'message' }
    }

    if (@($issues).Count -gt 0) {
        return 'Warning'
    }

    return 'Healthy'
}

function Get-StatusEmoji {
    param ([string]$Status)
    switch ($Status) {
        'Critical' { return '&#x1F534;' }  <# red circle #>
        'Warning'  { return '&#x1F7E1;' }  <# yellow circle #>
        'Healthy'  { return '&#x1F7E2;' }  <# green circle #>
        'Error'    { return '&#x26AB;' }    <# black circle #>
        default    { return '&#x2753;' }    <# question mark #>
    }
}

function Get-StatusText {
    param ([string]$Status)
    switch ($Status) {
        'Critical' { return 'CRITICAL' }
        'Warning'  { return 'WARNING' }
        'Healthy'  { return 'Healthy' }
        'Error'    { return 'ERROR' }
        default    { return 'Unknown' }
    }
}

function Get-IssueList {
    <#
    .SYNOPSIS
        Returns a list of issues found for a given inspection result.
    #>
    param (
        [object]$JsonResult
      , [int]$ExitCode
      , [string]$StdErr
    )

    $issues = @()

    if ($ExitCode -eq 1) {
        $issues += 'Connection failure'
        if ($StdErr) { $issues += $StdErr.Trim() }
        return $issues
    }
    if ($ExitCode -eq 2) {
        $issues += 'Encryption not enabled'
        return $issues
    }
    if ($ExitCode -eq 3) {
        $issues += 'Browser resolution failure'
        return $issues
    }
    if ($ExitCode -ne 0) {
        $issues += "Exit code: $ExitCode"
        if ($StdErr) { $issues += $StdErr.Trim() }
        return $issues
    }

    if (-not $JsonResult -or -not ($JsonResult.PSObject.Properties.Name -contains 'certificate') -or -not $JsonResult.certificate) {
        $issues += 'No certificate data returned'
        return $issues
    }

    $cert = $JsonResult.certificate
    $daysLeft = Get-SafeProperty $cert 'daysUntilExpiry'

    if ($null -ne $daysLeft -and $daysLeft -le 0) {
        $issues += 'Certificate has EXPIRED'
    }
    elseif ($null -ne $daysLeft -and $daysLeft -le 7) {
        $issues += "Expires in $daysLeft day(s) — CRITICAL"
    }
    elseif ($null -ne $daysLeft -and $daysLeft -le 30) {
        $issues += "Expires in $daysLeft day(s)"
    }

    if (Get-SafeProperty $cert 'isSelfSigned') {
        $issues += 'Self-signed certificate'
    }
    $keySize = Get-SafeProperty $cert 'keySizeBits'
    if ($null -ne $keySize -and $keySize -lt 2048) {
        $issues += "Weak key size ($keySize bits)"
    }
    $sigAlg = Get-SafeProperty $cert 'signatureAlgorithm'
    if ($sigAlg -and $sigAlg -match '(?i)(sha1|md5)') {
        $issues += "Deprecated signature algorithm ($sigAlg)"
    }

    if ($JsonResult.PSObject.Properties.Name -contains 'warnings' -and $JsonResult.warnings) {
        foreach ($w in $JsonResult.warnings) {
            $issues += Get-SafeProperty $w 'message'
        }
    }

    return $issues
}

#endregion

#region HTML Report Generation

function Build-HtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report from the inspection results.
    #>
    param (
        [array]$Results
      , [string]$ExeFullPath
      , [int]$GlobalTimeout
      , [string]$ToolVersion
      , [TimeSpan]$ElapsedTime
    )

    Write-Verbose "Build-HtmlReport: $($Results.Count) result(s), generating report..."
    $totalServers = $Results.Count
    $criticalCount = @($Results | Where-Object { $_.Status -eq 'Critical' }).Count
    $warningCount = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $errorCount = @($Results | Where-Object { $_.Status -eq 'Error' }).Count
    $healthyCount = @($Results | Where-Object { $_.Status -eq 'Healthy' }).Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    $machineFqdn = Get-MachineFqdn

    $css = @'
<style>
    body { font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
    .report-header { background: #1a365d; color: white; padding: 20px 30px; border-radius: 8px 8px 0 0; }
    .report-header h1 { margin: 0 0 8px 0; font-size: 24px; }
    .report-header .meta { font-size: 13px; opacity: 0.85; }
    .summary-bar { padding: 16px 30px; background: white; border-bottom: 1px solid #e0e0e0; }
    .summary-table { border-collapse: separate; border-spacing: 8px 0; margin: 0 auto; width: auto; }
    .summary-table td { padding: 12px 20px; border-radius: 6px; text-align: center; min-width: 100px; border-bottom: none; }
    .card-critical { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    .card-warning { background: #fef9c3; color: #854d0e; border: 1px solid #fde047; }
    .card-healthy { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
    .card-error { background: #e5e7eb; color: #374151; border: 1px solid #9ca3af; }
    .card-total { background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }
    .summary-count { font-size: 28px; font-weight: bold; }
    .summary-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
    table { width: 100%; border-collapse: collapse; background: white; }
    th { background: #f1f5f9; padding: 10px 14px; text-align: left; font-size: 13px; color: #475569; border-bottom: 2px solid #cbd5e1; }
    td { padding: 10px 14px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
    tr:hover { background: #f8fafc; }
    .status-critical { color: #dc2626; font-weight: bold; }
    .status-warning { color: #ca8a04; font-weight: bold; }
    .status-healthy { color: #16a34a; font-weight: bold; }
    .status-error { color: #6b7280; font-weight: bold; }
    details { margin: 8px 0; background: white; border: 1px solid #e2e8f0; border-radius: 6px; }
    summary { padding: 12px 16px; cursor: pointer; font-weight: 600; font-size: 14px; background: #f8fafc; border-radius: 6px; }
    summary:hover { background: #f1f5f9; }
    .detail-body { padding: 16px; }
    .detail-section { margin-bottom: 16px; }
    .detail-section h4 { margin: 0 0 8px 0; color: #1e40af; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
    .detail-table { width: 100%; }
    .detail-table td { padding: 4px 10px; font-size: 13px; border: none; }
    .detail-table td:first-child { font-weight: 600; color: #475569; width: 220px; white-space: nowrap; }
    .cmd-line { background: #1e293b; color: #e2e8f0; padding: 10px 14px; border-radius: 4px; font-family: Consolas, monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    .issue-list { margin: 0; padding-left: 20px; }
    .issue-list li { margin: 2px 0; font-size: 13px; }
    .san-list { margin: 0; padding-left: 20px; font-size: 12px; }
    .footer { padding: 16px 30px; background: white; border-top: 1px solid #e0e0e0; border-radius: 0 0 8px 8px; font-size: 12px; color: #6b7280; }
    .container { max-width: 1200px; margin: 0 auto; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 8px; }
    .warning-list { background: #fffbeb; border: 1px solid #fde68a; border-radius: 4px; padding: 8px 12px; }
    .warning-list li { color: #92400e; font-size: 12px; }
</style>
'@

    $summaryRows = [System.Text.StringBuilder]::new()
    foreach ($r in $Results) {
        Write-Verbose "  Summary row: $($r.ServerName) [$($r.Status)]"
        $statusEmoji = Get-StatusEmoji -Status $r.Status
        $statusClass = "status-$($r.Status.ToLower())"
        $statusText = Get-StatusText -Status $r.Status

        $cert = Get-SafeProperty $r.JsonResult 'certificate'
        $certSubject = if ($cert) { [System.Web.HttpUtility]::HtmlEncode((Get-SafeProperty $cert 'subject')) } else { '—' }
        $expiryDate = if ($cert -and (Get-SafeProperty $cert 'validTo')) { ([datetime](Get-SafeProperty $cert 'validTo')).ToString('yyyy-MM-dd') } else { '—' }
        $daysLeft = if ($cert) { Get-SafeProperty $cert 'daysUntilExpiry' } else { '—' }
        $tls = Get-SafeProperty $r.JsonResult 'tls'
        $tlsVersion = if ($tls) { [System.Web.HttpUtility]::HtmlEncode((Get-SafeProperty $tls 'protocol')) } else { '—' }
        $issueCount = @($r.Issues).Count

        [void]$summaryRows.AppendLine("        <tr>")
        [void]$summaryRows.AppendLine("            <td>$([System.Web.HttpUtility]::HtmlEncode($r.ServerName))</td>")
        [void]$summaryRows.AppendLine("            <td class=`"$statusClass`">$statusEmoji $statusText</td>")
        [void]$summaryRows.AppendLine("            <td>$certSubject</td>")
        [void]$summaryRows.AppendLine("            <td>$expiryDate</td>")
        [void]$summaryRows.AppendLine("            <td>$daysLeft</td>")
        [void]$summaryRows.AppendLine("            <td>$tlsVersion</td>")
        [void]$summaryRows.AppendLine("            <td>$issueCount</td>")
        [void]$summaryRows.AppendLine("        </tr>")
    }

    $detailSections = [System.Text.StringBuilder]::new()
    foreach ($r in $Results) {
        Write-Verbose "  Detail section: $($r.ServerName)"
        $statusEmoji = Get-StatusEmoji -Status $r.Status
        $statusText = Get-StatusText -Status $r.Status
        $serverEnc = [System.Web.HttpUtility]::HtmlEncode($r.ServerName)

        [void]$detailSections.AppendLine("<details>")
        [void]$detailSections.AppendLine("    <summary>$statusEmoji $serverEnc — $statusText</summary>")
        [void]$detailSections.AppendLine("    <div class=`"detail-body`">")

        [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
        [void]$detailSections.AppendLine("            <h4>Command Line</h4>")
        [void]$detailSections.AppendLine("            <div class=`"cmd-line`">$([System.Web.HttpUtility]::HtmlEncode($r.CommandLine))</div>")
        [void]$detailSections.AppendLine("        </div>")

        if (@($r.Issues).Count -gt 0) {
            [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
            [void]$detailSections.AppendLine("            <h4>Issues</h4>")
            [void]$detailSections.AppendLine("            <ul class=`"issue-list`">")
            foreach ($issue in $r.Issues) {
                [void]$detailSections.AppendLine("                <li>$([System.Web.HttpUtility]::HtmlEncode($issue))</li>")
            }
            [void]$detailSections.AppendLine("            </ul>")
            [void]$detailSections.AppendLine("        </div>")
        }

        if ($r.JsonResult) {
            $json = $r.JsonResult
            Write-Verbose "    Processing JSON sections for $($r.ServerName)..."

            if ($json.PSObject.Properties.Name -contains 'connection' -and $json.connection) {
                Write-Verbose "      Connection details section"
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>Connection Details</h4>")
                [void]$detailSections.AppendLine("            <table class=`"detail-table`">")
                $connFields = @(
                    ,@('Server', (Get-SafeProperty $json.connection 'serverName'))
                    ,@('Resolved Host', (Get-SafeProperty $json.connection 'resolvedHost'))
                    ,@('Resolved Port', (Get-SafeProperty $json.connection 'resolvedPort'))
                    ,@('Connected IP', (Get-SafeProperty $json.connection 'connectedIP'))
                    ,@('Instance Name', (Get-SafeProperty $json.connection 'instanceName'))
                    ,@('SQL Server Version', (Get-SafeProperty $json.connection 'sqlServerVersion'))
                    ,@('Encryption Mode', (Get-SafeProperty $json.connection 'encryptionMode'))
                    ,@('TDS Protocol', (Get-SafeProperty $json.connection 'tdsProtocol'))
                )
                foreach ($f in $connFields) {
                    if ($f[1]) {
                        [void]$detailSections.AppendLine("            <tr><td>$($f[0])</td><td>$([System.Web.HttpUtility]::HtmlEncode([string]$f[1]))</td></tr>")
                    }
                }
                [void]$detailSections.AppendLine("            </table>")
                [void]$detailSections.AppendLine("        </div>")
            }

            if ($json.PSObject.Properties.Name -contains 'certificate' -and $json.certificate) {
                Write-Verbose "      Certificate details section"
                $c = $json.certificate
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>Certificate Details</h4>")
                [void]$detailSections.AppendLine("            <table class=`"detail-table`">")
                $certFields = @(
                    ,@('Subject', (Get-SafeProperty $c 'subject'))
                    ,@('Issuer', (Get-SafeProperty $c 'issuer'))
                    ,@('Serial Number', (Get-SafeProperty $c 'serialNumber'))
                    ,@('Thumbprint (SHA-1)', (Get-SafeProperty $c 'thumbprintSha1'))
                    ,@('Fingerprint (SHA-256)', (Get-SafeProperty $c 'thumbprintSha256'))
                    ,@('Valid From', (Get-SafeProperty $c 'validFrom'))
                    ,@('Valid To', (Get-SafeProperty $c 'validTo'))
                    ,@('Days Until Expiry', (Get-SafeProperty $c 'daysUntilExpiry'))
                    ,@('Key Algorithm', "$(Get-SafeProperty $c 'keyAlgorithm') ($(Get-SafeProperty $c 'keySizeBits') bits)")
                    ,@('Signature Algorithm', (Get-SafeProperty $c 'signatureAlgorithm'))
                    ,@('Self-Signed', (Get-SafeProperty $c 'isSelfSigned'))
                )
                foreach ($f in $certFields) {
                    if ($null -ne $f[1]) {
                        [void]$detailSections.AppendLine("            <tr><td>$($f[0])</td><td>$([System.Web.HttpUtility]::HtmlEncode([string]$f[1]))</td></tr>")
                    }
                }
                if (($c.PSObject.Properties.Name -contains 'subjectAlternativeNames') -and $c.subjectAlternativeNames -and @($c.subjectAlternativeNames).Count -gt 0) {
                    $sanHtml = ($c.subjectAlternativeNames | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''
                    [void]$detailSections.AppendLine("            <tr><td>SANs</td><td><ul class=`"san-list`">$sanHtml</ul></td></tr>")
                }
                [void]$detailSections.AppendLine("            </table>")
                [void]$detailSections.AppendLine("        </div>")
            }

            if ($json.PSObject.Properties.Name -contains 'tls' -and $json.tls) {
                Write-Verbose "      TLS section"
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>TLS Connection Security</h4>")
                [void]$detailSections.AppendLine("            <table class=`"detail-table`">")
                $tlsFields = @(
                    ,@('Protocol', (Get-SafeProperty $json.tls 'protocol'))
                    ,@('Cipher Suite', (Get-SafeProperty $json.tls 'cipherSuite'))
                    ,@('Key Exchange', "$(Get-SafeProperty $json.tls 'keyExchangeAlgorithm') ($(Get-SafeProperty $json.tls 'keyExchangeStrength') bits)")
                    ,@('Hash Algorithm', "$(Get-SafeProperty $json.tls 'hashAlgorithm') ($(Get-SafeProperty $json.tls 'hashStrength') bits)")
                )
                foreach ($f in $tlsFields) {
                    if ($f[1]) {
                        [void]$detailSections.AppendLine("            <tr><td>$($f[0])</td><td>$([System.Web.HttpUtility]::HtmlEncode([string]$f[1]))</td></tr>")
                    }
                }
                [void]$detailSections.AppendLine("            </table>")
                [void]$detailSections.AppendLine("        </div>")
            }

            if ($json.PSObject.Properties.Name -contains 'warnings' -and $json.warnings -and @($json.warnings).Count -gt 0) {
                Write-Verbose "      Warnings section"
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>Warnings</h4>")
                [void]$detailSections.AppendLine("            <ul class=`"warning-list`">")
                foreach ($w in $json.warnings) {
                    $wSeverity = Get-SafeProperty $w 'severity'
                    $wMessage = Get-SafeProperty $w 'message'
                    [void]$detailSections.AppendLine("                <li><strong>[$wSeverity]</strong> $([System.Web.HttpUtility]::HtmlEncode($wMessage))</li>")
                }
                [void]$detailSections.AppendLine("            </ul>")
                [void]$detailSections.AppendLine("        </div>")
            }

            if ($json.PSObject.Properties.Name -contains 'kerberos' -and $json.kerberos -and $json.kerberos.PSObject.Properties.Name -contains 'dns' -and $json.kerberos.dns) {
                Write-Verbose "      DNS section"
                $dns = $json.kerberos.dns
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>DNS Resolution</h4>")
                [void]$detailSections.AppendLine("            <table class=`"detail-table`">")
                $dnsFields = @(
                    ,@('Requested Hostname', (Get-SafeProperty $dns 'requestedHostname'))
                    ,@('Resolved FQDN', (Get-SafeProperty $dns 'resolvedFqdn'))
                    ,@('DNS Suffix Used', (Get-SafeProperty $dns 'dnsSuffixUsed'))
                    ,@('Record Types', ((Get-SafeProperty $dns 'dnsRecordTypes') -join ', '))
                    ,@('Resolved IPs', ((Get-SafeProperty $dns 'resolvedIpAddresses') -join ', '))
                    ,@('Reverse Hostname', (Get-SafeProperty $dns 'reverseHostname'))
                    ,@('CNAME Target', (Get-SafeProperty $dns 'cnameTarget'))
                )
                foreach ($f in $dnsFields) {
                    if ($f[1]) {
                        [void]$detailSections.AppendLine("            <tr><td>$($f[0])</td><td>$([System.Web.HttpUtility]::HtmlEncode([string]$f[1]))</td></tr>")
                    }
                }
                [void]$detailSections.AppendLine("            </table>")
                [void]$detailSections.AppendLine("        </div>")
            }

            if ($json.PSObject.Properties.Name -contains 'kerberos' -and $json.kerberos -and $json.kerberos.PSObject.Properties.Name -contains 'spns' -and $json.kerberos.spns -and @($json.kerberos.spns).Count -gt 0) {
                Write-Verbose "      SPN section"
                [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
                [void]$detailSections.AppendLine("            <h4>Kerberos SPN Registration</h4>")
                [void]$detailSections.AppendLine("            <table class=`"detail-table`">")
                foreach ($spn in $json.kerberos.spns) {
                    $spnFound = Get-SafeProperty $spn 'found'
                    $spnAccount = Get-SafeProperty $spn 'accountName'
                    $spnLabel = Get-SafeProperty $spn 'label'
                    $spnValue = Get-SafeProperty $spn 'spn'
                    $spnStatus = if ($spnFound) { "REGISTERED &#x2192; $([System.Web.HttpUtility]::HtmlEncode($spnAccount))" } else { '<span style="color:#dc2626">NOT FOUND</span>' }
                    [void]$detailSections.AppendLine("            <tr><td>$([System.Web.HttpUtility]::HtmlEncode($spnLabel))</td><td><code>$([System.Web.HttpUtility]::HtmlEncode($spnValue))</code> $spnStatus</td></tr>")
                }
                [void]$detailSections.AppendLine("            </table>")
                [void]$detailSections.AppendLine("        </div>")
            }
        }
        elseif ($r.RawOutput) {
            [void]$detailSections.AppendLine("        <div class=`"detail-section`">")
            [void]$detailSections.AppendLine("            <h4>Raw Output</h4>")
            [void]$detailSections.AppendLine("            <div class=`"cmd-line`">$([System.Web.HttpUtility]::HtmlEncode($r.RawOutput))</div>")
            [void]$detailSections.AppendLine("        </div>")
        }

        [void]$detailSections.AppendLine("    </div>")
        [void]$detailSections.AppendLine("</details>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Certificate Health Report</title>
$css
</head>
<body>
<div class="container">
    <div class="report-header">
        <h1>SQL Certificate Health Report</h1>
        <div class="meta">Generated: $timestamp | Tool: sql-cert-inspector $ToolVersion | Servers: $totalServers</div>
    </div>

    <div class="summary-bar">
        <table class="summary-table"><tr>
            <td class="card-total"><div class="summary-count">$totalServers</div><div class="summary-label">Total</div></td>
            <td class="card-critical"><div class="summary-count">$criticalCount</div><div class="summary-label">Critical</div></td>
            <td class="card-warning"><div class="summary-count">$warningCount</div><div class="summary-label">Warning</div></td>
            <td class="card-error"><div class="summary-count">$errorCount</div><div class="summary-label">Error</div></td>
            <td class="card-healthy"><div class="summary-count">$healthyCount</div><div class="summary-label">Healthy</div></td>
        </tr></table>
    </div>

    <table>
        <thead>
            <tr>
                <th>Server</th>
                <th>Status</th>
                <th>Certificate Subject</th>
                <th>Expiry Date</th>
                <th>Days Left</th>
                <th>TLS Version</th>
                <th>Issues</th>
            </tr>
        </thead>
        <tbody>
$($summaryRows.ToString())
        </tbody>
    </table>

    <div style="padding: 20px 30px;">
        <h2 style="font-size: 18px; color: #1e40af; margin-bottom: 12px;">Server Details</h2>
$($detailSections.ToString())
    </div>

    <div class="footer">
        Execution time: $($ElapsedTime.ToString('hh\:mm\:ss')) |
        Tool: <code>$([System.Web.HttpUtility]::HtmlEncode($ExeFullPath))</code> |
        Sent from: <code>$([System.Web.HttpUtility]::HtmlEncode($machineFqdn))</code>
    </div>
</div>
</body>
</html>
"@

    return $html
}

#endregion

#region Email Subject

function Build-EmailSubject {
    <#
    .SYNOPSIS
        Builds a dynamic email subject line reflecting the worst health status.
    #>
    param ([array]$Results)

    $criticalCount = @($Results | Where-Object { $_.Status -eq 'Critical' }).Count
    $warningCount = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $errorCount = @($Results | Where-Object { $_.Status -eq 'Error' }).Count
    $date = Get-Date -Format 'yyyy-MM-dd'

    if ($criticalCount -gt 0) {
        $noun = if ($criticalCount -eq 1) { 'certificate' } else { 'certificates' }
        return "CRITICAL: $criticalCount $noun expiring — SQL Certificate Health Report — $date"
    }
    if ($errorCount -gt 0) {
        $noun = if ($errorCount -eq 1) { 'server' } else { 'servers' }
        return "ERROR: $errorCount $noun unreachable — SQL Certificate Health Report — $date"
    }
    if ($warningCount -gt 0) {
        $noun = if ($warningCount -eq 1) { 'issue' } else { 'issues' }
        return "WARNING: $warningCount $noun found — SQL Certificate Health Report — $date"
    }
    return "All Healthy — SQL Certificate Health Report — $date"
}

#endregion

#region Main Execution

if ($Setup) {
    Invoke-Setup
    return
}

Add-Type -AssemblyName System.Web

if (-not $InputFile) {
    Write-Error 'The -InputFile parameter is required unless -Setup is specified.'
    exit 1
}

$inputFileResolved = if ([System.IO.Path]::IsPathRooted($InputFile)) { $InputFile } else { Join-Path (Get-Location) $InputFile }

if (-not (Test-Path $inputFileResolved)) {
    if (Test-Interactive) {
        Write-Host "Input file not found: $inputFileResolved" -ForegroundColor Yellow
        $create = Read-Host 'Create a sample file at this location? (Y/N)'
        if ($create -match '^[Yy]') {
            $parentDir = Split-Path $inputFileResolved -Parent
            if (-not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }
            New-SampleInputFile -Path $inputFileResolved
            Write-Host "Sample file created: $inputFileResolved" -ForegroundColor Green
            Write-Host 'Edit the file to add your servers (remove the # comment prefix), then re-run.' -ForegroundColor Cyan
            exit 0
        }
    }
    Write-Error "Input file not found: $inputFileResolved"
    exit 1
}

$fileContent = Get-Content -Path $inputFileResolved -Encoding UTF8
$nonCommentLines = @($fileContent | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') })
if ($nonCommentLines.Count -lt 2) {
    if (Test-Interactive) {
        Write-Host "Input file is empty or contains only comments: $inputFileResolved" -ForegroundColor Yellow
        Write-Host 'Edit the file to add your servers (remove the # comment prefix), then re-run.' -ForegroundColor Cyan
    }
    else {
        Write-Error "Input file is empty or contains only comments: $inputFileResolved"
    }
    exit 1
}

$effectiveExePath = $ExePath
if ($effectiveExePath -eq '.' -and -not $PSBoundParameters.ContainsKey('ExePath')) {
    $savedConfig = Get-SmtpConfig
    if ($savedConfig -and ($savedConfig.PSObject.Properties.Name -contains 'exePath') -and $savedConfig.exePath) {
        $effectiveExePath = $savedConfig.exePath
    }
}

if ($effectiveExePath -match '(?i)sql-cert-inspector(\.exe)?$') {
    $effectiveExePath = Split-Path $effectiveExePath -Parent
}

$exeDir = if ([System.IO.Path]::IsPathRooted($effectiveExePath)) { $effectiveExePath } else { Join-Path (Get-Location) $effectiveExePath }
$exeFullPath = Join-Path $exeDir 'sql-cert-inspector.exe'

if (-not (Test-Path $exeFullPath)) {
    Write-Error "sql-cert-inspector.exe not found at: $exeFullPath"
    exit 1
}

$servers = Read-ServerList -Path $inputFileResolved -ValidateDns:$ValidateDns
Write-Verbose "Loaded $($servers.Count) server(s) from $inputFileResolved"

if ($WhatIfPreference) {
    Write-Host ''
    Write-Host '=== WhatIf Mode — No inspections will be performed ===' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "Input file:   $inputFileResolved"
    Write-Host "Executable:   $exeFullPath"
    Write-Host "Server count: $($servers.Count)"
    if ($Timeout -gt 0) { Write-Host "Global timeout: $Timeout seconds" }
    Write-Host ''

    $tableData = @()
    foreach ($s in $servers) {
        $cmdLine = Format-DisplayCommandLine -ExeFullPath $exeFullPath -Server $s -GlobalTimeout $Timeout
        $tableData += [PSCustomObject]@{
            Server  = $s.ServerName
            Port    = if ($s.Port -gt 0) { $s.Port } else { '(default)' }
            TDS     = if ($s.TdsVersion) { $s.TdsVersion } else { '7.x' }
            Timeout = if ($s.Timeout -gt 0) { $s.Timeout } elseif ($Timeout -gt 0) { "$Timeout (global)" } else { '5 (default)' }
            Command = $cmdLine
        }
    }

    $tableData | Format-Table -AutoSize -Wrap
    Write-Host ''
    Write-Host 'No actions were taken.' -ForegroundColor Yellow
    exit 0
}

$toolVersion = ''
try {
    $versionOutput = & $exeFullPath --version 2>&1
    $toolVersion = ($versionOutput | Select-Object -First 1).Trim()
}
catch {
    $toolVersion = 'unknown'
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$results = @()

Write-Host ''
Write-Host "=== SQL Certificate Health Check ===" -ForegroundColor Cyan
Write-Host "Inspecting $($servers.Count) server(s)..." -ForegroundColor White
Write-Host ''

$serverIndex = 0
foreach ($server in $servers) {
    $serverIndex++
    Write-Host "[$serverIndex/$($servers.Count)] $($server.ServerName)..." -NoNewline

    $inspectArgs = Build-InspectorArgs -Server $server -GlobalTimeout $Timeout -IncludeJson
    $displayCmd = Format-DisplayCommandLine -ExeFullPath $exeFullPath -Server $server -GlobalTimeout $Timeout
    Write-Verbose "Command: $displayCmd"

    $stdOut = ''
    $stdErr = ''
    $exitCode = 0
    $jsonResult = $null

    try {
        $procInfo = New-Object System.Diagnostics.ProcessStartInfo
        $procInfo.FileName = $exeFullPath
        $procInfo.Arguments = ($inspectArgs | ForEach-Object {
            if ($_ -match '\s|\\') { "`"$_`"" } else { $_ }
        }) -join ' '
        $procInfo.UseShellExecute = $false
        $procInfo.RedirectStandardOutput = $true
        $procInfo.RedirectStandardError = $true
        $procInfo.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($procInfo)
        $stdOut = $proc.StandardOutput.ReadToEnd()
        $stdErr = $proc.StandardError.ReadToEnd()

        # Compute per-server timeout for WaitForExit: use server-specific,
        # then global, then default of 30 seconds. Add 10s grace period
        # beyond the exe's own --timeout to allow clean exit.
        $serverTimeout = if ($server.Timeout -gt 0) { $server.Timeout } elseif ($Timeout -gt 0) { $Timeout } else { 30 }
        $waitMs = ($serverTimeout + 10) * 1000

        if (-not $proc.WaitForExit($waitMs)) {
            try { $proc.Kill() } catch { }
            $exitCode = 124
            $stdErr = "Process timed out after $($serverTimeout + 10) seconds and was terminated."
        }
        else {
            $exitCode = $proc.ExitCode
        }

        $proc.Dispose()
    }
    catch {
        $exitCode = 5
        $stdErr = $_.Exception.Message
    }

    if ($exitCode -eq 0 -and $stdOut) {
        try {
            $jsonResult = $stdOut | ConvertFrom-Json
            Write-Verbose "JSON parsed successfully for $($server.ServerName)"
        }
        catch {
            $stdErr = "Failed to parse JSON output: $($_.Exception.Message)"
            $exitCode = 5
        }
    }
    else {
        Write-Verbose "Skipping JSON parse for $($server.ServerName): exitCode=$exitCode, stdOut length=$($stdOut.Length)"
    }

    $status = Get-HealthStatus -JsonResult $jsonResult -ExitCode $exitCode
    $issues = Get-IssueList -JsonResult $jsonResult -ExitCode $exitCode -StdErr $stdErr
    Write-Verbose "Status: $status, Issues: $(@($issues).Count)"

    $statusColor = switch ($status) {
        'Critical' { 'Red' }
        'Warning'  { 'Yellow' }
        'Healthy'  { 'Green' }
        'Error'    { 'DarkGray' }
        default    { 'White' }
    }
    Write-Host " $(Get-StatusText -Status $status)" -ForegroundColor $statusColor

    $results += [PSCustomObject]@{
        ServerName  = $server.ServerName
        Status      = $status
        Issues      = @($issues)
        JsonResult  = $jsonResult
        ExitCode    = $exitCode
        RawOutput   = if (-not $jsonResult) { "$stdOut`n$stdErr".Trim() } else { $null }
        CommandLine = $displayCmd
    }
}

$stopwatch.Stop()
Write-Host ''

Write-Verbose "Building HTML report..."
$html = Build-HtmlReport -Results $results -ExeFullPath $exeFullPath -GlobalTimeout $Timeout -ToolVersion $toolVersion -ElapsedTime $stopwatch.Elapsed
Write-Verbose "HTML report built ($($html.Length) chars)"

if ($OutputPath) {
    $outputResolved = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path (Get-Location) $OutputPath }
    $parentDir = Split-Path $outputResolved -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    $html | Set-Content -Path $outputResolved -Encoding UTF8
    Write-Host "Report saved to: $outputResolved" -ForegroundColor Green
}

$hasIssues = @($results | Where-Object { $_.Status -in @('Critical', 'Warning', 'Error') }).Count -gt 0
$shouldSendEmail = ($hasIssues -or $AlwaysSendEmail)

if ($shouldSendEmail) {
    $smtpConfig = Get-SmtpConfig
    if ($smtpConfig) {
        $smtpPassword = $null
        if (Get-SafeProperty $smtpConfig 'useAuthentication') {
            $smtpPassword = Get-StoredCredential -Target $script:CredentialTarget
            if (-not $smtpPassword) {
                Write-Warning "SMTP authentication is enabled but no credential found in Credential Manager (target: $($script:CredentialTarget)). Run -Setup to configure. Skipping email."
                $shouldSendEmail = $false
            }
        }

        if ($shouldSendEmail) {
            $emailSubject = Build-EmailSubject -Results $results
            try {
                Send-SmtpEmail -Config $smtpConfig -Subject $emailSubject -Body $html -Password $smtpPassword
                Write-Host "Email sent: $(Get-SafeProperty $smtpConfig 'toAddress')" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to send email: $($_.Exception.Message)"
            }
        }
    }
    else {
        if ($AlwaysSendEmail) {
            Write-Warning "SMTP is not configured. Run with -Setup to configure email delivery."
        }
    }
}

$criticalCount = @($results | Where-Object { $_.Status -eq 'Critical' }).Count
$warningCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
$errorCount = @($results | Where-Object { $_.Status -eq 'Error' }).Count
$healthyCount = @($results | Where-Object { $_.Status -eq 'Healthy' }).Count

Write-Host ''
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "  Total:    $($results.Count)"
if ($criticalCount -gt 0) { Write-Host "  Critical: $criticalCount" -ForegroundColor Red }
if ($warningCount -gt 0)  { Write-Host "  Warning:  $warningCount" -ForegroundColor Yellow }
if ($errorCount -gt 0)    { Write-Host "  Error:    $errorCount" -ForegroundColor DarkGray }
Write-Host "  Healthy:  $healthyCount" -ForegroundColor Green
Write-Host "  Time:     $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
Write-Host ''

if ($criticalCount -gt 0) { exit 2 }
if ($errorCount -gt 0) { exit 1 }
if ($warningCount -gt 0) { exit 3 }
exit 0

#endregion
