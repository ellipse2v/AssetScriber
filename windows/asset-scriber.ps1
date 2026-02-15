# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# AssetScriber - An SBOM generation and discovery script (PowerShell Version)
# It uses syft to scan local and remote targets without installing agents.
param (
    [string]$Path = "",
    [string]$Config = "",
    [switch]$Discover,
    [switch]$OsOnly
)

# --- Configuration ---
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BIN_DIR = Join-Path $SCRIPT_DIR "bin"
$SYFT_PATH = Join-Path $BIN_DIR "syft.exe"
$JQ_PATH = Join-Path $BIN_DIR "jq.exe"
$OUTPUT_DIR = Join-Path $SCRIPT_DIR "asset_scriber_output"
$INTERMEDIATE_DIR = Join-Path $OUTPUT_DIR "intermediate"
$CSV_OUTPUT_PATH = Join-Path $OUTPUT_DIR "master_asset_list.csv"
$STATUS_REPORT_LOG = Join-Path $OUTPUT_DIR "status_report.log"

# --- Global Variables ---
$IS_ROOT = $false
$SCANNED_HOSTS = @()

# --- Utility Functions ---

function Log-Message {
    param (
        [Parameter(Mandatory=$true)][string]$Type,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $FormattedMessage = ""
    switch ($Type) {
        "INFO"    { $FormattedMessage = "`e[0;34m[INFO]`e[0m $Message" } # Blue
        "SUCCESS" { $FormattedMessage = "`e[0;32m[SUCCESS]`e[0m $Message" } # Green
        "WARN"    { $FormattedMessage = "`e[0;33m[WARN]`e[0m $Message" } # Yellow
        "ERROR"   { $FormattedMessage = "`e[0;31m[ERROR]`e[0m $Message" } # Red
        default   { $FormattedMessage = $Message }
    }

    Write-Host -ForegroundColor White $FormattedMessage
    Add-Content -Path $STATUS_REPORT_LOG -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Type] $Message"
}

function Test-CommandExistence {
    param (
        [Parameter(Mandatory=$true)][string]$Command
    )
    (Get-Command -Name $Command -ErrorAction SilentlyContinue) -ne $null
}

function Test-RootPrivileges {
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $IS_ROOT = $true
        Log-Message -Type "INFO" -Message "Script is running with administrator privileges."
    } else {
        $IS_ROOT = $false
        Log-Message -Type "WARN" -Message "Script is running without administrator privileges. Scans will be limited."
    }
}

function Show-Help {
    Write-Host "Usage: PowerShell.exe -File asset-scriber.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Path <path>             Scan a local filesystem path."
    Write-Host "  -Config <file>           Scan hosts listed in the specified config file."
    Write-Host "                           Format per line: <ip/host> [user] [password]"
    Write-Host "  -Discover                Discover and attempt to scan hosts on the local network."
    Write-Host "  -OsOnly                  Only include operating system packages in the output."
    Write-Host "  -Help                    Display this help message."
    Write-Host ""
    Write-Host "If no option is provided, the script scans the local system ('/' if root, '.' otherwise)."
}

# --- Core Functions ---

function Setup-Syft {
    Log-Message -Type "INFO" -Message "Checking for syft executable..."
    if (Test-Path $SYFT_PATH) {
        Log-Message -Type "SUCCESS" -Message "syft found at '$SYFT_PATH'."
        return $true
    }
    
    Log-Message -Type "ERROR" -Message "syft not found at '$SYFT_PATH'. Please ensure it's present."
    return $false
}

function Setup-Jq {
    Log-Message -Type "INFO" -Message "Checking for jq executable..."
    if (Test-Path $JQ_PATH) {
        Log-Message -Type "SUCCESS" -Message "jq found at '$JQ_PATH'."
        return $true
    }
    
    Log-Message -Type "ERROR" -Message "jq not found at '$JQ_PATH'. Please ensure it's present."
    return $false
}

function Process-SbomToCsv {
    param (
        [Parameter(Mandatory=$true)][string]$SbomFile,
        [Parameter(Mandatory=$true)][string]$Hostname
    )

    if (-not (Test-Path $JQ_PATH)) {
        Log-Message -Type "ERROR" -Message "jq path is not set. Cannot process SBOM JSON files."
        return $false
    }

    Log-Message -Type "INFO" -Message "Creating intermediate data for host '$Hostname'..."

    $DistroId = (&$JQ_PATH -r '.metadata.component.properties[]? | select(.name == "distro:id") | .value' $SbomFile)
    if (-not $DistroId) { $DistroId = "unknown" }

    $JqFilter = @"
.components[]? |
(
    . as `$component |
    (if `$component.type == "go-module" and (`$component.name | contains("/")) then
        (`$component.name | split("/") | .[-1])
    else
        `$component.name
    end) as `$final_name |
    [
        `$distro,
        `$final_name,
        `$component.version,
        (`$component.cpe // "N/A"),
        (`$component.purl // "N/A")
    ] | @csv
)
"@

    $IntermediateCsvPath = Join-Path $INTERMEDIATE_DIR "$Hostname.csv"
    
    # Create the header for the intermediate file
    Set-Content -Path $IntermediateCsvPath -Value "distro,name,version,cpe,purl"
    
    &$JQ_PATH -r --arg distro $DistroId $JqFilter $SbomFile | Add-Content -Path $IntermediateCsvPath

    Log-Message -Type "SUCCESS" -Message "Intermediate data for '$Hostname' created at '$IntermediateCsvPath'."
    return $true
}

function Perform-LocalScan {
    param (
        [Parameter(Mandatory=$true)][string]$ScanPath,
        [Parameter(Mandatory=$true)][string]$Hostname,
        [Parameter(Mandatory=$false)][switch]$OsOnly
    )

    Log-Message -Type "INFO" -Message "Starting local scan for host: '$Hostname' (Path: $ScanPath)"

    $SbomOutputPath = Join-Path $OUTPUT_DIR "sbom_$($Hostname -replace '[/\\]','_').json"

    $SyftArgs = @("scan", "dir:$ScanPath", "--output", "cyclonedx-json=$SbomOutputPath")

    if ($OsOnly) {
        $SyftArgs += @("--scope", "squashed")
    }

    $Process = Start-Process -FilePath $SYFT_PATH -ArgumentList $SyftArgs -Wait -PassThru -NoNewWindow
    $ExitCode = $Process.ExitCode

    if ($ExitCode -ne 0) {
        Log-Message -Type "ERROR" -Message "Syft scan failed for '$Hostname' with exit code $ExitCode."
        Remove-Item -Path $SbomOutputPath -ErrorAction SilentlyContinue
        return $false
    }

    Log-Message -Type "SUCCESS" -Message "SBOM generated for '$Hostname' at '$SbomOutputPath'."
    Process-SbomToCsv -SbomFile $SbomOutputPath -Hostname $Hostname
    return $true
}

function Perform-RemoteScan {
    param (
        [Parameter(Mandatory=$true)][string]$RemoteHost,
        [Parameter(Mandatory=$true)][string]$User,
        [Parameter(Mandatory=$false)][string]$Pass,
        [Parameter(Mandatory=$true)][string]$ScanTarget,
        [Parameter(Mandatory=$false)][switch]$OsOnly
    )

    if ($SCANNED_HOSTS -contains $RemoteHost) {
        Log-Message -Type "WARN" -Message "Host '$RemoteHost' has already been scanned. Skipping."
        return $true
    }

    # Check for rsync existence - assuming Git Bash or similar for rsync/ssh on Windows
    if (-not (Test-CommandExistence "rsync")) {
        Log-Message -Type "ERROR" -Message "Skipping remote scan of '$RemoteHost': 'rsync' command not found. Please ensure Git Bash or WSL is installed and rsync is in PATH."
        return $false
    }
    if (-not (Test-CommandExistence "ssh")) {
        Log-Message -Type "ERROR" -Message "Skipping remote scan of '$RemoteHost': 'ssh' command not found. Please ensure Git Bash or WSL is installed and ssh is in PATH."
        return $false
    }

    $RsyncCmdArgs = @("-a", "-z")
    $SshOpts = @("-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10")

    if ($Pass) {
        if (-not (Test-CommandExistence "sshpass")) {
            Log-Message -Type "ERROR" -Message "Skipping remote scan of '$RemoteHost': 'sshpass' is required for password authentication but is not installed."
            return $false
        }
        $RsyncCmdArgs = @("-e", "sshpass -p '$Pass' ssh $SshOpts", $RsyncCmdArgs)
    } else {
        $RsyncCmdArgs = @("-e", "ssh $SshOpts", $RsyncCmdArgs)
    }

    $TempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "assetscriber-rsync-$((New-Guid).ToString().Substring(0,8))") -Force
    Log-Message -Type "INFO" -Message "Created temporary directory for rsync: $($TempDir.FullName)"

    $RsyncSourcePath = $ScanTarget
    if (-not ($RsyncSourcePath.EndsWith("/"))) { $RsyncSourcePath += "/" }

    $RsyncConnectionString = "{0}@{1}:{2}" -f $User, $RemoteHost, $RsyncSourcePath
    Log-Message -Type "INFO" -Message "Starting rsync of '$RsyncConnectionString' to '$($TempDir.FullName)'. This may take a long time and consume significant disk space."
    
    $RsyncResult = Start-Process -FilePath "rsync" -ArgumentList @($RsyncCmdArgs, $RsyncConnectionString, "$($TempDir.FullName)/") -Wait -PassThru -NoNewWindow
    $RsyncExitCode = $RsyncResult.ExitCode

    if ($RsyncExitCode -ne 0) {
        Log-Message -Type "ERROR" -Message "Rsync failed for host '$RemoteHost' with exit code $RsyncExitCode."
        Remove-Item -Path $TempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        Log-Message -Type "INFO" -Message "Cleaned up temporary directory: $($TempDir.FullName)"
        return $false
    }
    Log-Message -Type "SUCCESS" -Message "Rsync completed for host '$RemoteHost'."

    $ScanResult = Perform-LocalScan -ScanPath $TempDir.FullName -Hostname $RemoteHost -OsOnly:$OsOnly
    $ScanExitCode = $? # Get last command's success/failure

    Log-Message -Type "INFO" -Message "Cleaning up temporary directory: $($TempDir.FullName)"
    Remove-Item -Path $TempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
    Log-Message -Type "SUCCESS" -Message "Finished cleanup for host '$RemoteHost'."

    if ($ScanResult) {
        $SCANNED_HOSTS += $RemoteHost
    }
    return $ScanResult
}

function Discover-Network {
    param (
        [Parameter(Mandatory=$false)][switch]$OsOnly
    )

    if (-not (Test-CommandExistence "nmap")) {
        Log-Message -Type "ERROR" -Message "Skipping network discovery: 'nmap' command not found. Please ensure nmap is installed and in PATH."
        return $false
    }
    # Windows doesn't have a direct equivalent of 'ip -o -f inet addr show | awk ...'
    # This part would need a more robust PowerShell-specific implementation
    Log-Message -Type "WARN" -Message "Network discovery for PowerShell is currently limited. Will attempt to use a default subnet or require manual input."
    
    # Placeholder for subnet discovery on Windows
    $Subnet = "192.168.1.0/24" # Example, this needs to be dynamically determined or user-provided
    Log-Message -Type "INFO" -Message "Using assumed subnet '$Subnet' for network discovery. This may not work correctly."

    Log-Message -Type "INFO" -Message "Scanning subnet '$Subnet' with nmap..."
    $Hosts = (nmap -sn $Subnet | Select-String -Pattern "Nmap scan report for" | ForEach-Object { ($_.ToString() -split " " | Select-Object -Last 1) -replace "[()]","" })
    
    Log-Message -Type "INFO" -Message "Discovered hosts: $($Hosts -join ', ')"

    $CurrentUser = $env:USERNAME
    foreach ($DiscoveredHost in $Hosts) {
        Log-Message -Type "INFO" -Message "Attempting to scan discovered host '$DiscoveredHost' as user '$CurrentUser'."
        Log-Message -Type "WARN" -Message "This will only work if passwordless SSH key authentication is configured for '$CurrentUser@$DiscoveredHost'."
        Perform-RemoteScan -RemoteHost $DiscoveredHost -User $CurrentUser -ScanTarget "/" -OsOnly:$OsOnly
    }
    return $true
}

function Generate-FinalCsv {
    Log-Message -Type "INFO" -Message "Generating the final master CSV file..."

    $IntermediateFiles = Get-ChildItem -Path $INTERMEDIATE_DIR -Filter "*.csv" -File

    if (-not $IntermediateFiles) {
        Log-Message -Type "WARN" -Message "No intermediate CSV files were found. Skipping final CSV generation."
        return $false
    }

    $Hosts = @()
    foreach ($File in $IntermediateFiles) {
        $Hosts += $File.BaseName
    }
    $HostList = ($Hosts | ForEach-Object { ",$_" }) -join ""

    # Create the header
    Set-Content -Path $CSV_OUTPUT_PATH -Value "distro,name,version,cpe,purl$HostList"

    # Use a Hashtable to store package data for pivoting
    $PackageData = @{}
    $AllPackageKeys = @()

    foreach ($File in $IntermediateFiles) {
        $Hostname = $File.BaseName
        $Content = Get-Content $File.FullName | Select-Object -Skip 1 # Skip header
        foreach ($Line in $Content) {
            $Parts = $Line -split ','
            if ($Parts.Count -ge 5) {
                $PackageKey = "$($Parts[0]),$($Parts[1]),$($Parts[2]),$($Parts[3]),$($Parts[4])"
                if (-not ($AllPackageKeys -contains $PackageKey)) {
                    $AllPackageKeys += $PackageKey
                }
                $PackageData["$PackageKey`t$Hostname"] = 1
            }
        }
    }

    # Sort package keys for consistent output
    $AllPackageKeys = $AllPackageKeys | Sort-Object

    # Append data to the CSV
    foreach ($PackageKey in $AllPackageKeys) {
        $OutputLine = "$PackageKey"
        foreach ($HostName in $Hosts) {
            if ($PackageData.ContainsKey("$PackageKey`t$HostName")) {
                $OutputLine += ",1"
            } else {
                $OutputLine += ",0"
            }
        }
        Add-Content -Path $CSV_OUTPUT_PATH -Value $OutputLine
    }

    Log-Message -Type "SUCCESS" -Message "Master CSV file created at '$CSV_OUTPUT_PATH'."
    return $true
}

function Main {
    # Initialize output directory and status log
    New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $INTERMEDIATE_DIR -Force | Out-Null
    Set-Content -Path $STATUS_REPORT_LOG -Value "AssetScriber Status Report - $(Get-Date)"
    Add-Content -Path $STATUS_REPORT_LOG -Value "-------------------------------------"

    if (-not (Setup-Syft) -or -not (Setup-Jq)) {
        Log-Message -Type "ERROR" -Message "Critical dependency setup failed. Exiting."
        exit 1
    }

    # --- Mode Selection Logic ---
    $ScanTarget = ""
    $FinalOsOnly = $false

    if ($Path) {
        # Mode 1: Path Scan. -OsOnly acts as a filter.
        Log-Message -Type "INFO" -Message "Mode selected: Path Scan on '$Path'"
        $ScanTarget = $Path
        $FinalOsOnly = $OsOnly
    } elseif ($OsOnly) {
        # Mode 2: OS-Only Scan. No -Path was given.
        Log-Message -Type "INFO" -Message "Mode selected: OS-Only Scan"
        $ScanTarget = "/"
        $FinalOsOnly = $true
    } else {
        # Mode 3: Full System Scan (Default).
        Log-Message -Type "INFO" -Message "Mode selected: Full System Scan"
        $ScanTarget = "/"
        $FinalOsOnly = $false
    }

    # --- Execution ---
    Test-RootPrivileges

    if ($Config) {
        # Scan remote hosts from config file
        if (-not (Test-Path $Config)) {
            Log-Message -Type "ERROR" -Message "Configuration file '$Config' not found."
        } else {
            $ConfigContent = Get-Content $Config
            foreach ($Line in $ConfigContent) {
                if ([string]::IsNullOrWhiteSpace($Line) -or $Line.TrimStart().StartsWith("#")) { continue }
                $Parts = $Line -split '\s+'
                $RemoteHost = $Parts[0]
                $User = if ($Parts.Count -gt 1) { $Parts[1] } else { $env:USERNAME }
                $Pass = if ($Parts.Count -gt 2) { $Parts[2] } else { "" }
                Perform-RemoteScan -RemoteHost $RemoteHost -User $User -Pass $Pass -ScanTarget $ScanTarget -OsOnly:$FinalOsOnly
            }
        }
    }

    if ($Discover) {
        # Discover and scan hosts on the network
        Log-Message -Type "INFO" -Message "Starting network discovery..."
        Discover-Network -OsOnly:$FinalOsOnly
    }

    if (-not $Config -and -not $Discover) {
        # No remote options given, perform a local scan
        Perform-LocalScan -ScanPath $ScanTarget -Hostname "localhost" -OsOnly:$FinalOsOnly
    }

    Generate-FinalCsv

    Log-Message -Type "SUCCESS" -Message "Operation finished. Results are in the '$OUTPUT_DIR' directory."
}

# Run the main function
Main
