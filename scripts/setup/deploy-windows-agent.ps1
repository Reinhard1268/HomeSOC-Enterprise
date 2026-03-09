# =============================================================================
# deploy-windows-agent.ps1 — Install and register Wazuh agent on Windows
# Description: Downloads Wazuh 4.x MSI installer, installs silently, and
#              auto-registers the agent with the Wazuh manager via port 1515.
# Usage: Run as Administrator in PowerShell:
#        .\deploy-windows-agent.ps1 -ManagerIP "192.168.1.100"
# Parameters:
#   -ManagerIP      IP of the host running the Wazuh manager (required)
#   -AgentName      Name to register agent as (default: hostname)
#   -AgentGroup     Wazuh group to join (default: windows-endpoints)
#   -WazuhVersion   Version to download (default: 4.7.3)
# =============================================================================

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,

    [string]$AgentName    = $env:COMPUTERNAME,
    [string]$AgentGroup   = "windows-endpoints",
    [string]$WazuhVersion = "4.7.3"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info    { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn    { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err     { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

# ── Variables ─────────────────────────────────────────────────────────────────
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${WazuhVersion}-1.msi"
$InstallerPath = "$env:TEMP\wazuh-agent-${WazuhVersion}.msi"
$WazuhInstallDir = "C:\Program Files (x86)\ossec-agent"
$OssecConfPath = "${WazuhInstallDir}\ossec.conf"

# ── Download installer ────────────────────────────────────────────────────────
function Download-Installer {
    Write-Info "Downloading Wazuh agent ${WazuhVersion} from packages.wazuh.com..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing
        Write-Success "Downloaded to ${InstallerPath}"
    } catch {
        Write-Err "Failed to download installer: $_"
    }
}

# ── Install agent ─────────────────────────────────────────────────────────────
function Install-WazuhAgent {
    Write-Info "Installing Wazuh agent silently..."
    $msiArgs = @(
        "/i", $InstallerPath,
        "/quiet",
        "WAZUH_MANAGER=${ManagerIP}",
        "WAZUH_MANAGER_PORT=1514",
        "WAZUH_PROTOCOL=udp",
        "WAZUH_REGISTRATION_SERVER=${ManagerIP}",
        "WAZUH_REGISTRATION_PORT=1515",
        "WAZUH_AGENT_NAME=${AgentName}",
        "WAZUH_AGENT_GROUP=${AgentGroup}",
        "/l*v", "$env:TEMP\wazuh-install.log"
    )

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Err "MSI install failed (exit code $($proc.ExitCode)). Log: $env:TEMP\wazuh-install.log"
    }
    Write-Success "Wazuh agent installed"
}

# ── Write custom ossec.conf ───────────────────────────────────────────────────
function Write-AgentConfig {
    Write-Info "Writing ossec.conf for ${AgentName}..."

    $config = @"
<ossec_config>

  <client>
    <server>
      <address>${ManagerIP}</address>
      <port>1514</port>
      <protocol>udp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${ManagerIP}</manager_address>
      <port>1515</port>
      <agent_name>${AgentName}</agent_name>
      <groups>${AgentGroup}</groups>
    </enrollment>
  </client>

  <!-- Windows Event Log collection -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
    <query>Event/System[EventID=4624 or EventID=4625 or EventID=4648
      or EventID=4688 or EventID=4698 or EventID=4699
      or EventID=4702 or EventID=4720 or EventID=4726
      or EventID=4776 or EventID=4768 or EventID=4769]</query>
  </localfile>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>System</location>
  </localfile>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>Application</location>
  </localfile>

  <!-- Sysmon (if installed) -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>

  <!-- PowerShell logging -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-PowerShell/Operational</location>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <windows_audit_interval>60</windows_audit_interval>
    <directories check_all="yes" realtime="yes" report_changes="yes">
      %WINDIR%\System32\drivers\etc
    </directories>
    <directories check_all="yes" realtime="yes">
      %WINDIR%\System32
    </directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">
      %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup
    </directories>
    <ignore>%WINDIR%\System32\LogFiles</ignore>
    <ignore>%WINDIR%\System32\wbem\Logs</ignore>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
  </syscheck>

  <!-- Rootkit detection -->
  <rootcheck>
    <disabled>no</disabled>
    <windows_apps>yes</windows_apps>
    <windows_malware>yes</windows_malware>
  </rootcheck>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
"@

    Set-Content -Path $OssecConfPath -Value $config -Encoding UTF8
    Write-Success "ossec.conf written to ${OssecConfPath}"
}

# ── Start service ─────────────────────────────────────────────────────────────
function Start-WazuhService {
    Write-Info "Starting Wazuh agent service..."
    try {
        Start-Service -Name "WazuhSvc" -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc = Get-Service -Name "WazuhSvc"
        if ($svc.Status -eq "Running") {
            Write-Success "WazuhSvc is running"
        } else {
            Write-Warn "Service status: $($svc.Status). Check Event Viewer for errors."
        }
    } catch {
        Write-Warn "Could not start WazuhSvc: $_"
        Write-Info "Try: Start-Service WazuhSvc  or  services.msc"
    }
}

# ── Configure firewall ────────────────────────────────────────────────────────
function Configure-Firewall {
    Write-Info "Adding Windows Firewall rules for Wazuh..."
    $rules = @(
        @{Name="Wazuh-Manager-UDP-Out"; Protocol="UDP"; Port=1514; Dir="Outbound"},
        @{Name="Wazuh-Enroll-TCP-Out"; Protocol="TCP"; Port=1515; Dir="Outbound"}
    )
    foreach ($r in $rules) {
        try {
            New-NetFirewallRule `
                -DisplayName $r.Name `
                -Direction $r.Dir `
                -Protocol $r.Protocol `
                -RemotePort $r.Port `
                -Action Allow `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Success "Firewall rule added: $($r.Name)"
        } catch {
            Write-Warn "Could not add rule $($r.Name): $_"
        }
    }
}

# ── Verify enrollment ─────────────────────────────────────────────────────────
function Verify-Enrollment {
    Write-Info "Checking agent enrollment (waiting up to 60s)..."
    $keyFile = "${WazuhInstallDir}\client.keys"
    $attempts = 0
    while ($attempts -lt 12) {
        if (Test-Path $keyFile) {
            $content = Get-Content $keyFile
            if ($content -match $AgentName) {
                Write-Success "Agent '${AgentName}' enrolled — client.keys populated"
                return
            }
        }
        Start-Sleep -Seconds 5
        $attempts++
    }
    Write-Warn "Enrollment not confirmed yet. Check manager: /var/ossec/bin/agent-control -l"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
function Remove-Installer {
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force
        Write-Info "Installer removed from temp"
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Wazuh Windows Agent Deployment ===" -ForegroundColor Cyan
Write-Host "  Manager IP  : ${ManagerIP}" -ForegroundColor White
Write-Host "  Agent Name  : ${AgentName}" -ForegroundColor White
Write-Host "  Agent Group : ${AgentGroup}" -ForegroundColor White
Write-Host "  Version     : ${WazuhVersion}" -ForegroundColor White
Write-Host ""

Download-Installer
Install-WazuhAgent
Write-AgentConfig
Configure-Firewall
Start-WazuhService
Verify-Enrollment
Remove-Installer

Write-Host ""
Write-Host "[DONE] Windows agent deployment complete!" -ForegroundColor Green
Write-Host "  View logs : Get-EventLog -LogName Application -Source 'WazuhSvc' -Newest 20"
Write-Host "  Status    : Get-Service WazuhSvc"
Write-Host ""
