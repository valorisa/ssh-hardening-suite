<#
PowerShell script for Windows 11 Enterprise
- Installs OpenSSH Server
- Generates ED25519 + ED25519-SK keys
- Applies firewall rules
- Sets up logging/audit
#>

# 1. Install OpenSSH
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

# 2. Generate keys
$sshFolder = "$env:USERPROFILE\.ssh"
if (-not (Test-Path $sshFolder)) { New-Item -ItemType Directory -Path $sshFolder -Force }

ssh-keygen -t ed25519 -a 100 -f "$sshFolder\id_ed25519" -C "valorisa@windows" -q -N ""
try { ssh-keygen -t ed25519-sk -O resident -f "$sshFolder\id_ed25519_sk" -C "valorisa@windows" -q -N "" } catch {}

# 3. Backup & apply sshd_config
$sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
Copy-Item $sshdConfigPath "$sshdConfigPath.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
Copy-Item ".\..\configs\sshd_config" $sshdConfigPath -Force
Restart-Service sshd

# 4. Firewall
New-NetFirewallRule -DisplayName "SSH Secure Port 22" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.0.2.0/24 -Action Allow
New-NetFirewallRule -DisplayName "SSH Block All Others" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress Any -Action Block

# 5. Audit
auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable

Write-Host "Windows SSH hardening completed."
