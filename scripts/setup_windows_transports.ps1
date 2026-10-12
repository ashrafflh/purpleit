# Run on the TARGET in elevated Windows PowerShell 5.1. No passwords are logged.
# Provisions a dedicated standard user and access needed by PurpleStrike transports.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][PSCredential]$TestCredential,
    [Parameter(Mandatory)][string[]]$ControllerAddress,
    [switch]$InstallSsh
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this setup in an elevated target-side PowerShell session.'
}
$name = $TestCredential.UserName
if ($name -notmatch '^[a-zA-Z][a-zA-Z0-9_]{0,19}$') { throw 'Use a local username of 1-20 letters/digits/underscores.' }
foreach ($address in $ControllerAddress) {
    # Require specific source IPs; avoid accidentally opening these services to everyone.
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($address, [ref]$parsed)) { throw "Invalid controller IP: $address" }
}
if (-not $ControllerAddress.Count) { throw 'Specify at least one controller IP.' }
$root = Join-Path $env:ProgramData 'PurpleStrike'
$transportPath = Join-Path $root 'Transport'
$shareName = 'PurpleStrikeTransport$'
$markerPath = Join-Path $root 'transport-setup-owner.json'
$share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
if ($share -and $share.Path -ne $transportPath) { throw 'Existing share points to a different path.' }
if (Test-Path -LiteralPath $markerPath) {
    $owner = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($owner.account -ne "$env:COMPUTERNAME\$name" -or $owner.path -ne $transportPath) {
        throw 'Existing setup belongs to a different account or directory.'
    }
} elseif ((Test-Path -LiteralPath $transportPath) -or $share) {
    throw 'Existing transport directory/share has no ownership record; review it before provisioning.'
}
# Refuse junctions/symlinks: setup must affect this directory, not a redirected path.
foreach ($path in @($root, $transportPath)) {
    if ((Test-Path -LiteralPath $path) -and
        ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing a redirected setup directory: $path"
    }
}
$description = 'PurpleStrike connection validation account'
$existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if ($existing -and $existing.Description -ne $description) { throw 'Refusing to modify an unrelated existing account.' }
if (-not $existing) {
    New-LocalUser -Name $name -Password $TestCredential.Password -Description $description | Out-Null
}
$account = "$env:COMPUTERNAME\$name"
$sid = (Get-LocalUser -Name $name).SID
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
if (@(Get-LocalGroupMember -Group $adminGroup).SID.Value -contains $sid.Value) {
    throw 'The test account must not belong to Administrators.'
}
foreach ($groupSid in @('S-1-5-32-545', 'S-1-5-32-580', 'S-1-5-32-562')) {
    $group = Get-LocalGroup -SID $groupSid
    if (@(Get-LocalGroupMember -Group $group).SID.Value -notcontains $sid.Value) {
        Add-LocalGroupMember -Group $group -Member $account
    }
}
if ((Get-Service WinRM).Status -ne 'Running') { Enable-PSRemoting -Force }

New-Item -ItemType Directory -Path $transportPath -Force | Out-Null
[pscustomobject]@{account=$account; path=$transportPath} |
    ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
$backupPath = Join-Path $root ("transport-setup-" + $sid.Value + '.json')
$originalSddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
# Capture both ACLs before modifying either one. Reruns preserve the first snapshot.
$current = Invoke-WmiMethod -Namespace root\cimv2 -Path '__SystemSecurity=@' -Name GetSecurityDescriptor
if ($current.ReturnValue -ne 0) { throw "Get WMI security failed: $($current.ReturnValue)" }
$descriptor = $current.Descriptor
$originalWmiSddl = (Invoke-WmiMethod -Class Win32_SecurityDescriptorHelper -Name Win32SDToSDDL -ArgumentList $descriptor).SDDL
if (-not (Test-Path -LiteralPath $backupPath)) {
    [pscustomobject]@{account=$account; sid=$sid.Value; winrm_sddl=$originalSddl; wmi_sddl=$originalWmiSddl; controller=$ControllerAddress; transport_path=$transportPath; share=$shareName} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding UTF8
}
# WinRS uses WinRM resource access; this does not modify Microsoft.PowerShell endpoint ACLs.
$sd = New-Object Security.AccessControl.CommonSecurityDescriptor($false, $false, $originalSddl)
$sd.DiscretionaryAcl.AddAccess([Security.AccessControl.AccessControlType]::Allow,
    $sid, -1610612736, [Security.AccessControl.InheritanceFlags]::None,
    [Security.AccessControl.PropagationFlags]::None) # GENERIC_READ | GENERIC_EXECUTE
Set-Item WSMan:\localhost\Service\RootSDDL -Value $sd.GetSddlForm('All') -Force

# WMI namespace access: Enable Account (1), Execute Methods (2), Remote Enable (32).
$trustee = ([WmiClass]'Win32_Trustee').CreateInstance()
$trustee.SIDString = $sid.Value
$trustee.Name = $name
$trustee.Domain = $env:COMPUTERNAME
$ace = ([WmiClass]'Win32_ACE').CreateInstance()
$ace.AccessMask = 35
$ace.AceFlags = 0
$ace.AceType = 0
$ace.Trustee = $trustee
if (-not @($descriptor.DACL | Where-Object { $_.Trustee.SIDString -eq $sid.Value -and $_.AccessMask -eq 35 }).Count) {
    $descriptor.DACL += $ace
    $changed = Invoke-WmiMethod -Namespace root\cimv2 -Path '__SystemSecurity=@' -Name SetSecurityDescriptor -ArgumentList $descriptor.PSObject.ImmediateBaseObject
    if ($changed.ReturnValue -ne 0) { throw "Set WMI security failed: $($changed.ReturnValue)" }
}

# Dedicated output share: no ADMIN$ dependency for the standard user.
$acl = Get-Acl -LiteralPath $transportPath
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'), @($sid.Value,'Modify'))) {
    $entrySid = New-Object Security.Principal.SecurityIdentifier($entry[0])
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($entrySid, $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRule($rule)
}
Set-Acl -LiteralPath $transportPath -AclObject $acl
if (-not $share) {
    New-SmbShare -Name $shareName -Path $transportPath -FullAccess $adminGroup.Name -ChangeAccess $account -Description 'PurpleStrike transport staging' | Out-Null
} else {
    Grant-SmbShareAccess -Name $shareName -AccountName $account -AccessRight Change -Force | Out-Null
}

# Machine-wide DCOM limits may be hardened by policy. Membership in Distributed COM
# Users uses the existing delegation; this script does not weaken global DCOM ACLs.
$rules = @(
    @{Name='PurpleStrike-Test-WinRM'; Port='5985'},
    @{Name='PurpleStrike-Test-SSH'; Port='22'},
    @{Name='PurpleStrike-Test-SMB'; Port='445'},
    @{Name='PurpleStrike-Test-RPC'; Port='135'}
)
foreach ($rule in $rules) {
    if (-not (Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rule.Port -RemoteAddress $ControllerAddress | Out-Null
    }
}
if (-not (Get-NetFirewallRule -Name 'PurpleStrike-Test-WMI' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'PurpleStrike-Test-WMI' -DisplayName 'PurpleStrike-Test-WMI' -Direction Inbound -Action Allow -Protocol TCP -LocalPort RPC -Service Winmgmt -Program "$env:SystemRoot\System32\svchost.exe" -RemoteAddress $ControllerAddress | Out-Null
}

if ($InstallSsh) {
    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($capability.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
    }
    Set-Service sshd -StartupType Automatic
    Start-Service sshd
}
[pscustomobject]@{
    account=$account; sid=$sid.Value; administrator=$false; backup=$backupPath
    wmi_share=$shareName; wmi_share_path='.'; wmi_remote_path=$transportPath
    ssh_installed=[bool](Get-Service sshd -ErrorAction SilentlyContinue)
} | ConvertTo-Json -Compress
