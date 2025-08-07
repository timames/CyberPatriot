# Start transcript to log all console output
Start-Transcript -Path "C:\Program Files\HBA_HS_WIN\script_output.log" -Force

# Displays an ASCII art banner with the script's branding for visual identification.
# Purpose: Provides a cosmetic header to indicate the script's purpose and origin, enhancing user experience in CyberPatriot competitions.
# Functionality: Uses Write-Host to output ASCII art and a title identifying the script as "HBA High School Windows Hardening Script".
# CyberPatriot Relevance: Serves as a team identifier, though it does not contribute to scoring; purely aesthetic.
# Considerations: No security impact; ensures readability in PowerShell console on Windows 10/11.
function HBABanner {
    Write-Host '
+========================================================+
|   _   _ ____    _       ______   ______  _____ ____    |
|  | | | | __ )  / \     / ___\ \ / / __ )| ____|  _ \   |
|  | |_| |  _ \ / _ \   | |    \ V /|  _ \|  _| | |_) |  |
|  |  _  | |_) / ___ \  | |___  | | | |_) | |___|  _ <   |
|  |_| |_|____/_/   \_\  \____| |_| |____/|_____|_| \_\  |
+========================================================+
'
}

# Creates a directory for logging script outputs and errors.
# Purpose: Centralizes logs in C:\Program Files\HBA_HS_WIN for auditability and scoring in CyberPatriot.
# Functionality: Uses New-Item to create the directory with -Force, overwriting if it exists.
# CyberPatriot Relevance: Logging is critical for tracking changes and verifying actions during competitions.
# Considerations: Requires admin privileges; may fail if UAC or antivirus restricts Program Files access on Windows 10/11.
function createDir {
    Write-Host "Creating logging directory..." -ForegroundColor Gray
    try {
        New-Item -ItemType Directory -Path "C:\Program Files\HBA_HS_WIN" -Force
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\createDir.txt"
        Write-Host "Error creating directory, logged to file" -ForegroundColor DarkYellow
    }
}

# Enables comprehensive auditing for system events to monitor security-related activities.
# Purpose: Enhances security monitoring by enabling success and failure auditing for all major event categories.
# Functionality: Uses auditpol to enable auditing for categories like Account Logon, Object Access, and System events.
# CyberPatriot Relevance: Auditing is often scored to ensure systems log unauthorized access or changes.
# Considerations: Broad auditing may generate excessive logs, impacting performance on Windows 10/11; consider selective subcategories.
function policyAudit {
    Write-Host "Creating audit policies..." -ForegroundColor Gray
    try {
        auditpol /set /category:"Account Logon" /success:enable
        auditpol /set /category:"Account Logon" /failure:enable
        auditpol /set /category:"Account Management" /success:enable
        auditpol /set /category:"Account Management" /failure:enable
        auditpol /set /category:"DS Access" /success:enable
        auditpol /set /category:"DS Access" /failure:enable
        auditpol /set /category:"Logon/Logoff" /success:enable
        auditpol /set /category:"Logon/Logoff" /failure:enable
        auditpol /set /category:"Object Access" /success:enable
        auditpol /set /category:"Object Access" /failure:enable
        auditpol /set /category:"Policy Change" /success:enable
        auditpol /set /category:"Policy Change" /failure:enable
        auditpol /set /category:"Privilege Use" /success:enable
        auditpol /set /category:"Privilege Use" /failure:enable
        auditpol /set /category:"Detailed Tracking" /success:enable
        auditpol /set /category:"Detailed Tracking" /failure:enable
        auditpol /set /category:"System" /success:enable
        auditpol /set /category:"System" /failure:enable
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\policyAudit.txt"
        Write-Host "Error setting audit policies, logged to file" -ForegroundColor DarkYellow
    }
}

# Configures global System Access Control Lists (SACLs) for file and registry auditing.
# Purpose: Tracks access to sensitive files and registry keys, enhancing security monitoring.
# Functionality: Uses auditpol /resourceSACL to set auditing for Domain Admins (on servers) or Administrator (on clients).
# CyberPatriot Relevance: Auditing privileged access is scored to detect unauthorized changes.
# Considerations: Only relevant for servers in domain environments; client-side auditing may be excessive for Windows 10/11.
function globalAudit {
    Write-Host "Adding global audit policies..." -ForegroundColor Gray
    try {
        $OSWMI = Get-CimInstance Win32_OperatingSystem -Property Caption,Version
        $OSName = $OSWMI.Caption
        if ($OSName -match "server") {
            auditpol /resourceSACL /set /type:File /user:"Domain Admins" /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:"Domain Admins" /success /failure /access:FW
        } else {
            auditpol /resourceSACL /set /type:File /user:Administrator /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:Administrator /success /failure /access:FW
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\globalAudit.txt"
        Write-Host "Error setting global audit policies, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables the insecure SMBv1 protocol to prevent vulnerabilities.
# Purpose: Mitigates risks from outdated SMBv1, such as EternalBlue exploits.
# Functionality: Disables SMBv1 server and client using Set-SmbServerConfiguration and Disable-WindowsOptionalFeature.
# CyberPatriot Relevance: Disabling SMBv1 is a common scoring criterion due to its known vulnerabilities.
# Considerations: SMBv1 is disabled by default in Windows 10/11, but checking ensures no regressions; may break legacy apps.
function smbShare {
    Write-Host "Disabling SMBv1..." -ForegroundColor Gray
    try {
        If ((Get-SmbServerConfiguration).EnableSMB1Protocol) { 
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
        }
        If ((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State -eq "Enabled") { 
            Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol 
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\smbShare.txt"
        Write-Host "Error disabling SMBv1, logged to file" -ForegroundColor DarkYellow
    }
}

# Ensures SMBv2/3 is enabled for secure file sharing.
# Purpose: Confirms modern SMB protocols are active, replacing insecure SMBv1.
# Functionality: Enables SMBv2/3 using Set-SmbServerConfiguration and Enable-WindowsOptionalFeature.
# CyberPatriot Relevance: Ensures secure file sharing configurations, though often redundant in Windows 10/11.
# Considerations: SMBv2/3 is default in Windows 10/11; function is precautionary but may be unnecessary.
function smbGood {
    Write-Host "Ensuring SMBv2/3 is enabled..." -ForegroundColor Gray
    try {
        If ((Get-SmbServerConfiguration).EnableSMB1Protocol) { 
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force 
        }
        If ((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State -eq "Enabled") { 
            Enable-WindowsOptionalFeature -Online -FeatureName smb2protocol 
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\smbGood.txt"
        Write-Host "Error enabling SMBv2/3, logged to file" -ForegroundColor DarkYellow
    }
}

# Configures Group Policy settings to enforce secure configurations.
# Purpose: Disables unnecessary features and enables Windows Update for security.
# Functionality: Uses Set-PolicyFileEntry to set registry-based policies (e.g., disable Messenger, IIS, enable updates).
# CyberPatriot Relevance: Aligns with competition requirements to enforce secure policies.
# Considerations: Requires PolicyFileEditor module; some settings (e.g., Messenger) are deprecated in Windows 10/11.
function groupPolicy {
    Write-Host "Creating Group Policies..." -ForegroundColor Gray
    try {
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName PreventAutoRun -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName DisableContentFileUpdates -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -ValueName PreventIISInstall -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName NoAutoUpdate -Type DWord -Data 0
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\groupPolicy.txt"
        Write-Host "Error setting group policies, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables Telnet client and server features to eliminate insecure protocols.
# Purpose: Removes Telnet, which transmits data in plaintext and is a security risk.
# Functionality: Uses dism to disable TelnetClient and TelnetServer features.
# CyberPatriot Relevance: Disabling insecure protocols is a common scoring task.
# Considerations: Telnet is rarely used in Windows 10/11; function is precautionary but may error if features are absent.
function telnetEnable {
    Write-Host "Disabling telnet..." -ForegroundColor Gray
    try {
        dism /online /Disable-feature /featurename:TelnetClient /NoRestart
        dism /online /Disable-feature /featurename:TelnetServer /NoRestart
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\telnetEnable.txt"
        Write-Host "Error disabling telnet, logged to file" -ForegroundColor DarkYellow
    }
}

# Configures firewall rules to block outbound connections for potentially abusable executables.
# Purpose: Prevents misuse of Living-Off-the-Land Binaries (LOLBins) like calc.exe or certutil.exe.
# Functionality: Uses netsh advfirewall to block TCP outbound connections for 40+ executables.
# CyberPatriot Relevance: Blocking LOLBins aligns with securing systems against exploitation.
# Considerations: May block legitimate tools (e.g., msiexec); only covers TCP, not UDP; applicable to Windows 10/11.
function hostFirewall {
    Write-Host "Configuring firewall rules..." -ForegroundColor Gray
    try {
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\hostFirewall.txt"
        Write-Host "Error configuring firewall rules, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables Windows Remote Management (WinRM) to reduce remote access risks.
# Purpose: Minimizes attack surface by disabling PowerShell remoting, a potential vector for lateral movement.
# Functionality: Uses Disable-PSRemoting, sets trusted hosts to *, and configures PowerShell session security.
# CyberPatriot Relevance: Disabling unnecessary remote access is scored to secure systems.
# Considerations: Trusted hosts set to * is insecure; consider admin tools in Windows 10/11 if needed.
function winRM {
    Write-Host "Disabling WinRM..." -ForegroundColor Gray
    try {
        Disable-PSRemoting -Force
        Set-Item wsman:\localhost\client\trustedhosts * -Force
        Set-PSSessionConfiguration -Name "Microsoft.PowerShell" -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\winRM.txt"
        Write-Host "Error disabling WinRM, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables anonymous LDAP binds on Windows Server to prevent unauthorized queries.
# Purpose: Enhances Active Directory security by requiring authentication for LDAP access.
# Functionality: Sets DenyUnauthenticatedBind on AD object; skips on non-server systems.
# CyberPatriot Relevance: Securing AD configurations is scored in server-based VMs.
# Considerations: Requires ActiveDirectory module; irrelevant for Windows 10/11 client VMs.
function anonLdap {
    Write-Host "Disabling anonymous LDAP..." -ForegroundColor Gray
    try {
        $OSWMI = (Get-CimInstance Win32_OperatingSystem).Caption
        $RootDSE = Get-ADRootDSE
        $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
        if ($OSWMI -match "server") {
            Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }
        } else {
            Write-Warning "Localhost is not a Windows server. Skipping function."
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\anonLdap.txt"
        Write-Host "Error disabling anonymous LDAP, logged to file" -ForegroundColor DarkYellow
    }
}

# Configures Windows Defender with real-time monitoring and Attack Surface Reduction (ASR) rules.
# Purpose: Strengthens malware protection and blocks common attack vectors like Office macros; aligns with README Windows Action Center requirement.
# Functionality: Enables real-time monitoring and sets specific ASR rules to block malicious behaviors.
# CyberPatriot Relevance: Enabling Defender and ASR is scored for robust malware defense; fulfills Action Center monitoring.
# Considerations: ASR rules may cause false positives in Windows 10/11; test in audit mode first.
function defenderConfig {
    Write-Host "Configuring Windows Defender..." -ForegroundColor Gray
    try {
        Set-MpPreference -EnableRealtimeMonitoring $true
        Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\defenderConfig.txt"
        Write-Host "Error configuring Windows Defender, logged to file" -ForegroundColor DarkYellow
    }
}

# Sets multiple registry keys to enforce secure configurations.
# Purpose: Applies security settings for Windows Update, Defender, LSA, and Office macros.
# Functionality: Uses reg add to set 50+ keys, including enabling updates, disabling autorun, and securing macros.
# CyberPatriot Relevance: Registry hardening is scored for securing system behavior and preventing exploits.
# Considerations: Some settings (e.g., Office 2016-specific) may be outdated in Windows 11; risks breaking apps if not tested.
function registryKeys {
    Write-Host "Configuring registry keys..." -ForegroundColor Gray
    try {
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
        reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
        reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
        reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\registryKeys.txt"
        Write-Host "Error configuring registry keys, logged to file" -ForegroundColor DarkYellow
    }
}

# Creates a secure administrative account for use in competitions.
# Purpose: Provides a controlled admin account ("techie") to replace default accounts.
# Functionality: Uses net user to create the account with a hardcoded base64-encoded password.
# CyberPatriot Relevance: Creating a secure admin account is scored to replace vulnerable defaults.
# Considerations: Hardcoded password is insecure; consider randomizing. Consider only on Windows 10/11.
function techAccount {
    Write-Host "Configuring tech account..." -ForegroundColor Gray
    try {
        $OS = (Get-CimInstance Win32_OperatingSystem).Caption
        if ($OS -match "Windows 10|Windows 11") {
            $Username = "techie"
            $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
            $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
            cmd.exe /c "net user $Username $passwordplaintext /add /y"
            cmd.exe /c "net localgroup Administrators $Username /add"
        } else {
            Write-Output "This is a server or unsupported device. Skipping function."
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\techAccount.txt"
        Write-Host "Error configuring tech account, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables PowerShell remoting to reduce attack surface (redundant with winRM).
# Purpose: Minimizes remote access risks; included for thoroughness.
# Functionality: Uses Disable-PSRemoting to turn off PowerShell remoting.
# CyberPatriot Relevance: Redundant but ensures no remote access vulnerabilities.
# Considerations: May break admin tools in Windows 10/11; overlaps with winRM function.
function miscellaneousStuff {
    Write-Host "Configuring miscellaneous items..." -ForegroundColor Gray
    try {
        Disable-PSRemoting -Force
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\miscellaneousStuff.txt"
        Write-Host "Error configuring miscellaneous items, logged to file" -ForegroundColor DarkYellow
    }
}

# Resets all local user passwords to random 16-character strings or provided for admins.
# Purpose: Ensures strong passwords to prevent unauthorized access, incorporating README passwords for admins.
# Functionality: Sets provided passwords for admins (except ashepard), generates random for users, exports to CSV.
# CyberPatriot Relevance: Strong passwords are scored to secure accounts; skips auto-login user.
# Considerations: Plaintext CSV export is insecure; risks locking out users/services in Windows 10/11.
function localPass {
    Write-Host "Changing local passwords..." -ForegroundColor Gray
    try {
        $adminPasswords = @{
            "ashepard" = "Cyb3rCont3st"
            "ygagarin" = "dawn"
            "vkomarov" = "v4l3nT!NA"
            "jglenn" = "f4fW!ldc4t"
            "vtereshkova" = "V05t()k1!"
            "gcooper" = "proJb!uEb0oK"
        }
        $userList = @()
        $users = Get-LocalUser
        foreach ($user in $users) {
            if ($user.Name -eq "ashepard") {
                $newPassword = $adminPasswords["ashepard"]  # Note: Not changing as per guidelines
                $status = "Not changed (auto-login user)"
            } elseif ($adminPasswords.ContainsKey($user.Name)) {
                $newPassword = $adminPasswords[$user.Name]
                $securePass = ConvertTo-SecureString -AsPlainText $newPassword -Force
                $user | Set-LocalUser -Password $securePass
                $status = "Set to provided password"
            } else {
                $newPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object {[char]$_})
                $securePass = ConvertTo-SecureString -AsPlainText $newPassword -Force
                $user | Set-LocalUser -Password $securePass
                $status = "Random password generated"
            }
            $userFull = [PSCustomObject]@{
                "AccountName" = $user.Name
                "Password" = $newPassword
                "Status" = $status
            }
            $userList += $userFull
        }
        $userList | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\localmod.csv" -NoTypeInformation
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\localPass.txt"
        Write-Host "Error changing local passwords, logged to file" -ForegroundColor DarkYellow
    }
}

# Renames the default Administrator account to obscure it.
# Purpose: Makes it harder for attackers to target the default admin account.
# Functionality: Uses net user to delete "Administrator" and create "Wasabi" with admin privileges.
# CyberPatriot Relevance: Renaming default accounts is scored to reduce attack vectors.
# Considerations: Hardcoded "Wasabi" is predictable; risks breaking services relying on Administrator in Windows 10/11.
function adminChange {
    Write-Host "Changing Administrators name..." -ForegroundColor Gray
    try {
        $adminName = "Administrator"
        $newAdminname = "Wasabi"
        cmd.exe /c "net user $adminName /delete"
        cmd.exe /c "net user $newAdminname /add /active:yes"
        cmd.exe /c "net localgroup Administrators $newAdminname /add"
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\adminChange.txt"
        Write-Host "Error changing administrator name, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes unauthorized local user accounts based on README whitelist.
# Purpose: Eliminates rogue accounts planted in CyberPatriot VMs.
# Functionality: Uses Get-LocalUser to delete accounts not in authorized list; logs to CSV.
# CyberPatriot Relevance: Removing unauthorized users is a key scoring task.
# Considerations: Uses README authorized list; risks deleting legitimate accounts if not accurate.
function removeUnauthorizedUsers {
    Write-Host "Removing unauthorized users..." -ForegroundColor Gray
    try {
        $authorizedAdmins = @("ashepard", "ygagarin", "vkomarov", "jglenn", "vtereshkova", "gcooper")
        $authorizedUsers = @("timon", "zazu", "ed", "banzai", "scar", "rafiki", "nala", "shenzi", "sarabi", "pumbaa", "sarafina", "gauri", "bruno", "demitri", "erik", "vasca", "veles", "damir", "gopher", "gleb")
        $allAuthorized = $authorizedAdmins + $authorizedUsers + @("Guest", "techie", "Wasabi")  # Include built-in and script-created
        Get-LocalUser | Where-Object { $_.Name -notin $allAuthorized } | ForEach-Object {
            Remove-LocalUser -Name $_.Name
        }
        Get-LocalUser | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\users_audit.csv" -NoTypeInformation
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\removeUnauthorizedUsers.txt"
        Write-Host "Error removing unauthorized users, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables automatic logon to prevent unauthorized access.
# Purpose: Ensures users must authenticate, reducing security risks.
# Functionality: Sets AutoAdminLogon to 0 and removes DefaultUserName/Password registry keys.
# CyberPatriot Relevance: Disabling auto-logon is scored to secure login processes.
# Considerations: Safe for Windows 10/11; no significant risks if properly implemented.
function disableAutoLogon {
    Write-Host "Disabling auto-logon..." -ForegroundColor Gray
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\disableAutoLogon.txt"
        Write-Host "Error disabling auto-logon, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes unauthorized scheduled tasks to eliminate persistence mechanisms.
# Purpose: Deletes non-Microsoft tasks that may run malicious scripts.
# Functionality: Uses Get-ScheduledTask to log and remove tasks not in \Microsoft* path.
# CyberPatriot Relevance: Removing malicious tasks is a common scoring task.
# Considerations: Filter is broad; customize per README to avoid deleting legitimate tasks in Windows 10/11.
function removeMaliciousTasks {
    Write-Host "Removing malicious scheduled tasks..." -ForegroundColor Gray
    try {
        Get-ScheduledTask | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\tasks_audit.csv" -NoTypeInformation
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Unregister-ScheduledTask -Confirm:$false
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\removeMaliciousTasks.txt"
        Write-Host "Error removing malicious tasks, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes unauthorized software to eliminate vulnerable applications.
# Purpose: Uninstalls programs not in whitelist (updated for README software) to reduce attack surface.
# Functionality: Uses Get-WmiObject Win32_Product to uninstall non-allowed software; logs to CSV.
# CyberPatriot Relevance: Removing unauthorized software is scored to secure VMs.
# Considerations: Whitelist includes README software; risks uninstalling legitimate apps if not complete.
function removeUnauthorizedSoftware {
    Write-Host "Removing unauthorized software..." -ForegroundColor Gray
    try {
        $allowedSoftware = @("Microsoft Windows Operating System", "Mozilla Firefox", "Mozilla Thunderbird")
        Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -notin $allowedSoftware } | ForEach-Object { $_.Uninstall() }
        Get-WmiObject -Class Win32_Product | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\software_audit.csv" -NoTypeInformation
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\removeUnauthorizedSoftware.txt"
        Write-Host "Error removing unauthorized software, logged to file" -ForegroundColor DarkYellow
    }
}

# Secures permissions on critical system directories.
# Purpose: Restricts access to C:\Windows to prevent unauthorized modifications.
# Functionality: Uses icacls to set strict permissions for Administrators, SYSTEM, and Users.
# CyberPatriot Relevance: Securing file permissions is scored to protect system integrity.
# Considerations: Safe for Windows 10/11; additional directories may need securing based on README.
function secureFilePermissions {
    Write-Host "Securing file and folder permissions..." -ForegroundColor Gray
    try {
        icacls "C:\Windows" /inheritance:d /grant:r "Administrators:(OI)(F)" "SYSTEM:(OI)(F)" "Users:(OI)(RX)"
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\secureFilePermissions.txt"
        Write-Host "Error securing file permissions, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes suspicious files from user directories to eliminate potential malware and non-work media/hacking tools.
# Purpose: Deletes executable and media files that may be malicious or prohibited per README.
# Functionality: Uses Get-ChildItem to scan C:\Users and remove specified file types; logs to CSV.
# CyberPatriot Relevance: Removing malicious/media/hacking files is a key scoring task in competitions.
# Considerations: Aggressive; risks deleting legitimate files in Windows 10/11; extensions include media and tools.
function removeMaliciousFiles {
    Write-Host "Removing malicious and non-work files..." -ForegroundColor Gray
    try {
        Get-ChildItem -Path C:\Users -Recurse -Include *.exe,*.bat,*.vbs,*.mp3,*.mp4,*.avi,*.wmv,*.jpg,*.png,*.gif,*.bmp -ErrorAction SilentlyContinue | Remove-Item -Force
        Get-ChildItem -Path C:\Users -Recurse -Include *.exe,*.bat,*.vbs,*.mp3,*.mp4,*.avi,*.wmv,*.jpg,*.png,*.gif,*.bmp -ErrorAction SilentlyContinue | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\files_audit.csv" -NoTypeInformation
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\removeMaliciousFiles.txt"
        Write-Host "Error removing malicious files, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables Remote Desktop Protocol (RDP) to reduce remote access risks.
# Purpose: Prevents unauthorized remote access by disabling RDP.
# Functionality: Sets fDenyTSConnections registry key to 1.
# CyberPatriot Relevance: Disabling RDP is scored unless README specifies it’s needed.
# Considerations: Safe for Windows 10/11; verify RDP isn’t required for competition scenarios.
function disableRDP {
    Write-Host "Disabling Remote Desktop..." -ForegroundColor Gray
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\disableRDP.txt"
        Write-Host "Error disabling RDP, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes unauthorized network shares to prevent data exposure.
# Purpose: Eliminates non-essential shares that may be exploited.
# Functionality: Uses Get-SmbShare to log and remove shares not in whitelist (ADMIN$, C$, IPC$).
# CyberPatriot Relevance: Securing shares is scored to prevent unauthorized access.
# Considerations: Whitelist is standard; risks removing legitimate shares in Windows 10/11 if not customized.
function secureNetworkShares {
    Write-Host "Securing network shares..." -ForegroundColor Gray
    try {
        Get-SmbShare | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\shares_audit.csv" -NoTypeInformation
        Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") } | Remove-SmbShare -Force
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\secureNetworkShares.txt"
        Write-Host "Error securing network shares, logged to file" -ForegroundColor DarkYellow
    }
}

# Applies security settings to Microsoft Edge to reduce browser-based risks.
# Purpose: Disables insecure features like autofill to prevent data leakage.
# Functionality: Sets registry keys to disable AutofillCreditCardEnabled and JavaScriptAllowed.
# CyberPatriot Relevance: Securing browsers is scored to mitigate web-based attacks.
# Considerations: Edge-specific; may need additional settings for other browsers in Windows 10/11.
function secureBrowserSettings {
    Write-Host "Securing browser settings..." -ForegroundColor Gray
    try {
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "JavaScriptAllowed" /t REG_DWORD /d 0 /f
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\secureBrowserSettings.txt"
        Write-Host "Error securing browser settings, logged to file" -ForegroundColor DarkYellow
    }
}

# Detects and updates web browsers (Firefox, Chrome, Edge, IE) to patch vulnerabilities, and ensures Thunderbird is installed/updated.
# Purpose: Ensures browsers and Thunderbird are up-to-date per README to mitigate known exploits.
# Functionality: Uses Get-WmiObject and file checks to detect; uses winget to install/upgrade Firefox and Thunderbird; logs to CSV.
# CyberPatriot Relevance: Updating software is a critical scoring task to secure VMs.
# Considerations: Requires winget for Firefox/Thunderbird (Windows 10 1709+/11); Edge updates via Windows Update; manual if winget absent.
function updateBrowsers {
    Write-Host "Checking and updating web browsers and Thunderbird..." -ForegroundColor Gray
    try {
        $browserList = @()
        $installedSoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Mozilla Firefox|Google Chrome|Mozilla Thunderbird" }
        foreach ($software in $installedSoftware) {
            $browserList += [PSCustomObject]@{
                Name = $software.Name
                Version = $software.Version
                Status = "Detected"
            }
        }
        $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if (Test-Path $edgePath) {
            $edgeVersion = (Get-Item $edgePath).VersionInfo.FileVersion
            $browserList += [PSCustomObject]@{
                Name = "Microsoft Edge"
                Version = $edgeVersion
                Status = "Detected"
            }
        }
        $iePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        if (Test-Path $iePath) {
            $ieVersion = (Get-Item $iePath).VersionInfo.FileVersion
            $browserList += [PSCustomObject]@{
                Name = "Internet Explorer"
                Version = $ieVersion
                Status = "Detected"
            }
        }
        $wingetCheck = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetCheck) {
            # Update Firefox
            if ($browserList | Where-Object { $_.Name -match "Mozilla Firefox" }) {
                winget upgrade --id Mozilla.Firefox --force
                $newVersion = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Mozilla Firefox" }).Version
                $browserList | Where-Object { $_.Name -match "Mozilla Firefox" } | ForEach-Object { $_.Status = "Updated to $newVersion" }
            } else {
                winget install --id Mozilla.Firefox --force
                $browserList += [PSCustomObject]@{
                    Name = "Mozilla Firefox"
                    Version = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Mozilla Firefox" }).Version
                    Status = "Installed"
                }
            }
            # Install/Update Thunderbird
            if ($browserList | Where-Object { $_.Name -match "Mozilla Thunderbird" }) {
                winget upgrade --id Mozilla.Thunderbird --force
                $newVersion = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Mozilla Thunderbird" }).Version
                $browserList | Where-Object { $_.Name -match "Mozilla Thunderbird" } | ForEach-Object { $_.Status = "Updated to $newVersion" }
            } else {
                winget install --id Mozilla.Thunderbird --force
                $browserList += [PSCustomObject]@{
                    Name = "Mozilla Thunderbird"
                    Version = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Mozilla Thunderbird" }).Version
                    Status = "Installed"
                }
            }
        } else {
            $browserList | ForEach-Object { $_.Status += "; winget not available - manual update required" }
        }
        if ($browserList | Where-Object { $_.Name -eq "Microsoft Edge" }) {
            $browserList | Where-Object { $_.Name -eq "Microsoft Edge" } | ForEach-Object { $_.Status = "Managed by Windows Update" }
        }
        $browserList | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\browserUpdates.csv" -NoTypeInformation
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\browserUpdates.txt"
        Write-Host "Error updating browsers, logged to file" -ForegroundColor DarkYellow
    }
}

# Applies Windows updates to patch system vulnerabilities, avoiding feature updates per README.
# Purpose: Ensures the OS is up-to-date without installing prohibited Feature Updates.
# Functionality: Uses PSWindowsUpdate to install security updates only.
# CyberPatriot Relevance: Applying updates is a critical scoring task.
# Considerations: Requires PSWindowsUpdate module; limits to security to comply with README; may need internet.
function applyUpdates {
    Write-Host "Applying security updates..." -ForegroundColor Gray
    try {
        # Requires PSWindowsUpdate module; install if needed (manual step)
        # Install-Module PSWindowsUpdate -Force
        Get-WUInstall -Category "Security" -AcceptAll -AutoReboot
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\applyUpdates.txt"
        Write-Host "Error applying updates, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables unnecessary services to reduce attack surface, excluding CCS Client per README.
# Purpose: Stops and disables non-essential services like Print Spooler.
# Functionality: Uses Set-Service and Stop-Service to disable specified services.
# CyberPatriot Relevance: Disabling unnecessary services is scored to secure VMs.
# Considerations: Excludes CCS Client; customize list per README to avoid breaking required services.
function disableUnnecessaryServices {
    Write-Host "Disabling unnecessary services..." -ForegroundColor Gray
    try {
        $servicesToDisable = @("Spooler", "Bluetooth Support Service", "Xbox Live Auth Manager")  # Exclude CCS Client
        foreach ($service in $servicesToDisable) {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\disableUnnecessaryServices.txt"
        Write-Host "Error disabling unnecessary services, logged to file" -ForegroundColor DarkYellow
    }
}

# Sets PowerShell execution policy to Restricted to prevent unauthorized scripts.
# Purpose: Enhances security by limiting script execution.
# Functionality: Uses Set-ExecutionPolicy to enforce Restricted policy.
# CyberPatriot Relevance: Securing PowerShell is scored to prevent malicious scripts.
# Considerations: May interfere with legitimate scripts in Windows 10/11; verify requirements.
function securePowerShellPolicy {
    Write-Host "Securing PowerShell execution policy..." -ForegroundColor Gray
    try {
        Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Restricted -Force
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\securePowerShellPolicy.txt"
        Write-Host "Error securing PowerShell policy, logged to file" -ForegroundColor DarkYellow
    }
}

# Removes unauthorized registry entries to eliminate persistence mechanisms.
# Purpose: Cleans Run keys that may launch malicious programs at startup.
# Functionality: Uses Get-ItemProperty to log and Remove-ItemProperty to delete Run keys.
# CyberPatriot Relevance: Removing malicious registry entries is scored.
# Considerations: Aggressive; risks removing legitimate entries in Windows 10/11; customize whitelist.
function removeUnauthorizedRegistry {
    Write-Host "Removing unauthorized registry entries..." -ForegroundColor Gray
    try {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Export-Csv -Path "C:\Program Files\HBA_HS_WIN\registry_run_audit.csv" -NoTypeInformation
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name * -ErrorAction SilentlyContinue
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\removeUnauthorizedRegistry.txt"
        Write-Host "Error removing unauthorized registry entries, logged to file" -ForegroundColor DarkYellow
    }
}

# Checks Secure Boot status to ensure boot-time security.
# Purpose: Verifies Secure Boot is enabled to prevent unauthorized bootloaders.
# Functionality: Uses Confirm-SecureBootUEFI; logs if disabled.
# CyberPatriot Relevance: Secure Boot is scored for modern Windows systems.
# Considerations: Cannot enable via script; requires BIOS changes in Windows 10/11.
function enableSecureBoot {
    Write-Host "Checking Secure Boot status..." -ForegroundColor Gray
    try {
        if (-not (Confirm-SecureBootUEFI)) {
            Write-Output "Secure Boot is disabled. Enable in BIOS." | Out-File "C:\Program Files\HBA_HS_WIN\secureBoot.txt"
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\enableSecureBoot.txt"
        Write-Host "Error checking……

System: Secure Boot status, logged to file" -ForegroundColor DarkYellow
    }
}

# Disables Guest account logins to prevent unauthorized access.
# Purpose: Ensures the Guest account cannot be used, reducing security risks.
# Functionality: Uses net user to disable the Guest account.
# CyberPatriot Relevance: Disabling Guest logins is a common scoring task.
# Considerations: Safe for Windows 10/11; no significant risks.
function disableGuestLogins {
    Write-Host "Disabling Guest account logins..." -ForegroundColor Gray
    try {
        net user Guest /active:no
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\disableGuestLogins.txt"
        Write-Host "Error disabling Guest logins, logged to file" -ForegroundColor DarkYellow
    }
}

# Ensures the time zone is set to UTC per README.
# Purpose: Verifies and sets time zone to UTC if not already set.
# Functionality: Uses Get-TimeZone and Set-TimeZone.
# CyberPatriot Relevance: Maintains competition guidelines for time zone.
# Considerations: README instructs not to change if set; this checks first.
function ensureUtcTimeZone {
    Write-Host "Ensuring UTC time zone..." -ForegroundColor Gray
    try {
        if ((Get-TimeZone).Id -ne "UTC") {
            Set-TimeZone -Id "UTC"
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\ensureUtcTimeZone.txt"
        Write-Host "Error ensuring UTC time zone, logged to file" -ForegroundColor DarkYellow
    }
}

# Sets the membership of the "voyagers" group per README.
# Purpose: Configures group membership to specified users.
# Functionality: Removes current members and adds specified users.
# CyberPatriot Relevance: Aligns with README audit requirements for group membership.
# Considerations: Assumes group exists; creates if not (optional).
function setVoyagersGroup {
    Write-Host "Setting voyagers group membership..." -ForegroundColor Gray
    try {
        $groupName = "voyagers"
        $members = @("gcooper", "scar", "zazu", "sarafina")
        if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $groupName
        }
        Get-LocalGroupMember -Group $groupName | ForEach-Object { Remove-LocalGroupMember -Group $groupName -Member $_.Name -ErrorAction SilentlyContinue }
        foreach ($member in $members) {
            Add-LocalGroupMember -Group $groupName -Member $member -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\setVoyagersGroup.txt"
        Write-Host "Error setting voyagers group, logged to file" -ForegroundColor DarkYellow
    }
}

# Ensures all authorized users from README exist.
# Purpose: Creates missing authorized users (admins and users).
# Functionality: Uses New-LocalUser if missing; passwords set in localPass.
# CyberPatriot Relevance: Ensures only authorized accounts exist per README.
# Considerations: Creates with no password initially; set later.
function ensureAuthorizedUsers {
    Write-Host "Ensuring authorized users exist..." -ForegroundColor Gray
    try {
        $authorizedAdmins = @("ashepard", "ygagarin", "vkomarov", "jglenn", "vtereshkova", "gcooper")
        $authorizedUsers = @("timon", "zazu", "ed", "banzai", "scar", "rafiki", "nala", "shenzi", "sarabi", "pumbaa", "sarafina", "gauri", "bruno", "demitri", "erik", "vasca", "veles", "damir", "gopher", "gleb")
        $allAuthorized = $authorizedAdmins + $authorizedUsers
        foreach ($user in $allAuthorized) {
            if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $user -NoPassword
            }
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\ensureAuthorizedUsers.txt"
        Write-Host "Error ensuring authorized users, logged to file" -ForegroundColor DarkYellow
    }
}

# Ensures authorized admins are in the Administrators group.
# Purpose: Adds README admins to Administrators group.
# Functionality: Uses Add-LocalGroupMember.
# CyberPatriot Relevance: Ensures proper admin privileges per README.
# Considerations: Silent if already member.
function ensureAdmins {
    Write-Host "Ensuring authorized admins in group..." -ForegroundColor Gray
    try {
        $authorizedAdmins = @("ashepard", "ygagarin", "vkomarov", "jglenn", "vtereshkova", "gcooper")
        foreach ($admin in $authorizedAdmins) {
            Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\HBA_HS_WIN\ensureAdmins.txt"
        Write-Host "Error ensuring admins, logged to file" -ForegroundColor DarkYellow
    }
}

# Sets Firefox as the default browser per README.
# Purpose: Configures Firefox as default using MDM policy.
# Functionality: Uses CIM to set default associations via base64 XML.
# CyberPatriot Relevance: Aligns with README requirement for default browser.
# Considerations: Requires Firefox installed; works on Pro/Enterprise editions.
function SetDefaultBrowserToFirefox {
    Write-Host "Setting Firefox as default browser..." -ForegroundColor Gray
    try {
        $namespaceName = "root\cimv2\mdm\dmmap"
        $className = "MDM_Policy_Config01_ApplicationDefaults02"
        $obj = Get-CimInstance -Namespace $namespaceName -ClassName $className -Filter "ParentID='./Vendor/MSFT/Policy/Config' and InstanceID='ApplicationDefaults'" -ErrorAction SilentlyContinue
        $base64XML = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPERlZmF1bHRBc3NvY2lhdGlvbnM+CiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5odG0iIFByb2dJZD0iRmlyZWZveEhUTUwiIEFwcGxpY2F0aW9uTmFtZT0iTW96aWxsYSBGaXJlZm94IiAvPgogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIuaHRtbCIgUHJvZ0lkPSJGaXJlZm94SFRNTCIgQXBwbGljYXRpb25OYW1lPSJNb3ppbGxhIEZpcmVmb3giIC8+CiAgPEFzc29jaWF0aW9
