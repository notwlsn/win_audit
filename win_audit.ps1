
#RECORDING TRANSCRIPT TO DUMP FILE
$CurrentDir = $PSScriptRoot
$ServerName = $env:computername
$DumpFilePath = "$CurrentDir\"+$ServerName+"-CONFIG_DUMP_$(get-date -Format yyyyMMdd_hhmmtt).txt"

Start-Transcript -Path $DumpFilePath -NoClobber

Write-Host
Write-Host 'Checking if your PowerShell Script Execution Policy is set to Unrestricted' -ForegroundColor Yellow -BackgroundColor Black
Start-Sleep -s 5
Write-Host
$ExecutionPolicy = Get-ExecutionPolicy
$ScriptExecution = "Unrestricted"
    If ($ExecutionPolicy -eq $ScriptExecution) 
        {
            Write-Host 'Yay! your PowerShell Script Execution Policy is already set to ' $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
        }
    Else
        {
            Write-Host Your PowerShell Script Execution Policy is set to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
            Write-Host
            Write-Host 'This policy should be set to Unrestricted for the script to execute properly.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'This change will be reverted back to its original state after script execution is complete.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'Setting PowerShell Script Execution Policy to Unrestricted automatically. Please Wait...'
            Start-Sleep -s 5
            
            Set-ExecutionPolicy Unrestricted -force
        
            Write-Host
            Write-Host 'PowerShell Script Execution Policy is now set to Unrestricted.' -ForegroundColor Yellow -BackgroundColor Black
            Start-Sleep -s 5
        }
"`n"

#BEGIN SCRIPT

Write-Host =========
Write-Host SEC-AUDIT
Write-Host =========
Write-Host ==============================================================================
Write-Host PowerShell Script for Windows Server Compliance / Security Configuration Audit
Write-Host ==============================================================================
Write-Host

<# 
===============
VERSION HISTORY 
===============

Current
=======
Version Details: V1.0.1
Release Date: 29-Jan-2019

#>

Write-Host ========================
Write-Host 1.0. LICENSE INFORMATION 
Write-Host ======================== 
Write-Output '
PowerPower Shell Script for Windows Compliance / Security Configuration Audit.
'
"`n"

Write-Host BEGINNING TO RETRIEVE CONFIGURATION. PLEASE WAIT... -ForegroundColor Yellow -BackgroundColor Black
Write-Host Please close all other windows until the retrieval is complete.
Write-Host
Start-Sleep -s 5

Write-Host ========================
Write-Host 2.0. GENERAL INFORMATION 
Write-Host ======================== 
Write-Host
Write-Host TIMESTAMP INFORMATION
Write-Host =====================
    Get-Date
Write-Host
Write-Host OPERATING SYSTEM / SERVICE PACK / ARCHITECTURE INFORMATION
Write-Host ==========================================================
$sServer = "."
$sOS =Get-WmiObject -class Win32_OperatingSystem -computername $sServer
$sOS | Select-Object Description, Caption, OSArchitecture, ServicePackMajorVersion | Format-List | Out-Host
Write-Host
Write-Host SERVER INFORMATION
Write-Host ==================
    Get-CimInstance Win32_OperatingSystem | FL * | Out-Host
Write-Host
Write-Host INTERNET EXPLORER INFORMATION
Write-Host =============================
    (Get-ItemProperty 'HKLM:\Software\Microsoft\Internet Explorer').SvcVersion
Write-Host
Write-Host NETWORK CONFIGURATION
Write-Host =====================
    ipconfig /all | Out-Host
Write-Host
Write-Host LOCAL ACCOUNTS INFORMATION
Write-Host ==========================
    Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | 
        Select-Object PSComputerName, Status, Caption, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, PasswordChangeable, PasswordRequired, SID, SIDType | Out-Host
Write-Host
Write-Host LOCAL PASSWORD POLICY
Write-Host =====================
    net accounts | Out-Host
Write-Host
Write-Host GROUP POLICY INFORMATION
Write-Host ========================
    gpresult /Z
"`n"

Write-Host ====================================
Write-Host 2.1. AUDITING / LOGGING / MONITORING 
Write-Host ==================================== 

Write-Host =================================
Write-Host 2.1.1. AUDITING SHOULD BE ENABLED
Write-Host =================================
Write-Host
    AuditPol /List /user /v
Write-Host
Write-Host Note: If there are no user accounts displayed, then auditing is not enabled for any user account.
Write-Host
Write-Host LISTING AUDIT CATEGORIES
Write-Host ========================
    AuditPol /list /category /v
Write-Host
Write-Host LISTING AUDIT SUB-CATEGORIES
Write-Host ============================
    AuditPol /list /subcategory:* /v
Write-Host
Write-Host USER-LEVEL AUDIT SETTINGS FOR ALL USER ACCOUNTS
Write-Host ===============================================
    AuditPol /get /user:* /category:*
Write-Host Note: If error occurs here and usage syntax is displayed then, Error 0x00000534 occurred: No mapping between account names and security IDs was done.
Write-Host
Write-Host USER-LEVEL AUDIT SETTINGS FOR DEFAULT ADMINISTRATOR ACCOUNT
Write-Host ===========================================================
    Auditpol /get /user:Administrator /category:*
Write-Host
Write-Host USER-LEVEL AUDIT SETTINGS FOR DEFAULT GUEST ACCOUNT
Write-Host ===================================================
    Auditpol /get /user:Guest /category:*
Write-Host
Write-Host SYSTEM-LEVEL AUDIT CATEGORY SETTINGS
Write-Host ====================================
    AuditPol /get /category:*
Write-Host
Write-Host CrashOnAuditFail SETTINGS
Write-Host =========================
    auditpol /get /option:CrashOnAuditFail
Write-Host Note: The CrashOnAuditFail option causes the system to crash when the auditing system fails for some reason. This is a safety feature because it ensures that no one can turn off auditing and then continue to use the system unless they use the standard methods to do so and have the proper rights.
Write-Host
Write-Host FULL PrivilegeAuditing SETTINGS
Write-Host ===============================
    auditpol /get /option:FullPrivilegeAuditing
Write-Host
Write-Host AUDIT BASE OBJECTS SETTINGS
Write-Host ===========================
    auditpol /get /option:AuditBaseObjects
"`n"

Write-Host ==================================
Write-Host 2.1.2. EVENT LOG SIZES INFORMATION
Write-Host ==================================
Write-Host "Note: Maximum size must be = or > 100 MB."
Write-Host
Write-Host APPLICATION EVENT LOG PROPERTIES
Write-Host ================================
    Write-Host Maximum-Size in Bytes: -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application').MaxSize
Write-Host
Write-Host SYSTEM EVENT LOG PROPERTIES
Write-Host ===========================
    Write-Host Maximum-Size in Bytes: -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\System').MaxSize
Write-Host
Write-Host SECURITY EVENT LOG PROPERTIES
Write-Host =============================
    Write-Host Maximum-Size in Bytes: -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security').MaxSize
Write-Host
Write-Host ================================
Write-Host 2.1.3. PERMISSIONS ON EVENT LOGS
Write-Host ================================
Write-Host "Note: Restrict Guest Access value in registry should be set to 1."
Write-Host
Write-Host APPLICATION EVENT LOG PERMISSIONS
Write-Host =================================
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application').RestrictGuestAccess
Write-Host
Write-Host SYSTEM EVENT LOG PERMISSIONS
Write-Host ============================
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\System').RestrictGuestAccess
Write-Host
Write-Host SECURITY EVENT LOG PERMISSIONS
Write-Host ==============================
    Write-Host "Restrict Guest Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security').RestrictGuestAccess
Write-Host
Write-Host "DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS (DACLS) ON APPLICATION EVENT LOG"
Write-Host ================================================================================
    cacls "C:\WINDOWS\system32\winevt\Logs\Application.evtx"
Write-Host
Write-Host "DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS (DACLS) ON SYSTEM EVENT LOG"
Write-Host ===========================================================================
    cacls "C:\WINDOWS\system32\winevt\Logs\System.evtx"
Write-Host
Write-Host "DISPLAYING DISCRETIONARY ACCESS CONTROL LISTS (DACLS) ON SECURITY EVENT LOG"
Write-Host =============================================================================
    cacls "C:\WINDOWS\system32\winevt\Logs\Security.evtx"
"`n"

Write-Host ==================================================================
Write-Host 2.1.4. AUDIT THE ACCESS OF GLOBAL SYSTEM OBJECTS SHOULD BE DISABLED
Write-Host ==================================================================
Write-Host "Note: Audit Base Objects value in registry should be set to 0."
Write-Host
Write-Host AUDIT BASE OBJECT SETTINGS
Write-Host ==========================
    Write-Host "Audit Base Objects Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\').AuditBaseObjects
"`n"

Write-Host ===================================================================================================
Write-Host 2.1.5. AUDITING OF SENSITIVE SYSTEM, APPLICATION FILES AND DIRECTORIES SHOULD BE ENABLED ON SERVERS
Write-Host ===================================================================================================
Write-Host
Write-Host ACLS FOR SYSTEM ROOT
Write-Host ====================
    Get-Acl "$env:SystemRoot" |Format-List | Out-Host

Write-Host ACLS FOR SYSTEM32 FOLDER
Write-Host ========================
    Get-Acl "$env:SystemRoot\system32" |Format-List | Out-Host

Write-Host ACLS FOR DRIVERS FOLDER
Write-Host =======================
    Get-Acl "$env:SystemRoot\system32\drivers" |Format-List | Out-Host

Write-Host ACLS FOR CONFIG FOLDER
Write-Host ======================
    Get-Acl "$env:SystemRoot\System32\config" |Format-List | Out-Host

Write-Host ACLS FOR SPOOL FOLDER
Write-Host =====================
    Get-Acl "$env:SystemRoot\System32\spool" |Format-List | Out-Host
"`n"

Write-Host =======================================================================
Write-Host 2.1.6. AUDITING OF SENSITIVE REGISTRY KEYS SHOULD BE ENABLED ON SERVERS
Write-Host =======================================================================
Write-Host
Write-Host ACLS FOR SYSTEM KEY IN REGISTRY
Write-Host ===============================
    Get-Acl "HKLM:\SYSTEM" |Format-List | Out-Host

Write-Host ACLS FOR PERFLIB KEY IN REGISTRY
Write-Host ================================
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib" |Format-List | Out-Host

Write-Host ACLS FOR WINLOGON KEY IN REGISTRY
Write-Host =================================
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" |Format-List | Out-Host
    
Write-Host ACLS FOR LSA KEY IN REGISTRY
Write-Host ============================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |Format-List | Out-Host   

Write-Host ACLS FOR SECURE PIPE SERVERS KEY IN REGISTRY
Write-Host ============================================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers" |Format-List | Out-Host

Write-Host ACLS FOR KNOWNDLLS KEY IN REGISTRY
Write-Host ==================================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" |Format-List | Out-Host

Write-Host ACLS FOR ALLOWEDPATHS KEY IN REGISTRY
Write-Host =====================================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" |Format-List | Out-Host

Write-Host ACLS FOR SHARES KEY IN REGISTRY
Write-Host ===============================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Shares" |Format-List | Out-Host

Write-Host ACLS FOR UPS KEY IN REGISTRY
Write-Host ============================
Write-Host Note: If there is error in the output for this key, then propably there is no system UPS.
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\UPS" |Format-List | Out-Host

Write-Host ACLS FOR SNMP KEYS IN REGISTRY
Write-Host ==============================
Write-Host Note: If there is error in the output for the keys in this section, then propably SNMP is not configured.
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" |Format-List | Out-Host
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\Policies\SNMP\Parameters\ValidCommunities" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\Policies\SNMP\Parameters\PermittedManagers" |Format-List | Out-Host

Write-Host ACLS FOR CURRENT VERSION KEYS IN REGISTRY
Write-Host =========================================
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\AeDebug" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Fonts" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontSubstitutes" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Font Drivers" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontMapper" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\GRE_Initialize" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI Extensions" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Ports" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\ProfileList" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Compatibility32" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Drivers32" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI32" |Format-List | Out-Host

Write-Host "Note: There might be errors in ACLS output for the keys below depending on the version of the Operating System. There should probably be no errors for older versions of Operating Systems."
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Compatibility" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Drivers" |Format-List | Out-Host 
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Embedding" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Type 1 Installer" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\WOW" |Format-List | Out-Host
    Get-Acl "HKCR:\" |Format-List | Out-Host

Write-Host ACLS FOR RPC KEYS IN REGISTRY
Write-Host =============================
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\RPC" |Format-List | Out-Host
"`n"

Write-Host =============================================================================================
Write-Host 2.1.7. AUDITING SHOULD BE ENABLED FOR OBJECT ACCESS IF AN EVENT CORRELATION SYSTEM IS PRESENT
Write-Host =============================================================================================
    AuditPol /get /category:"Object Access"

Write-Host =====================================================================
Write-Host 2.1.8. AUDITING SHOULD BE ENABLED FOR LOGON EVENT SUCCESS AND FAILURE
Write-Host =====================================================================
    AuditPol /get /category:"Logon/Logoff,Account Logon"

Write-Host ============================================================================
Write-Host 2.1.9. AUDITING SHOULD BE ENABLED FOR ACCOUNT MANAGEMENT SUCCESS AND FAILURE
Write-Host ============================================================================
    AuditPol /get /category:"Account Management"
"`n"

Write-Host ======================================
Write-Host 2.2. FILE SYSTEM ACCESS AND MANAGEMENT 
Write-Host ====================================== 

Write-Host ==================================================================
Write-Host 2.2.1. SHARES THAT ARE ACCESSIBLE ANONYMOUSLY SHOULD BE RESTRICTED
Write-Host ==================================================================
Write-Host "Note: The recommended Value of following registry key should be set to 1."
Write-Host
Write-Host "Restrict Null Session Access Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters').restrictnullsessaccess
"`n"

Write-Host ===============================
Write-Host 2.2.2. SYSTEM FOLDER PERMISSION 
Write-Host ===============================
    Get-Acl "$env:SystemRoot\system32" |Format-List | Out-Host
"`n"

Write-Host =================================================================================
Write-Host 2.2.3. DIRECTORIES THAT CONATAIN SENSITIVE WINDOWS SYSTEM FILES SHOULD BE SECURED 
Write-Host =================================================================================
    Get-Acl "$env:SystemRoot" |Format-List | Out-Host
    Get-Acl "$env:SystemDrive" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\system32" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\system32\drivers" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\System32\config" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\System32\spool" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\System32\spool" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\security" |Format-List | Out-Host
Write-Host "Note: The below folders will be present in AD server only."
Write-Host
    Get-Acl "$env:SystemRoot\sysvol" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\ntds" |Format-List | Out-Host
    Get-Acl "$env:SystemRoot\ntfrs" |Format-List | Out-Host
"`n"

Write-Host ================================================================================
Write-Host 2.2.4 KEY EXECUTIBLE FILES SHOULD BE PROPERLY RESTRICTED FROM UNAUTHORISED USERS
Write-Host ================================================================================
Write-Host "arp.exe"
    cacls "C:\Windows\system32\arp.exe"
Write-Host "at.exe"
    cacls "C:\Windows\system32\at.exe"
Write-Host "attrib.exe"
    cacls "C:\Windows\system32\attrib.exe"
Write-Host "cacls.exe"
    cacls "C:\Windows\system32\cacls.exe"
Write-Host "cmd.exe"
    cacls "C:\Windows\system32\cmd.exe"
Write-Host "dcpromo.exe"
    cacls "C:\Windows\system32\dcpromo.exe"
Write-Host "eventcreate.exe"
    cacls "C:\Windows\system32\eventcreate.exe"
Write-Host "finger.exe"
    cacls "C:\Windows\system32\finger.exe"
Write-Host "ftp.exe"
    cacls "C:\Windows\system32\ftp.exe"
Write-Host "gpupdate.exe"
    cacls "C:\Windows\system32\gpupdate.exe"
Write-Host "icacls.exe"
    cacls "C:\Windows\system32\icacls.exe"
Write-Host "ipconfig.exe"
    cacls "C:\Windows\system32\ipconfig.exe"
Write-Host "nbtstat.exe"
    cacls "C:\Windows\system32\nbtstat.exe"
Write-Host "net.exe"
cacls "C:\Windows\system32\net.exe"
Write-Host "net1.exe"
         "C:\Windows\system32\net1.exe"
Write-Host "netsh.exe"
    cacls "C:\Windows\system32\netsh.exe"
Write-Host "netstat.exe"
cacls "C:\Windows\system32\netstat.exe"
Write-Host "nslookup.exe"
    cacls "C:\Windows\system32\nslookup.exe"
Write-Host "ping.exe"
    cacls "C:\Windows\system32\ping.exe"
Write-Host "reg.exe"
    cacls "C:\Windows\system32\reg.exe"
Write-Host "regedt32.exe"
    cacls "C:\Windows\system32\regedt32.exe"
Write-Host "regini.exe"
    cacls "C:\Windows\system32\regini.exe"
Write-Host "regsvr32.exe"
    cacls "C:\Windows\system32\regsvr32.exe"
Write-Host "route.exe"
    cacls "C:\Windows\system32\route.exe"
Write-Host "runonce.exe"
    cacls "C:\Windows\system32\runonce.exe"
Write-Host "sc.exe"
    cacls "C:\Windows\system32\sc.exe"
Write-Host "secedit.exe"
    cacls "C:\Windows\system32\secedit.exe"
Write-Host "subst.exe"
    cacls "C:\Windows\system32\subst.exe"
Write-Host "systeminfo.exe"
    cacls "C:\Windows\system32\systeminfo.exe"
Write-Host "syskey.exe"
    cacls "C:\Windows\system32\syskey.exe"
Write-Host "telnet.exe"
    cacls "C:\Windows\system32\telnet.exe"
Write-Host "tftp.exe"
    cacls "C:\Windows\system32\tftp.exe"
Write-Host "tlntsvr.exe"
    cacls "C:\Windows\system32\tlntsvr.exe"
Write-Host "tracert.exe"
    cacls "C:\Windows\system32\tracert.exe"
Write-Host "xcopy.exe"
    cacls "C:\Windows\system32\xcopy.exe"
"`n"

Write-Host ===========================================================================================================
Write-Host 2.2.5. KEYS SHOULD BE SECURED SO THAT UNAUTHORIZED USERS CANNOT MODIFY THE LIST OF PROGRAMS RUN ON START UP
Write-Host ===========================================================================================================
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" |Format-List | Out-Host

Write-Host ==============================================================================
Write-Host "2.2.6. THE REGISTRY'S REMOTELY ACCESSIBLE PATHS AND SUBPATHS SHOULD BE SECURED"
Write-Host ==============================================================================
Write-Host "Note: Below are the default paths that are remotely accessible."
    Get-Acl "HKLM:\System\CurrentControlSet\Control\ProductOptions" |Format-List | Out-Host
    Get-Acl "HKLM:\System\CurrentControlSet\Control\Server Applications" |Format-List | Out-Host
    Get-Acl "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" |Format-List | Out-Host

Write-Host =============================================================================
Write-Host 2.2.7. UNAUTHORIZED USERS SHOULD NOT BE ALLOWED TO REMOTELY EDIT THE REGISTRY
Write-Host =============================================================================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" |Format-List | Out-Host

Write-Host ============================================================================================
Write-Host "2.2.8. UNAUTHORIZED USERS SHOULD NOT BE ALLOWED TO REMOTELY EDIT THE REGISTRY'S ALLOWED PATH"
Write-Host ============================================================================================
    Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" |Format-List | Out-Host
"`n"

Write-Host =====================
Write-Host 2.3. GROUP MANAGEMENT 
Write-Host ===================== 

Write-Host =========================================
Write-Host 2.3.1. BACKGROUND REFRESH OF GROUP POLICY
Write-Host =========================================
Write-Host "Note: If there is no key set, then background refresh of group policy is not configured."
Write-Host
Write-Host "Background Refresh of Group Policy Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').DisableBkGndGroupPolicy
"`n"

Write-Host =================================
Write-Host 2.3.2. REGISTRY POLICY PROCESSING
Write-Host =================================
Write-Host "Note: If there are no keys set, then registry policy processing is not configured. If registry policy processing is configured then the two keys below are set in the registry with value 1." 
Write-Host
Write-Host "NoBackgroundPolicy Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}').NoBackgroundPolicy
Write-Host
Write-Host "NoGPOListChanges Value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}').NoGPOListChanges
Write-Host
Write-Host "Below are all the subkeys that are present in the Group Policy key in registry" -NoNewline
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
Write-Host
Write-Output 'This policy setting determines when registry policies are updated.

This policy setting affects all policies in the Administrative Templates folder and any other policies that store values in the registry. It overrides customized settings that the program implementing a registry policy set when it was installed.

The Do not apply during periodic background processing options registry key Value is NoBackgroundPolicy. This option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart. Background updates can disrupt the user, cause a program to stop or operate abnormally, and, in rare cases, damage data.

In order to prevent computer from refreshing registry in background while it is in use, the value data of NoBackgroundPolicy should be to 1

To Process even if the Group Policy objects have not changed, the value data of NoGPOListChanges should be to 0

The Process even if the Group Policy objects have not changed option updates and reapplies the policies even if the policies have not changed. Many policy implementations specify that they are updated only when changed. However, you might want to update unchanged policies, such as reapplying a desired policy setting in case a user has changed it.'
"`n"

Write-Host =======================================================================================================
Write-Host 2.3.3. THE BUILT IN LOCAL GROUPS SHOULD ONLY CONTAIN GLOBAL GROUPS THAT ARE AUTHORIZED FOR EACH PURPOSE
Write-Host =======================================================================================================

Write-Host "Below is the list of all local groups and its members presents on"$server" server."
    $server = "$env:COMPUTERNAME"
    $computer = [ADSI]"WinNT://$server,computer"

    $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach {
        write-host $_.name
        write-host "------"
        $group =[ADSI]$_.psbase.Path
        $group.psbase.Invoke("Members") | foreach {$_."GetType".Invoke().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        write-host
    }

Write-Host "Below is the list of all groups on" (Get-WmiObject Win32_ComputerSystem).Domain -NoNewline
Write-Host " Domain."
    net group /domain | Out-Host
"`n"

Write-Host =====================================================================================
Write-Host 2.3.4. NULL CREDENTIAL LOGON SHOULD NOT BE INCLUDED AS A MEMBER OF THE EVERYONE GROUP
Write-Host =====================================================================================
Write-Host "Note: The recommended value of following registry key should be set to 0." 
Write-Host
Write-Host "everyoneincludesanonymous value in Registry is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa').everyoneincludesanonymous
"`n"

Write-Host =====================================================================================================
Write-Host 2.3.5. RESTRICTED GROUP FEATURE SHOULD BE UTILIZED TO CONTROL ACCESS TO CRITICAL GROUPS ON THE SERVER
Write-Host =====================================================================================================

$RestrictedGroup = Get-WMIObject Win32_Group -filter "domain='$env:computername'" | Select-String -AllMatches Restricted | Out-Host

#!$variablename is to check that if $variablename has $null as value.
#if (!$variablename) { Write-Host "variable is null" }
#$variablename is to check if $variablename has any value except $null.
#if ($variablename) { Write-Host "variable is NOT null" }
Write-Host
If (!$RestrictedGroup) {
    Write-Host Restricted group is not present.
    }
    else {
    Write-Host Restricted group is present.
    }
"`n"

Write-Host ================================================
Write-Host 2.3.6. TELNET CLIENT GROUP SHOULD NOT BE CREATED
Write-Host ================================================

$RestrictedGroup = Get-WMIObject Win32_Group -filter "domain='$env:computername'" | Select-String -AllMatches TelnetClients | Out-Host

#!$variablename is to check that if $variablename has $null as value.
#if (!$variablename) { Write-Host "variable is null" }
#$variablename is to check if $variablename has any value except $null.
#if ($variablename) { Write-Host "variable is NOT null" }
Write-Host
If (!$RestrictedGroup) {
    Write-Host TelnetClients group is not present.
    }
    else {
    Write-Host TelnetClients group is present.
    }
"`n"

Write-Host =========================
Write-Host 2.4.NETWORK CONFIGURATION
Write-Host =========================

    ipconfig /all | Out-Host
"`n"

Write-Host =================================
Write-Host 2.4.1. REMOTE ASSISTANCE SETTINGS
Write-Host =================================
Write-Host

Function Get-RemoteDesktopConfig
    {if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 1)

              {"RDP connections are not allowed"}

     elseif ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1)
             {"Only Secure RDP Connections allowed"} 

     else     {"All RDP connections allowed"}

    } 

Write-Host Remote Desktop Configuration Settings
Write-Host =====================================
Write-Host
    Get-RemoteDesktopConfig
Write-Host

Function Get-RemoteGroupMembership
{
    [CmdletBinding()]
    PARAM
    (
        [Parameter(HelpMessage="Computer or computers to gather information from",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DNSHostName','PSComputerName')]
        [string[]]
        $ComputerName=$env:computername,
        
        [Parameter(HelpMessage="Include empty groups in results")]
        [switch]
        $IncludeEmptyGroups,
       
        [Parameter(HelpMessage="Maximum number of concurrent threads")]
        [ValidateRange(1,65535)]
        [int32]
        $ThrottleLimit = 32,
 
        [Parameter(HelpMessage="Timeout before a thread stops trying to gather the information")]
        [ValidateRange(1,65535)]
        [int32]
        $Timeout = 120,
 
        [Parameter(HelpMessage="Display progress of function")]
        [switch]
        $ShowProgress,
        
        [Parameter(HelpMessage="Set this if you want the function to prompt for alternate credentials")]
        [switch]
        $PromptForCredential,
        
        [Parameter(HelpMessage="Set this if you want to provide your own alternate credentials")]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN
    {
        # Gather possible local host names and IPs to prevent credential utilization in some cases
        Write-Verbose -Message 'Local Group Membership: Creating local hostname list'
        $IPAddresses = [net.dns]::GetHostAddresses($env:COMPUTERNAME) | Select-Object -ExpandProperty IpAddressToString
        $HostNames = $IPAddresses | ForEach-Object {
            try {
                [net.dns]::GetHostByAddress($_)
            } catch {
                # We do not care about errors here...
            }
        } | Select-Object -ExpandProperty HostName -Unique
        $LocalHost = @('', '.', 'localhost', $env:COMPUTERNAME, '::1', '127.0.0.1') + $IPAddresses + $HostNames
 
        Write-Verbose -Message 'Local Group Membership: Creating initial variables'
        $runspacetimers       = [HashTable]::Synchronized(@{})
        $runspaces            = New-Object -TypeName System.Collections.ArrayList
        $bgRunspaceCounter    = 0
        
        if ($PromptForCredential)
        {
            $Credential = Get-Credential
        }
        
        Write-Verbose -Message 'Local Group Membership: Creating Initial Session State'
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($ExternalVariable in ('runspacetimers', 'Credential', 'LocalHost'))
        {
            Write-Verbose -Message "Local Group Membership: Adding variable $ExternalVariable to initial session state"
            $iss.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $ExternalVariable, (Get-Variable -Name $ExternalVariable -ValueOnly), ''))
        }
        
        Write-Verbose -Message 'Local Group Membership: Creating runspace pool'
        $rp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
        $rp.ApartmentState = 'STA'
        $rp.Open()
 
        # This is the actual code called for each computer
        Write-Verbose -Message 'Local Group Membership: Defining background runspaces scriptblock'
        $ScriptBlock = {
            [CmdletBinding()]
            Param
            (
                [Parameter(Position=0)]
                [string]
                $ComputerName,
 
                [Parameter(Position=1)]
                [int]
                $bgRunspaceID,
                
                [Parameter()]
                [switch]
                $IncludeEmptyGroups
            )
            $runspacetimers.$bgRunspaceID = Get-Date
            
            try
            {
                Write-Verbose -Message ('Local Group Membership: Runspace {0}: Start' -f $ComputerName)
                $WMIHast = @{
                    ComputerName = $ComputerName
                    ErrorAction = 'Stop'
                }
                if (($LocalHost -notcontains $ComputerName) -and ($Credential -ne $null))
                {
                    $WMIHast.Credential = $Credential
                }

                # General variables
                $GroupMembership = @()
                $PSDateTime = Get-Date
                
                #region Group Information
                Write-Verbose -Message ('Local Group Membership: Runspace {0}: Group memberhsip information' -f $ComputerName)

                # Modify this variable to change your default set of display properties
                $defaultProperties    = @('ComputerName','GroupMembership')
                $wmi_groups = Get-WmiObject @WMIHast -Class win32_group -filter "Domain = '$ComputerName'"
                foreach ($group in $wmi_groups)
                {
                    $Query = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = `"Win32_Group.Domain='$ComputerName',Name='$($group.name)'`""
                    $wmi_users = Get-WmiObject @WMIHast -query $Query
                    if (($wmi_users -eq $null) -and ($IncludeEmptyGroups))
                    {
                        $MembershipProperty = @{
                            'Group' = $group.Name
                            'GroupMember' = ''
                            'MemberType' = ''
                        }
                        $GroupMembership += New-Object PSObject -Property $MembershipProperty
                    }
                    else
                    {
                        foreach ($user in $wmi_users.partcomponent)
                        {
                            if ($user -match 'Win32_UserAccount')
                            {
                                $Type = 'User Account'
                            }
                            elseif ($user -match 'Win32_Group')
                            {
                                $Type = 'Group'
                            }
                            elseif ($user -match 'Win32_SystemAccount')
                            {
                                $Type = 'System Account'
                            }
                            else
                            {
                                $Type = 'Other'
                            }
                            $MembershipProperty = @{
                                'Group' = $group.Name
                                'GroupMember' = ($user.replace("Domain="," , ").replace(",Name=","\").replace("\\",",").replace('"','').split(","))[2]
                                'MemberType' = $Type
                            }
                            $GroupMembership += New-Object PSObject -Property $MembershipProperty
                        }
                    }
                }
                
                $ResultProperty = @{
                    'PSComputerName' = $ComputerName
                    'PSDateTime' = $PSDateTime
                    'ComputerName' = $ComputerName
                    'GroupMembership' = $GroupMembership
                }
                $ResultObject = New-Object -TypeName PSObject -Property $ResultProperty
                
                # Setup the default properties for output
                $ResultObject.PSObject.TypeNames.Insert(0,'My.GroupMembership.Info')
                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultProperties)
                $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
                $ResultObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers
                Write-Output -InputObject $ResultObject
                #endregion Group Information
            }
            catch
            {
                Write-Warning -Message ('Local Group Membership: {0}: {1}' -f $ComputerName, $_.Exception.Message)
            }
            Write-Verbose -Message ('Local Group Membership: Runspace {0}: End' -f $ComputerName)
        }
 
        Function Get-Result
        {
            [CmdletBinding()]
            Param 
            (
                [switch]$Wait
            )
            do
            {
                $More = $false
                foreach ($runspace in $runspaces)
                {
                    $StartTime = $runspacetimers[$runspace.ID]
                    if ($runspace.Handle.isCompleted)
                    {
                        Write-Verbose -Message ('Local Group Membership: Thread done for {0}' -f $runspace.IObject)
                        $runspace.PowerShell.EndInvoke($runspace.Handle)
                        $runspace.PowerShell.Dispose()
                        $runspace.PowerShell = $null
                        $runspace.Handle = $null
                    }
                    elseif ($runspace.Handle -ne $null)
                    {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime)
                    {
                        if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $runspace.PowerShell)
                        {
                            Write-Warning -Message ('Timeout {0}' -f $runspace.IObject)
                            $runspace.PowerShell.Dispose()
                            $runspace.PowerShell = $null
                            $runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($threat in $runspaces.Clone())
                {
                    if ( -not $threat.handle)
                    {
                        Write-Verbose -Message ('Local Group Membership: Removing {0} from runspaces' -f $threat.IObject)
                        $runspaces.Remove($threat)
                    }
                }
                if ($ShowProgress)
                {
                    $ProgressSplatting = @{
                        Activity = 'Local Group Membership: Getting info'
                        Status = 'Local Group Membership: {0} of {1} total threads done' -f ($bgRunspaceCounter - $runspaces.Count), $bgRunspaceCounter
                        PercentComplete = ($bgRunspaceCounter - $runspaces.Count) / $bgRunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        }
    }
    PROCESS
    {
        foreach ($Computer in $ComputerName)
        {
            $bgRunspaceCounter++
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
            $null = $psCMD.AddParameter('ComputerName',$Computer)
            $null = $psCMD.AddParameter('bgRunspaceID',$bgRunspaceCounter)
            $null = $psCMD.AddParameter('IncludeEmptyGroups',$IncludeEmptyGroups)
            $null = $psCMD.AddParameter('Verbose',$VerbosePreference)
            $psCMD.RunspacePool = $rp
 
            Write-Verbose -Message ('Local Group Membership: Starting {0}' -f $Computer)
            
            [void]$runspaces.Add(@{
                Handle = $psCMD.BeginInvoke()
                PowerShell = $psCMD
                IObject = $Computer
                ID = $bgRunspaceCounter
           })
           Get-Result
        }
    }
     END
    {
        Get-Result -Wait
        if ($ShowProgress)
        {
            Write-Progress -Activity 'Local Group Membership: Getting local group information' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Local Group Membership: Closing runspace pool"
        $rp.Close()
        $rp.Dispose()
    }
}

Write-Host Remote Group Membership Information
Write-Host ===================================
    Get-RemoteGroupMembership 
"`n"

Write-Host ===============================
Write-Host 2.4.2. TERMINAL SERVER SETTINGS
Write-Host ===============================
Write-Host
Write-Host Terminal Server Settings
Write-Host ------------------------
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Write-Host
Write-Host Terminal Server Client Settings
Write-Host --------------------------------
Write-Host
    Get-ItemProperty 'HKCU:\Software\Microsoft\Terminal Server Client\'
"`n"

#------------------------------Start of UserRights Enumeration Function---------------------- 
<#
CREDITS FOR THIS FUNCTION GOES TO THE AUTHOR - Tony Pombo
#>

Set-StrictMode -Version 2.0

Add-Type '
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier));
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
' # This type (PS_LSA) is used by Grant-UserRight, Revoke-UserRight, Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight, Grant-TokenPriviledge, Revoke-TokenPrivilege

function Get-AccountsWithUserRight {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Priv in $Right) {
            $output = @{'Account'=$lsa.EnumerateAccountsWithUserRight($Priv); 'Right'=$Priv; }
            Write-Output (New-Object -TypeName PSObject -Property $output)
        }
    }
} # Gets all accounts that are assigned a specified privilege

#------------------------------End of UserRights Enumeration Function---------------------- 

Write-Host ==================================================
Write-Host 2.4.3. DENIAL OF ACCESS TO THE SYSTEM FROM NETWORK
Write-Host ==================================================
Write-Host "Note: Below are the user accounts that are denied access to the system from a network."
    Get-AccountsWithUserRight SeDenyNetworkLogonRight | Format-List | Out-Host
"`n"

Write-Host ==========================================================
Write-Host 2.4.4. MINIMUM SESSION SECURITY FOR NTLM SSP BASED SERVERS
Write-Host ==========================================================
Write-Host 'Note: The recommended value of NtlmMinServerSec registry key should be set to 0X20000000'
Write-Host
Write-Host 'NtlmMinServerSec value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\').NtlmMinServerSec
"`n"

Write-Host ======================================================================
Write-Host "2.4.5. MICROSOFT NETWORK SERVER: DIGITALLY SIGN COMMUNICATIONS(Always)"
Write-Host ======================================================================
Write-Host 'Note: The recommended Value of following registry key should be set to 1'
Write-Host
Write-Host 'RequireSecuritySignature for LanmanWorkstation value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\').RequireSecuritySignature
Write-Host
Write-Host 'RequireSecuritySignature for LanmanServer value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\lanmanserver\Parameters\').RequireSecuritySignature
"`n"

Write-Host ==================================================================
Write-Host 2.4.6. DONOT ALLOW ANONYMOUS ENUMERATION OF SAM ACCOUNT AND SHARES
Write-Host ==================================================================
Write-Host 'Note: The recommended value of RestrictAnonymous registry key should be set to 1'
Write-Host
Write-Host 'RestrictAnonymous value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous
"`n"

Write-Host ================================================================
Write-Host 2.4.7. DONOT STORE LANMANAGER HASH VALUE ON NEXT PASSWORD CHANGE
Write-Host ================================================================
Write-Host  'Note: The recommended value of NoLMHash registry key should be set to 1'
Write-Host
Write-Host 'NoLMHash value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\').NoLMHash
"`n"

Write-Host =======================================
Write-Host 2.4.8. LAN MANAGER AUTHENTICATION LEVEL
Write-Host =======================================
Write-Host 'Note: For the Enterprise Member Server and Enterprise Domain Controller profile The recommended value of following registry key should be set to 3.For the SSLF Member Server and SSLF Domain Controller profile The recommended Value of following registry key should be set to 5' 
Write-Host
Write-Host 'Note: In certain scenarios, this key might not be present in newer version of windows.' 
Write-Host
Write-Host 'LmCompatibilityLevel value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\').LmCompatibilityLevel
Write-Output '
LmCompatibilityLevel values and their description
=================================================
0 - Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
1 - Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
2 - Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication.
3 - Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
4 - Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2.
5 - Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2.'
Write-Host
Write-Host 'Below are the other keys presents under the LSA key in registry.' -NoNewline
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\'
"`n"

Write-Host =============================================
Write-Host 2.4.9. SET CLIENT CONNECTION ENCRYPTION LEVEL
Write-Host =============================================
Write-Host 'Note: The recommended Value of MinEncryptionLevel registry key should be set to 3'
Write-Host
Write-Host 'MinEncryptionLevel value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').MinEncryptionLevel
"`n"

Write-Host =====================================
Write-Host 2.4.10. DONOT ALLOW DRIVE REDIRECTION
Write-Host =====================================		
Write-Host 'Note: For the Enterprise Member Server and Enterprise Domain Controller profile(s) The recommended value is Not Configured.For the SSLF Member Server and SSLF Domain Controller profile(s) The recommended value of following registry key should be set to 1.'
Write-Host
Write-Host 'fDisableCdm value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\Wds\rdpwd').fDisableCdm
"`n"

Write-Host ========================
Write-Host 2.5. PASSWORD MANAGEMENT 
Write-Host ========================
Write-Host ========================
Write-Host 2.5.1. PASSWORD POLICY 
Write-Host ========================
Write-Host
Write-Host Local Password Policy
Write-Host =====================
    net accounts | Out-Host
Write-Host
Write-Host Domain Password Policy
Write-Host ======================
Write-Host 'Note: This will work only if the server is connected to the Domain Controller'
Write-Host    
    net accounts /domain | Out-Host
"`n"

Write-Host ==========================================================================================
Write-Host 2.5.2. DEFAULT PASSWORDS SUPPLIED WITH SOFTWARE PACKAGES SHOULD BE CHANGED ON INSTALLATION
Write-Host ==========================================================================================
Write-Host "Below are the list of programs that are installed on this server."
Write-Host
Write-Host "Note: Default passwords for know software packages should be checked manually."
    Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-Host
"`n"

Write-Host ========================================================================
Write-Host 2.5.3. PASSWORD SHOULD NOT BE STORED LOCALLY USING REVERSIBLE ENCRYPTION
Write-Host ========================================================================
Write-Host "Note: If the store passwords with reversible encryption setting is not shown, then this control should be checked manually."
Write-Host
Write-Host Local Password Policy
Write-Host =====================
    net accounts | Out-Host
Write-Host
Write-Host Domain Password Policy
Write-Host ======================
Write-Host 'Note: This will work only if the server is connected to the Domain Controller'
Write-Host    
    net accounts /domain | Out-Host
"`n"

Write-Host =============================================================
Write-Host 2.5.4. DEFAULT PASSWORD FOR AUTOMATIC LOGON SHOULD BE REMOVED
Write-Host =============================================================
Write-Host Note: The recommended state is that registry value should not exist.
Write-Host
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').DefaultPassword
"`n"

Write-Host ======================================================================================================================================
Write-Host 2.5.5. THE PASSWORD FOR THE RENAMED LOCAL ADMINISTRATOR ACCOUNT SHOULD BE CHANGED IN ACCORDANCE WITH CORPORATE STANDARD AND GUIDELINES 
Write-Host ======================================================================================================================================
Write-Host 'Note: Below are the list of users in group Administrators'    
Write-Host
    net localgroup administrators | Out-Host
"`n"

Write-Host ===================================================================
Write-Host 2.5.6. USERS PRIVATE KEY SHOULD REQUIRE PASSWORD BEFORE BEING USED 
Write-Host ===================================================================
Write-Host "Note: The recommended value of ForceKeyProtection registry key should be set to 2"
Write-Host
Write-Host 'The value of ForceKeyProtection in the registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Cryptography\').ForceKeyProtection
Write-Output '
<0> = Do not force UI on key protection
<1> = Default to UI, but let user change selection
<2> = Force UI on key protection; disable option for user'
"`n"

Write-Host =========================
Write-Host 2.6. SYSTEM CONFIGURATION  
Write-Host =========================

Write-Host ====================
Write-Host 2.6.0 UPDATE HISTORY
Write-Host ====================

    wmic qfe list

Write-Host ==============================
Write-Host 2.6.1. LATEST SECURITY PATCHES
Write-Host ==============================
Write-Host
    Get-HotFix -Description "Security*"
"`n"

Write-Host =======================
Write-Host 2.6.2. SECURITY OPTIONS
Write-Host =======================
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' | select NullSessionPipes, autodisconnect, enableforcedlogoff, enablesecuritysignature, requiresecuritysignature, restrictnullsessaccess, AdjustedNullSessionPipes, EnableAuthenticateUserSharing | Out-Host
"`n"

Write-Host ====================================
Write-Host 2.6.3. FILE SYSTEM OF DISK PARTITION  
Write-Host ====================================
    [System.IO.DriveInfo]::getdrives()
"`n"

Write-Host =======================================
Write-Host 2.6.4. CHECK FOR NON ESSENTIAL SERVICES   
Write-Host ======================================= 
    net start | Out-Host
"`n"

Write-Host =========================
Write-Host 2.6.5. ANTIVIRUS SOFTWARE   
Write-Host ========================= 
    
    function Get-AntivirusName {
    [cmdletBinding()]	
    param (
    [string]$ComputerName = "$env:computername" ,
    $Credential
    )
	    BEGIN 
		    {
			    # Setting WMI query in a variable
	    	    $wmiQuery = "SELECT * FROM AntiVirusProduct"
		    }

	    PROCESS 
		    {
			    # doing getting wmi
                $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue'	   	 
                Write-host $AntivirusProduct.displayName -ForegroundColor Cyan
		    }
	    END {
		    }
    } #end  of the function
     
Write-Host
Write-Host 'Antivirus solution installed on this server is ' -NoNewline 
    Get-AntivirusName
Write-Host
Write-Host **IF OUTPUT IS BLANK - NO ANTI VIRUS IS INSTALLED / REQUIRES MANUAL CHECK**
"`n"

Write-Host ==============================
Write-Host 2.6.6. WINDOWS ERROR REPORTING   
Write-Host ==============================
Write-Host "Note: The recommended Value of following registry keys should be set to 1."
Write-Host
Write-Host "The value of Windows Error Reporting key in HKLM is set to " -NoNewline
    (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\Windows Error Reporting\').Disabled
Write-Host
Write-Host "The value of Windows Error Reporting key in HKCU is set to " -NoNewline
    (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\').Disabled
"`n"

Write-Host ======================
Write-Host 2.6.7. CRASH DETECTION  
Write-Host ======================
Write-Host 'Note: Gathering information about crash and shutdown events. This might take time please be patient.'
Write-Host
Write-Host ' Gathering information ...'  -ForegroundColor Yellow -BackgroundColor Black
    Start-Sleep -s 7
    $events1=get-eventlog system | where-object {$_.EventID -eq '41'} | Format-table -Wrap | Out-Host
        If ( $events1 )
	        {
	            Write-Host ' Found Unexpected System Restarts. Thats Not Good. Please wait???' -ForegroundColor red -backgroundcolor black
	            Start-Sleep -s 7
	    
	            Write-Host ' Here are the list of Events : ' -ForegroundColor Green -BackgroundColor Black
	            Write-Output $events1
	        }
        Else
	        {
	        Write-Host ' No Unexpected System Restarts Found.' -ForegroundColor Green -BackgroundColor Black
	        }
Write-Host ' Now Checking Normal Shutdown Events. ' -ForegroundColor Yellow -BackgroundColor Black
    Start-Sleep -s 7
    $events2=get-eventlog system | where-object {$_.EventID -eq '1076'} | Format-Table -wrap | Out-Host
    $events3=get-eventlog system | where-object {$_.EventID -eq '1074'} | Format-Table -Wrap | Out-Host
    Start-Sleep 20
        If ( $events2 )
	        {
	
	        Write-Host ' Found Normal Shutdown Event. Please wait???' -ForegroundColor Red -BackgroundColor Black
	        Start-Sleep -s 7
	
	        Write-Host ' Here are the list of Events : ' -ForegroundColor green -BackgroundColor Black
	
	        Write-Output $events2
	        }
        Else
	        { 
	        if ( $events3 )
	        {
		        Start-Sleep -s 7
		
		        Write-Output $events3
		
	        }
        else
	        {
	
	        Write-Host ' No such events found from the available logs.' -ForegroundColor Green -BackgroundColor Black
	
	        }
	        }
"`n"

Write-Host ================================
Write-Host 2.6.8. PROXY SETTING PER MACHINE  
Write-Host ================================ 
    Get-ItemProperty 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object *Proxy* | Out-Host
"`n"

Write-Host ================================
Write-Host 2.6.9 WINDOWS MESSENGER SETTINGS 
Write-Host ================================
Write-Host "Note: The recommended Value of following registry key should be set to 1."
Write-Host "This key will not be present in newer version of Windows operating systems."

    Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Messenger\Client\'
"`n"

Write-Host ================================
Write-Host 2.6.10. NTP CLIENT CONFIGURATION 
Write-Host ================================
Write-Host
Write-Host 'NTP Server address in the client is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\SYSTEM\Currentcontrolset\Services\W32time\Parameters\').Ntpserver
"`n"

Write-Host =====================================
Write-Host 2.6.11. FIREWALL SHOULD BE CONFIGURED
Write-Host ======================================
Write-Host
Write-Host 'Below are the firewall profile settings.'
    netsh advfirewall show domainprofile | Out-Host
    netsh advfirewall show privateprofile | Out-Host
    netsh advfirewall show publicprofile | Out-Host
"`n"

Write-Host ======================================================
Write-Host 2.6.12. LEGAL NOTICE AND WARNING SHOULD BE IMPLEMENTED
Write-Host ======================================================
    Get-ItemProperty 'HKLM:/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon' | Select-Object LegalNoticeCaption, LegalNoticeText | Format-List | Out-Host
"`n"

Write-Host ======================================================================
Write-Host 2.6.13. ANONYMOUS ACCESS TO NAMED PIPES AND SHARE SHOULD BE RESTRICTED
Write-Host ======================================================================
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' | select NullSessionPipes, autodisconnect, enableforcedlogoff, enablesecuritysignature, requiresecuritysignature, restrictnullsessaccess, AdjustedNullSessionPipes, EnableAuthenticateUserSharing | Out-Host
"`n"

Write-Host =======================================================================================================
Write-Host 2.6.14. CERTAIN REGISTRY KEYS SHOULD BE SECURED TO PREVENT UNAUTHORIZED ACCESS TO SERVERS CONFIGURATION 
Write-Host =======================================================================================================
    Get-Acl "HKLM:\SOFTWARE" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\PerfLib" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Rpc" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\AeDebug" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Compatibility32" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Drivers32" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Font Drivers" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Fonts" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontMapper" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\FontSubstitutes" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\GRE_Initialize" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI32" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\MCI Extensions" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\Ports" |Format-List | Out-Host
    Get-Acl "HKLM:\SOFTWARE\MICROSOFT\Windows NT\CurrentVersion\ProfileList" |Format-List | Out-Host
"`n"

Write-Host ==================================================================================================
Write-Host 2.6.15. CLIENT CONNECTION SHOULD USE HIGH LEVEL OF ENCRYPTION WHEN CONNECTED VIA TERMINAL SERVICES 
Write-Host ==================================================================================================
Write-Host
Write-Host 'The minimum encryption level value in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\').MinEncryptionLevel
Write-Output '
1 = low
2 = client compatible
3 = high
4 = fips'
"`n" 

Write-Host =======================================
Write-Host 2.6.16. DISABLE AUTORUN FOR ALL DEVICES
Write-Host =======================================
Write-Host 'Note: The recommended value of NoDriveTypeAutoRun registry key should be set to 0xFF. '
Write-Host
Write-Host 'The value of NoDriveTypeAutoRun in the registry is set to ' -NoNewline     
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\").NoDriveTypeAutoRun
Write-Host
Write-Host 'Note: If the key is not found then Autorun is not disabled.'
"`n"

Write-Host ==========================================================
Write-Host 2.6.17. DOMAIN AUTHENTIFICATION REQUIRED TO UNLOCK SERVERS
Write-Host ==========================================================
Write-Host
Write-Host 'The ForceUnlockLogon value in the registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').ForceUnlockLogon
Write-Host
Write-Output '
If Value:0 [hint=Domain controller authentication is not required to unlock the workstation]
If Value:1 [hint=Domain controller authentication is required to unlock the workstation]'
"`n"

Write-Host =================================================================
Write-Host 2.6.18. ERROR REPORTING NOTIFICATION SHOULD BE DISPLAYED TO USERS
Write-Host =================================================================
Write-Host 'Note: The recommended value of DontShowUI registry key should be set to 0, if error reporting is enabled.'    
Write-Host
Write-Host 'The DontShowUI value for error reporting in the registry is set to ' -NoNewline
    (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting').DontShowUI
"`n"

Write-Host ====================================================================================
Write-Host 2.6.19. MICROSOFT NETWORK SERVERS SHOULD DIGITALLY SIGN COMMUNICATIONS WITH CLIENT
Write-Host ====================================================================================
Write-Host 'Note: The value of the EnableSecuritySignature and RequireSecuritySignature should be set to 1.'
Write-Host
Write-Host LanmanServer Settings
Write-Host =====================
Write-Host
Write-Host 'The value of EnableSecuritySignature in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters').EnableSecuritySignature
Write-Host
Write-Host 'The value of RequireSecuritySignature in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters').RequireSecuritySignature
Write-Host
Write-Host 'LanmanWorkstation (client) Settings'
Write-Host ===================================
Write-Host
Write-Host 'The value of EnableSecuritySignature in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters').EnableSecuritySignature
Write-Host
Write-Host 'The value of RequireSecuritySignature in registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters').RequireSecuritySignature
"`n"

Write-Host =====================================================================
Write-Host 2.6.20. NETWORK CONNECTION SETTINGS SHOULD BE CONFIGURED APPROPIATELY
Write-Host =====================================================================
    ipconfig /all | Out-Host
"`n"

Write-Host ==========================================================================================
Write-Host 2.6.21. NTFS SHOUD BE USED ON ALL PARTITION, THERE SHOULD BE NO UNFORMATTED SPACE ON DRIVE
Write-Host ==========================================================================================
    [System.IO.DriveInfo]::getdrives()
"`n"

Write-Host ============================================================================================================================
Write-Host 2.6.22. ONE INSTANCE OF WINDOWS SHOULD BE THE ONLY OPERATING SYSTEM ON THE PRODUCTION SERVER, NO DUAL BOOT PRODUCTION SERVER
Write-Host ============================================================================================================================
    bcdedit
Write-Host
Write-Host 'Checking if the system is booted via BIOS or UEFI' -ForegroundColor Yellow -BackgroundColor Black
Write-Host
    $SecureBoot = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
    If ($SecureBoot -eq '1')
        {
            Write-Host 'Key Present: UEFI Secure Boot is enabled'
        }
    If ($SecureBoot -eq '0')
        {
            Write-Host 'Key Present: UEFI Secure Boot is disabled'
        }
Write-Host
Write-Output '
Note: If the UEFISecureBootEnabled key is not present in the registry, then the system is booted via BIOS.

If the UEFISecureBootEnabled key is present, then the system is booted via UEFI. Check above settings to determine if secure boot is enabled for UEFI.'
"`n"

Write-Host ============================================
Write-Host 2.6.23.  Serial Port and Printer Information
Write-Host ============================================ 
Write-Host
Write-Host Serial Port Information
Write-Host =======================
    Get-WMIObject Win32_SerialPort | Select-Object DeviceID,Description | Out-Host
Write-Host
Write-Host 'Note: If no data is displayed, then there is no serial port in the system.'
Write-Host
Write-Host Printer Information
Write-Host ===================
    Get-WMIObject Win32_Printer | Select-Object Name,PrinterStatus, PrinterState, ShareName | Out-Host
"`n"

Write-Host =====================================================================================================================
Write-Host 2.6.24.  ONLY USERS LOGGED ON LOCALLY SHOULD BE ABLE TO ACCESS DATA ON THE MEDIA IN THE CD-ROM DRIVE AND FLOPPY DRIVE
Write-Host ===================================================================================================================== 
Write-Host "Note: The value of the AllocateFloppies and AllocateCDRoms registry key should be set to 1" 
Write-Host
Write-Host Access to Floppy Disk
Write-Host =====================
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').AllocateFloppies
Write-Host
Write-Host Access to CD-ROM
Write-Host ================
    (Get-ItemProperty  'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').AllocateCDRoms
Write-Host
Write-Host 'Note: If the AllocateFloppies and AllocateCDRoms keys are not present then this setting is not configured.'
"`n"

Write-Host =========================================================================================================================
Write-Host 2.6.25. REMOTE ASSISTANCE FUNCTIONALITY SHOULD BE DISABLED ON SERVERS. ACCESS TO SERVERS SHOULD BE REMOTE DESKTOP SESSION
Write-Host ========================================================================================================================== 
Write-Host 'Note: The fAllowToGetHelp value in the registry should be set to 0 '
Write-Host    
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fAllowToGetHelp
Write-Host
Write-Host 'If this key does not exist, then remote assistance is not configured.'
"`n"

Write-Host ===========================================================
Write-Host 2.6.26. SECURE CHANNEL DATA SHOULD BE SET TO ALWAYS ENCRYPT
Write-Host ============================================================ 
Write-Host 'Note: The SealSecureChannel key value in the registry should be set to 1 '
Write-Host
Write-Host 'The SealSecureChannel key value in the registry is set to ' -NoNewline
    (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters').SealSecureChannel
"`n"

Write-Host ==============================================================================================================
Write-Host 2.6.27. SIMPLE TCP/IP SERVICES THAT ENABLE UNNECESSARY ENTICEMENT INFORMATION SERVICES TO RUN SHOULD BE REMOVED
Write-Host ============================================================================================================== 
Write-Host 'Note: The registry value must be removed or set to  0 or the keys should be removed for the below mentioned SimpTCP services.'
Write-Host
Write-Output 'SimpTCP Services: EnableTcpChargen, EnableTcpDaytime, EnableTcpDiscard, EnableTcpWrite-Host, EnableTcpQotd, EnableUdpChargen, EnableUdpDaytime, EnableUdpDiscard, EnableUdpWrite-Host, EnableUdpQotd' 
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\SimpTCP\Parameters\'
Write-Host
Write-Host 'Note: If the keys are not present then the SimpTCP services are not running.'
"`n"

Write-Host ===============================
Write-Host 2.6.28. USER RIGHTS INFORMATION 
Write-Host ===============================
Write-Host 'Note: Ensure that only authorized users accounts have rights to specific actions.'
Write-Host
Write-Host 'Below are the user rights and their descriptions for reference'
Write-Host ==============================================================
Write-Output '
SeTrustedCredManAccessPrivilege	:	Access Credential Manager as a trusted caller 
SeNetworkLogonRight:                Access this computer from the network 
SeTcbPrivilege:                     Act as part of the operating system 
SeMachineAccountPrivilege:          Add workstations to domain 
SeIncreaseQuotaPrivilege:           Adjust memory quotas for a process 
SeInteractiveLogonRight:            Allow log on locally 
SeRemoteInteractiveLogonRight:      Allow log on through Remote Desktop Services 
SeBackupPrivilege:                  Back up files and directories 
SeChangeNotifyPrivilege:            Bypass traverse checking 
SeSystemtimePrivilege:              Change the system time 
SeTimeZonePrivilege:                Change the time zone 
SeCreatePagefilePrivilege:          Create a page file 
SeCreateTokenPrivilege:             Create a token object 
SeCreateGlobalPrivilege:            Create global objects 
SeCreatePermanentPrivilege:         Create permanent shared objects 
SeCreateSymbolicLinkPrivilege:      Create symbolic links 
SeDebugPrivilege:                   Debugprograms
SeDenyNetworkLogonRight:            Denyaccesstothiscomputerfromthenetwork
SeDenyBatchLogonRight:              Denylogonasabatchjob
SeDenyServiceLogonRight:            Denylogonasaservice
SeDenyInteractiveLogonRight:        Denylogonlocally
SeDenyRemoteInteractiveLogonRight:  DenylogonthroughRemoteDesktopServices
SeEnableDelegationPrivilege:        Enablecomputeranduseraccountstobetrustedfordelegation
SeRemoteShutdownPrivilege:          Forceshutdownfromaremotesystem
SeAuditPrivilege:                   Generatesecurityaudits
SeImpersonatePrivilege:             Impersonateaclientafterauthentication
SeIncreaseWorkingSetPrivilege:      Increaseaprocessworkingset
SeIncreaseBasePriorityPrivilege:    Increaseschedulingpriority
SeLoadDriverPrivilege:              Loadandunloaddevicedrivers
SeLockMemoryPrivilege:              Lockpagesinmemory
SeBatchLogonRight:                  Logonasabatchjob
SeServiceLogonRight:                Logonasaservice
SeSecurityPrivilege:                Manageauditingandsecuritylog
SeRelabelPrivilege:                 Modifyanobjectlabel
SeSystemEnvironmentPrivilege:       Modifyfirmwareenvironmentvalues
SeManageVolumePrivilege:            Performvolumemaintenancetasks
SeProfileSingleProcessPrivilege:    Profilesingleprocess
SeSystemProfilePrivilege:           Profilesystemperformance
SeUndockPrivilege:                  Removecomputerfromdockingstation
SeAssignPrimaryTokenPrivilege:      Replaceaprocessleveltoken
SeRestorePrivilege:                 Restorefilesanddirectories
SeShutdownPrivilege:                Shutdownthesystem
SeSyncAgentPrivilege:               Synchronizedirectoryservicedata
SeTakeOwnershipPrivilege:           Takeownershipoffilesorotherobjects
'
Write-Host
Write-Host 'Below are details user accounts with specific user rights'
Write-Host =========================================================
    Get-AccountsWithUserRight SeTrustedCredManAccessPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeNetworkLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeTcbPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeMachineAccountPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeIncreaseQuotaPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeInteractiveLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeRemoteInteractiveLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeBackupPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeChangeNotifyPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeSystemtimePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeTimeZonePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeCreatePagefilePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeCreateTokenPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeCreateGlobalPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeCreatePermanentPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeCreateSymbolicLinkPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeDebugPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeDenyNetworkLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeDenyBatchLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeDenyServiceLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeDenyInteractiveLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeDenyRemoteInteractiveLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeEnableDelegationPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeRemoteShutdownPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeAuditPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeImpersonatePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeIncreaseWorkingSetPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeIncreaseBasePriorityPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeLoadDriverPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeLockMemoryPrivilege | Format-List | Out-Host 
    Get-AccountsWithUserRight SeBatchLogonRight | Format-List| Out-Host
    Get-AccountsWithUserRight SeServiceLogonRight | Format-List | Out-Host
    Get-AccountsWithUserRight SeSecurityPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeRelabelPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeSystemEnvironmentPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeManageVolumePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeProfileSingleProcessPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeSystemProfilePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeUndockPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeAssignPrimaryTokenPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeRestorePrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeShutdownPrivilege | Format-List | Out-Host
    Get-AccountsWithUserRight SeSyncAgentPrivilege | Format-List | Out-Host
    (Get-AccountsWithUserRight SeTakeOwnershipPrivilege) | Format-List | Out-Host
"`n"

Write-Host ====================================================================
Write-Host 2.6.29. DO NOT ALLOW ANONYMUS ENUMERATION OF SAM ACCOUNTS AND SHARES 
Write-Host ==================================================================== 
Write-Host 'Note: The value of restrictanonymous and restrictanonymoussam keys in the registry should be set to 1.'
    Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\' | Format-List restrictanonymous, restrictanonymoussam | Out-Host
"`n"

Write-Host ==========================================================
Write-Host 2.6.30. TELNET SERVICE SHOULD NOT BE PRESENT ON THE SERVER    
Write-Host ========================================================== 
Write-Host 'Note: The TlntSvr and TelnetServer registry keys must not be present.'
Write-Host
Write-Host 'TlntSvr registry key entry details'
Write-Host ==================================
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr\' 
Write-Host
Write-Host 'TelnetServer registry key entry details'
Write-Host =======================================
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\TelnetServer\' 
"`n"

Write-Host ==================================================================================
Write-Host 2.6.31. USER SESSION THAT ARE INACTIVE FOR A SET AMOUNT OF TIME SHOULD BE DISABLED      
Write-Host ================================================================================== 
Write-Host 'Note: The MaxIdleTime should be set to 30 Minutes (1800000 Milliseconds) and MaxDisconnectionTime should be set to 60 Minutes (3600000 Milliseconds).'
Write-Host
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' | Format-List MaxDisconnectionTime, MaxIdleTime | Out-Host
Write-Host
Write-Host 'Note: If the keys are not displayed then MaxIdleTime and MaxDisconnectionTime is not configured.'
"`n"

Write-Host ================================
Write-Host 2.7.  USER ACCOUNT CONFIGURATION
Write-Host ================================
    Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | 
        Select-Object PSComputerName, Status, Caption, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, PasswordChangeable, PasswordRequired, SID, SIDType | Out-Host
"`n"

Write-Host ==========================
Write-Host 2.7.1.RENAME ADMINITRATOR
Write-Host ==========================
Write-Host 'Note: Below are all users in the administrators group. Check if local administrator account is renamed.' 
Write-Host   
    net localgroup administrators | Out-Host
"`n"

Write-Host ==========================  
Write-Host 2.7.2.GUEST ACCOUNT STATUS
Write-Host ==========================
Write-Host
    net user Guest | Out-Host
"`n"

Write-Host ==========================
Write-Host 2.7.3.PASSWORD REQUIREMENT
Write-Host ==========================
Write-Host
    net accounts | Out-Host
"`n"

Write-Host ======================
Write-Host 2.7.4 DORMANT ACCOUNTS 
Write-Host ======================
Write-Host 'Note: Check for user accounts that have not logged in for the past 90 days.'
Write-Host
    $([ADSI]"WinNT://$env:COMPUTERNAME").Children | where {$_.SchemaClassName -eq 'user'} | Select-Object name, lastlogin | Out-Host
"`n"

#END OF SCRIPT

Write-Host
Write-Host Script execution complete. Please Wait... -ForegroundColor Yellow -BackgroundColor Black
Write-Host
Start-Sleep -s 5
Write-Host Reverting the PowerShell script execution policy to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
    
    Start-Sleep -s 5
    Set-ExecutionPolicy $ExecutionPolicy -force

Write-Host
Write-Host The PowerShell Script Execution Policy setting has been reverted back to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
Write-Host 
Write-Host All done. Have a good day.
Write-Host

#STOP RECORDING TRANSCRIPT
Stop-Transcript