
#  Build Review Script for cyber passport

#  v0.1 demonstrated on 20/10/2026
# 

############## for v0.1 ##############

    # script perfroms secruity checks for a build review, including:
    # password policies - done
    # file shares - done
    # weak service permissions - done
    # misconfigured anti-virus - done
    # weak passwords in use - done
    # outdated 3rd party application - kinda done, gather data for manual review 
    # missing sec updates - done
    # default accoutns in use - done 
    # weak sec policies - done 
    # these include BitLocker Enabled / USB storage restricted / WDAC config
    # weak firewal rules - done

############## for v1.0 ##############
    
    # disabled ipv6 , ipv4 enabled/preferred done 
    # local admin on syst done 
    # max admin (4) and domain admin, together with above check done
    # laps done
    # multicast network resolution protools enabled? 3 done 
    # nla net lev auth - required done 
    # rdp enabled done
    # lsa prtoection ! enabled done 
    # user acc cont (uac) enabled done 
    # safe dll search mode 
    # always install elevated disabled done
    # smbv1
    # win verified trust enabled
    # open ports PS whats open / whjat shoukd be open / wht shouldn't 
    # microsfot store disabled
    # web filtering -  explit db website check

# Initilise array
$script:AuditResults = @() 

# function to parse the secedit files for integers key-value pairs using regex
# regex is like:
# ^\s* start of line, ignore leading spaces
# $key exact setting key name 
# \s*=\s* ignore spaces around the equal sign
# (-?\d+) capture positive or negative integers 

function Get-SecEditValue {
    param (
        [string[]]$content,
        [string]$Key
    )

    # pattern for start of line and capture the value, see above 
    $pattern = "^\s*$Key\s*=\s*(-?\d+)"

    # use Select-String to find the line and extract the value
    $match = $content | Select-String -Pattern $pattern

    # if a match is found, return the value as an integer, otherwise return null
    if ($match) {
        return [int]$match.Matches.Groups[1].Value
    } else {
        return $null
    }
}

# Helper function to standardise results displaying 
function Add-Result {
    param (
        [string]$Category,
        [string]$Check,
        [string]$Expected,
        [string]$Actual,
        [string]$Status
    )

    # Append obj to the array for printing 
    # $script is usued for variables that persist across mutiple functions

    # Create obj and stor eit in array
    $script:AuditResults += [pscustomobject]@{
        Category = $Category
        Check = $Check
        Expected = $Expected
        Actual = $Actual 
        Status = $Status
    }

    # Print with : $script:AuditREsults | Format ..
}

############## password policies ############## 
function Test-PasswordPolicy {

    # Must be ran by admin
    if (-not $isAdmin) {
        Write-Host "Script has to be executed by an admin"
        return
    }

    $passwordPolicyChecks = @(
        # Check definitions 
        @{
            Key         = "MinimumPasswordLength"
            Description = "Minimum Password Length"
            Expected    = ">= 14 characters"
            Test        = { param($v) $v -ge 14 }
        },
        @{
            Key         = "PasswordComplexity"
            Description = "Password Must Meet Complexity Requirements"
            Expected    = "1 (Enabled)"
            Test        = { param($v) $v -eq 1 }
        },
        @{
            Key         = "MaximumPasswordAge"
            Description = "Maximum Password Age"
            Expected    = "<= 60 days (and > 0)"
            Test        = { param($v) $v -gt 0 -and $v -le 60 }
        },
        @{
            Key         = "LockoutBadCount"
            Description = "Account Lockout Threshold"
            Expected    = "1 to 5 invalid attempts"
            Test        = { param($v) $v -gt 0 -and $v -le 5 }
            # how long locked oout for 
            # how long betweeen resets/attempts 
        },
        @{
            Key         = "ClearTextPassword"
            Description = "Store Passwords Using Reversible Encryption"
            Expected    = "Disabled (0)"
            Test        = { param($v) $v -eq 0 }
        },
        @{
            Key         = "PasswordHistorySize"
            Description = "Password History"
            Expected    = ">= 24"
            Test        = { param($v) $v -ge 24 }
        }
    )

    # Temp file for storing secedit output
    $tempFile = Join-Path $env:TEMP 'PasswordSecedit.txt'

    try {
        # Collect data 
        # secedit is a Windows tool that analysises security settings
        secedit /export /cfg $tempFile /areas SECURITYPOLICY | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to export security policy. Exit code: $LASTEXITCODE"
        }

        # Read file content
        $content = Get-Content $tempFile -ErrorAction Stop

        # Loop through checks
        foreach ($check in $passwordPolicyChecks) {
            # try catch to avoid one failed check from stopping the whole script
            try {
                $value = Get-SecEditValue -content $content -Key $check.Key
                # Is setting present in the export 
                if ($null -eq $value) {
                    Add-Result `
                        -Category "Password Policies" `
                        -Check $check.Description `
                        -Expected $check.Expected `
                        -Actual "Not Configured" `
                        -Status "Not Configured" 
                } else {
                    $pass = & $check.Test $value
                    Add-Result `
                        -Category "Password Policies" `
                        -Check $check.Description `
                        -Expected $check.Expected `
                        -Actual $value `
                        -Status $(if  ($pass) { 'Pass' } else { 'Fail' })
                } # else
            } catch { # If one check fails
                Add-Result `
                -Category "Password Policies" `
                -Check $check.Description `
                -Expected $check.Expected `
                -Actual $_.Exception.Message `
                -Status 'Error'
            }
        } # for each
    } catch { # If nothing could be read 
          Add-Result `
            -Category "Password Policies" `
            -Check "Password Policy Check" `
            -Expected "N/A" `
            -Actual $_.Exception.Message `
            -Status 'Error'
    } finally {
        # clean up the temporary file
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

############## file shares ##############   
# SMBv1 vulns and SMb signing 
function Test-FileShares {
    try {
        $shares = Get-SmbShare -ErrorAction Stop | 
            Where-Object {
                $_.Name -notmatch "^(ADMIN\$|IPC\$|C\$|print\$)$"
            }

            # If there are any shares
            if ($shares) {
                # Loop through and print for manual review
                foreach ($share in $shares) {
 
                Add-Result `
                    -Category "File Shares" `
                    -Check $share.Name `
                    -Expected "Share reviewed and approved" `
                    -Actual $share.Path `
                    -Status "Fail"                   
                }
            } else {
                    
                Add-Result `
                    -Category "File Shares" `
                    -Check "Non-Standard SMB Shares" `
                    -Expected "No non-standard shares present" `
                    -Actual "None Found" `
                    -Status "Pass"                
            }
    } catch { # Error handling 
         Add-Result `
            -Category "File Shares" `
            -Check "SMB Share Enumeration" `
            -Expected "Shares retrieved successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############## antivirus ##############
# Values of states of antivuris
# Real time protection
[Flags()] enum ProductState 
{
    Off         = 0x0000
    On          = 0x1000
    Snoozed     = 0x2000
    Expired     = 0x3000
}

# Is the antivuris up to date
[Flags()] enum SignatureStatus
{
    UpToDate     = 0x00
    OutOfDate    = 0x10
}

# [Flags()] enum ProductOwner
# {
#     NonMs        = 0x000
#     Windows      = 0x100
# }

# Define bit masks
[Flags()] enum ProductFlags
{
    SignatureStatus = 0x00F0
    ProductOwner    = 0x0F00
    ProductState    = 0xF000
}
# AV in sandbox / mic def 
function Test-Antivirus {
try {
    # Get bits
    $info = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    # [UInt32]$state = $info.productState

    # Check for installed AVs
    if ($info) {
        foreach ($i in $info) {
            # Check ral time protection
            $implementedAV = [ProductState](
                $i.productState -band [ProductFlags]::ProductState
            )
            # Signature up to date
            $signatureStatus = [SignatureStatus] (
                $i.productState -band [ProductFlags]::SignatureStatus
            )

            # Check that the antivuris is on and up to date
            if (($implementedAV -eq [ProductState]::On) -and ($signatureStatus -eq [SignatureStatus]::UpToDate)) {
                Add-Result `
                    -Category "Antivirus" `
                    -Check $i.DisplayName `
                    -Expected "Enabled and Up To Date" `
                    -Actual "State: $implementedAV, Signatures: $signatureStatus" `
                    -Status "Pass"
                } else {    
                Add-Result `
                    -Category "Antivirus" `
                    -Check $i.DisplayName `
                    -Expected "Enabled and Up To Date" `
                    -Actual "State: $implementedAV, Signatures: $signatureStatus" `
                    -Status "Fail"                      
                }
        }
    } else { 
         Add-Result `
            -Category "Antivirus" `
            -Check "Installed Antivirus" `
            -Expected "AV installed" `
            -Actual "No AV detected" `
            -Status "Fail"
    }
} catch {
      Add-Result `
        -Category "Antivirus" `
        -Check "AV Enumeration" `
        -Expected "Retrieve AV information" `
        -Actual $_.Exception.Message `
        -Status "Error"

    return
    }
}

############## outdated 3rd party apps ##############
function Test-ThirdPartyApp {
    # First i got to find the installed apps and their unistall entries in the registry
    # so to exctract app name, install date, etc
    $paths =@(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    try {
        # Gather data 
        # data is all applications
        $data = foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) {
                foreach ($i in Get-ChildItem -LiteralPath $path -ErrorAction Stop) {
                    # app is one application
                    $app = Get-ItemProperty -LiteralPath $i.PSPath -ErrorAction Stop

                    if ($app.DisplayName) {
                        [pscustomobject]@{
                            Name = $app.DisplayName
                            Version = $app.DisplayVersion
                            Publisher = $app.Publisher
                            InstallDate = $app.InstallDate
                        }
                    }
                }
            }
        }

        # Export all apps
        $data | Export-Csv ThirdPartyData.csv -NoTypeInformation

        # Export results
        Add-Result `
            -Category "Third Party Applications" `
            -Check "Application Inventory" `
            -Expected "Inventory exported for review" `
            -Actual "$($data.Count) applications exported to ThirdPartyData.csv" `
            -Status "Pass"
    } catch {
         Add-Result `
            -Category "Third Party Applications" `
            -Check "Application Inventory" `
            -Expected "Inventory exported successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### check for missing windows updates ###############
function Test-WindowsSecurityUpdates {
    try {
        # Using built-in PS function that checks for Windows updates using the 
        # built-in Windows update agent
        $session = New-Object -ComObject Microsoft.Update.Session
        $search = $session.CreateUpdateSearcher()

        # find software updates tht are not installed
        $searchresult = $search.Search(
            "IsInstalled=0 and IsHidden=0 and Type='Software'"
        )
        # if no new updates to be done
        if ($searchresult.Updates.Count -eq 0) {
            Add-Result `
                -Category "Windows Updates" `
                -Check "Missing Security Updates" `
                -Expected "No missing updates" `
                -Actual "No pending updates found" `
                -Status "Pass"
        } else { # otherwise 
            # How many updates in general to do
             Add-Result `
                -Category "Windows Updates" `
                -Check "Missing Security Updates" `
                -Expected "No missing updates" `
                -Actual "$($searchResult.Updates.Count) updates pending" `
                -Status "Fail"

            foreach ($update in $searchResult.Updates) {

                # Specific updates required
                Add-Result `
                    -Category "Windows Updates" `
                    -Check $update.Title `
                    -Expected "Installed" `
                    -Actual "Missing" `
                    -Status "Fail" 
            }
        }
    } catch {
        # Error handling 
         Add-Result `
            -Category "Windows Updates" `
            -Check "Update Enumeration" `
            -Expected "Successfully retrieve update status" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### check for default accounts ###############
# function to identify accounts that should not exist anymore/be disabled
# such as admin, guest, test accounts etc 
# LAPS checks add 
function Test-Accounts {
    try { 
        # Standard user IDs
        $IDs =@{
            '500' = 'Administrator'
            '501' = 'Guest'
            '503' = 'DefaultAccount'
            '504' = 'UtilityAccount'
        }

        foreach ($user in Get-LocalUser -ErrorAction Stop) {
            # Get value if the account SID as txt
            # Split txt at each - into parts 
            # Select the last part of the result
            $id = ($user.SID.Value -split '-')[-1]

            if ($IDs.ContainsKey($id)) {
                $accountType = $IDs[$id]

                # Since not all accounts should be disabled, such as Admin, use switrch statement 
                switch ($accountType) {
                    "Administrator" {
                        $expected = "Disabled or Renamed"
                        $status = if ($user.Enabled) { "Fail" } else { "Pass" }
                    } 
                    "Guest" {
                        $expected = "Disabled"
                        $status = if ($user.Enabled) { "Fail" } else { "Pass" }
                    }
                    "DefaultAccount" {
                        $expected = "Disabled"
                        $status = if ($user.Enabled) { "Fail" } else { "Pass" }

                    }
                    "UtilityAccount" {
                        $expected = "Disabled" 
                        $status = if ($user.Enabled) { "Fail" } else { "Pass" }
                    }
                }

                Add-Result `
                    -Category "Accounts" `
                    -Check $accountType `
                    -Expected $expected `
                    -Actual "Name: $($user.Name), Enabled: $($user.Enabled), Last Logon: $($user.LastLogon)" `
                    -Status $status
            }
        }
    } catch {
        Add-Result `
            -Category "Accounts" `
            -Check $accountType `
            -Expected $expected `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
} 

############### firewall ###############
function Test-Firewall {

    try {
        $firewall = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($fire in $firewall) {
             Add-Result `
                -Category "Firewall" `
                -Check "$($fire.Name) Profile" `
                -Expected "Enabled and Default Inbound Action = Block" `
                -Actual "Enabled: $($fire.Enabled), Inbound: $($fire.DefaultInboundAction)" `
                -Status $(if ($fire.Enabled -and $fire.DefaultInboundAction -ne 'Allow') 
                { 'Pass' } else { 'Fail' })
        }
    } catch {
       Add-Result `
            -Category "Firewall" `
            -Check "Firewall Enumeration" `
            -Expected "Firewall configuration retrieved successfully" `
            -Actual $_.Exception.Message `
            -Status "Error" 
    }
}

############### weak service permission ###############
# Usually this includes: unquoted service paths 
# (Windows service’s ImagePath registry value contains spaces but is not enclosed in quote)
# Writable service binaries
# the ImagePAth file/folder is writable by low-level users
# Writable service directories 
# Services running as Local System
function Test-UnquotedPaths {
    # Find services 
    try {
        # No findings for now
        $findings = 0 

        $services = Get-CimInstance Win32_Service -ErrorAction Stop

        foreach ($service in $services) {
            # Path for every service
            $path = $service.PathName

            # Does path contain spaces?/isquoted
            if ( $path -match '\s' -and 
                $path -notmatch '^".*"' -and
                $path -notmatch 'system32') {

                    $findings ++ 

                    Add-Result `
                        -Category "Service Permissions" `
                        -Check $service.Name `
                        -Expected "Quoted service path" `
                        -Actual $path `
                        -Status "Fail"
                }
        } 
            if ($findings -eq 0) {
                    Add-Result `
                        -Category "Service Permissions" `
                        -Check "Unquoted Service Paths" `
                        -Expected "No vulnerable services found" `
                        -Actual "None Found" `
                        -Status "Pass"
                }
    } catch {
        Add-Result `
            -Category "Service Permissions" `
            -Check "Service Enumeration" `
            -Expected "Services enumerated successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

function Test-WeakServices {
    try {
        $findings = 0

        $services = Get-CimInstance Win32_Service -ErrorAction Stop

        foreach ($service in $services) {
             # Remove quotes etc so that PS can read it 
             $path = $service.PathName

             # Skip empty paths
             if (-not $path) {
                continue 
             }
             # Remove opening and closing quotes
             $exePath = $path -replace '^"', ''
             $exePath = $exePath -replace '".*$', ''

             if (-not (Test-Path $exePath)) {
                continue
             }

             # ACL = Access Control List
             $acl = Get-Acl $exePath

             $permission = $acl.Access | Where-Object {
                # Check who has what permissions
                 $_.IdentityReference -match 'Users|Everyone|Authenticated Users' -and
                (
                    $_.FileSystemRights.ToString() -match 'Write' -or
                    $_.FileSystemRights.ToString() -match 'Modify' -or
                    $_.FileSystemRights.ToString() -match 'FullControl'
                )
             }

             if ($permission) {
                $findings ++ 
                 Add-Result `
                    -Category "Service Permissions" `
                    -Check $service.Name `
                    -Expected "Service executable not writable by standard users" `
                    -Actual $exePath `
                    -Status "Fail"
             }
        }

         if ($findings -eq 0) {

            Add-Result `
                -Category "Service Permissions" `
                -Check "Weak Service Permissions" `
                -Expected "No writable service executables" `
                -Actual "None Found" `
                -Status "Pass"
        }
    } catch {
        Add-Result `
            -Category "Service Permissions" `
            -Check "Service Permission Enumeration" `
            -Expected "Services analysed successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### weak passwords in use ###############
# Looking for: password doesn't expire
# password not required / dormant accounts
# never used accounts / enabled accounts unactie for 60 days 
function Test-WeakPasswords {
    try {

        # Initialise variables 
        $findings = 0
        $dormantDays = 60

        foreach ($user in Get-LocalUser -ErrorAction Stop) {
            # Check password never expires 
            if ($user.PasswordNeverExpires) {
                $findings ++

                 Add-Result `
                    -Category "Account Hygiene" `
                    -Check $user.Name `
                    -Expected "Password expires according to policy" `
                    -Actual "PasswordNeverExpires = True" `
                    -Status "Fail"
            }

            # Is password required?
            if (-not $user.PasswordRequired) {
                $findings ++

                Add-Result `
                    -Category "Account Hygiene" `
                    -Check $user.Name `
                    -Expected "Password required" `
                    -Actual "PasswordRequired = False" `
                    -Status "Fail"
             }

             # Is the account enaled and whenh was the last successful login / never logged on
            if ($user.Enabled -and -not $user.LastLogon) {
                $findings ++

                 Add-Result `
                    -Category "Account Hygiene" `
                    -Check $user.Name `
                    -Expected "Account reviewed and used" `
                    -Actual "Enabled account has never logged on" `
                    -Status "Fail"
            }

            # Check for enabled accoutns that have not logged on in 60 days
            if ($user.Enabled -and $user.LastLogon -and $user.LastLogon -lt (Get-Date).AddDays(-$dormantDays)) {
                $findings ++

                Add-Result `
                    -Category "Account Hygiene" `
                    -Check $user.Name `
                    -Expected "Account active within last 90 days" `
                    -Actual "Last logon: $($user.LastLogon)" `
                    -Status "Fail"
            }
        }

        # If no issue found 
        if ($findings -eq 0) {

            Add-Result `
                -Category "Account Hygiene" `
                -Check "Local Accounts" `
                -Expected "No weak account configurations found" `
                -Actual "None Found" `
                -Status "Pass"
        }
    } catch {
        Add-Result `
            -Category "Account Hygiene" `
            -Check "Account Enumeration" `
            -Expected "Accounts retrieved successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### weak security policies ###############
# USB storage restricted - sys prevents users from connecting and Using USB storage unless explicity authorised
# BitLocker enabled - encrypt entire drives to protect data from unauthorised access
# WDAC configured - Windows Defender Application Control enforces rule at OS layer and has allowlist for trusted publichers,c ode signatures, file hashes etc  

## check this all again pleaseeee 
function Test-USBPolicy {
    # Check USB storage policy
    try {
        $usb = Get-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" `
            -Name Start `
            -ErrorAction Stop

            # Disabled USB storage with start at value 4 and start value 3 for enabling it
        Add-Result `
            -Category "Security Hardening" `
            -Check "USB Storage" `
            -Expected "Disabled (Start = 4)" `
            -Actual "Start = $($usb.Start)" `
            -Status $(if ($usb.Start -eq 4) { "Pass" } else { "Fail" })

    } catch {
         Add-Result `
            -Category "Security Hardening" `
            -Check "USB Storage" `
            -Expected "Configuration available" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}
# 

# Check BitLocker settings
function Test-BitLocker {
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop

        foreach ($volume in $volumes) {

            Add-Result `
                -Category "Security Hardening" `
                -Check "BitLocker ($($volume.MountPoint))" `
                -Expected "Protection Enabled" `
                -Actual "Protection Status: $($volume.ProtectionStatus)" `
                -Status $(if ($volume.ProtectionStatus -eq 'On') { "Pass" } else { "Fail" })
        }
    } catch {
         Add-Result `
            -Category "Security Hardening" `
            -Check "BitLocker" `
            -Expected "Volumes retrieved successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

# Check WDAC
# Policies folder C:\Windows\System32\CodeIntegrity\CIPolicies\Active
function Test-WDAC {
    try {
        $wdacPolicy = @(Get-ChildItem `
            -Path "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\" `
            -Filter "*.cip" `
            -ErrorAction SilentlyContinue)

        # Double check there is the WDAC policy
        if ($wdacPolicy -gt 0) {

            Add-Result `
                -Category "Security Policies" `
                -Check "WDAC Configuration" `
                -Expected "WDAC policy present" `
                -Actual "$($wdacPolicy.Count) policy file(s) found" `
                -Status  if $($)"Pass"
        } else {
            Add-Result `
                -Category "Security Policies" `
                -Check "WDAC Configuration" `
                -Expected "WDAC policy present" `
                -Actual "No active policies found" `
                -Status "Fail"
        }
    }
    catch {

         Add-Result `
            -Category "Security Policies" `
            -Check "WDAC Configuration" `
            -Expected "WDAC policy present" `
            -Actual "No active WDAC policies found" `
            -Status "Fail"
    }
}

############### IPv6 disabled and IPv4 enabled ###############
function Test-IPprotocol {
    try {

        # Check IP configuration 
        $disabledComponents = Get-ItemPropertyValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
            -Name DisabledComponents `
            -ErrorAction SilentlyContinue
        
        # Check if IPv4 is enabled
        # Show what protocols are bound to network adapters
        # ms_tcpip = ipv4 
        # if any adapters are using IPv4 then it is set to true 
        $IPv4enabled = ( Get-NetAdapterBinding ` -ComponentID ms_tcpip).Enabled -contains $true
        # Check if IPv4/6 are disabled/preferred
        # 0xFF is 255 in decimal - this disables IPv6 in the system
        $IPv6disabled = ($disabledComponents -eq 0xFF)
        # 0x20 is 32 in decimals - also means to prefer the IPv4 over IPV6
        $IPv4preferred = ($disabledComponents -eq 0x20)
        
        # Check whether IPv4 is enabled and/or Ipv6 disabled/IPv4 preferred 
        Add-Result `
            -Category "Security Hardening" `
            -Check "IP Protocol Configuration" `
            -Expected "IPv4 enabled, IPv6 disabled or IPv4 preferred" `
            -Actual "IPv4 Enabled: $ipv4Enabled, DisabledComponents: $disabledComponents" `
            -Status $(if ($ipv4Enabled -and ($ipv6Disabled -or $ipv4Preferred)) { "Pass" } else { "Fail" })

    } catch {
        Add-Result `
            -Category "Security Hardening" `
            -Check "IP Protocol Configuration" `
            -Expected "Protocol settings retrievable" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### Local admin on system ###############
# and check there is max 4 admins on system
function Test-LocalAdmin {
    try {
        # Get all of approved memebers
        $ApprovedMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

        # Loop through them alland add them to the csv 
        foreach ($member in $ApprovedMembers) {
            Add-Result `
                -Category "Privileged Access" `
                -Check "Local Admin Membership" `
                -Expected "Only authorised members" `
                -Actual $member.Name `
                -Status "Manual Review"
        }
        
        # Check how many admins there are 
        Add-Result `
            -Category "Privileged Access" `
            -Check "Local Admin count" `
            -Expected "Not more than 4 admins" `
            -Actual "$($ApprovedMembers.Count) Administrators" `
            -Status $(if ($ApprovedMembers.Count -le 4) { "Pass" } else { "Fail" })

    } catch {
        Add-Result `
            -Category "Privileged Access" `
            -Check "Local Administrator Enumeration" `
            -Expected "Administrators group retrieved successfully" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### LAPS (Local Admin Pasword Solutions) ###############
function Test-Laps {
    try {
        # Gather Laps data
        $laps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction Stop

        # Properties to pass checks 
        $pass = ($laps.BackupDirectory -ge 1 -and
                $laps.PasswordLength -gt 12 -and
                $laps.PasswordAgeDays -le 30
        )

        # If there is no path 
        if ($null -eq $path) {
            Write-Host "LAPS Path was not found"
            Add-Result `
                -Category "Privileged Access" `
                -Check "LAPS implementation" `
                -Expected "Configured and Enabled" `
                -Actual "Device not AD/AzureAD joined - LAPS not applicable" `
                -Status "Fail"
        } else {
            # Print results and check if the configurations pass the checks 
            Add-Result `
                -Category "Privileged Access" `
                -Check "LAPS implementation" `
                -Expected "Configured and enabled" `
                -Actual "Account = $($laps.AdminstratorAccountName), password length = $($laps.PasswordLength),
                        password age = $($laps.PasswordAgeDays)"
                -Status $(if ($pass) { "Pass" } else { "Fail" })
        } 

        } catch {
            # Error handlig 
            Write-Host "Error laps"
            Write-Host $_.Exception.Message

            Add-Result `
                -Category "Privileged Access" `
                -Check "Windows LAPS" `
                -Expected "Configured and enabled" `
                -Actual "LAPS policy not configured" `
                -Status "Fail"
    }
}

############### Multicast name resolution enabled ###############
# 0 = Disabled and 1 = Enabled Missing = Not Configured 
function Test-NameResolution {
    try {
        # Path where the settings and configuration for this check should be 
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

        # Check if the path exist as it does not exist on my machine 
        if (-not (Test-Path $path)) {
            Add-Result `
                -Category "Security Hardening" `
                -Check "Multicast Name Resolution" `
                -Expected "Disabled" `
                -Actual "No DNSClient path exists" `
                -Status "Review"
            return
        }

        continue 

        # If path exists
        # Retrieve data 
        $config = Get-ItemPropertyValue `
            -Path $path `
            -ErrorAction SilentlyContinue

            # Add result 
            Add-Result `
                -Category "Security Hardening" `
                -Check "Multicast Name Resolution" `
                -Expected "Disabled (0)" `
                -Actual "$config" `
                -Status $(if ($config -eq 0) { "Pass" } else { "Fail" })
    } catch {
           Add-Result `
                -Category "Security Hardening" `
                -Check "LLMNR" `
                -Expected "Configuration retrievable" `
                -Actual $_.Exception.Message `
                -Status "Error" 
    }
}

############### Network Level Authentication (NLA) ###############
# It is required, and when enabled it has value of 1 
# in: HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
function Test-NLA {
    try {
        # Path to settings 
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

        # Variable gathering 
        $nla = Get-ItemPropertyValue `
            -Path $path `
            -Name userAuthentication `
            -ErrorAction Stop
        
        # Add result 
        Add-Result `
            -Category "Remote Access" `
            -Check "Netowrk Level Authentication" `
            -Expected "Enabled (1)" `
            -Actual "userAuthentication = $nla" `
            -Status $(if ($nla -eq 1) { "Pass" } else { "Fail" })       
    } catch {
        Add-Result `
            -Category "Remote Access" `
            -Check "Network Level Authentication" `
            -Expected "Configuration retrievable" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### Remot Desktop Protocol ###############
# Needs to be enabled = 0 
# I disabled = 1 
# -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
function Test-RDP {
    try {
        # Path to configurations 
        $path = "HKLM:\System\CurrentControlSet\Control\Terminal Server"

        # Variable gathering 
        $rdp = Get-ItemPropertyValue `
            -Path $path `
            -Name fDenyTSConnections `
            -ErrorAction Stop
        
        # Add to standardised output format     
        Add-Result `
            -Category "Remote Access" `
            -Check "Remote Desktop Protocol" `
            -Expected "Enabled (0)" `
            -Actual "fDenyTSConnections = $rdp" `
            -Status $(if ($nla -eq 0) { "Pass" } else { "Fail"} )
    } catch {
        Add-Result `
            -Category "Remote Access" `
            -Check "Remote Desktop Protocol" `
            -Expected "Configuration retrievable" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### Local Security Authority (LSA) ###############
# should be enabled = 1 
# disabled = 0
function Test-LSA {
    try {
        # Get path and variable value from settings 
        $path = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $lsa = Get-ItemPropertyValue `
            -Path $path `
            -Name RunAsPPL `
            -ErrorAction Stop
        
        # If it is equal to null / doesn't exist then throw an error
        if ($null -eq $lsa) {
            Add-Result `
                -Category "Security Hardening" `
                -Check "Local Security Authority" `
                -Expected "Enabled (1)" `
                -Actual "LSA not existent on system" `
                -Status "Error"
        }    

        # Otherwise display configuration 
        Add-Result `
            -Category "Security Hardening" `
            -Check "Local Security Authority" `
            -Expected "Enabled (1)" `
            -Actual "RunAsPPL = $lsa" `
            -Status $(if ($lsa -eq 0) { "Pass" }  else { "Fail" })
    } catch {
         Add-Result `
            -Category "Security Hardening" `
            -Check "Local Security Authority" `
            -Expected "Enabled (1)" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### User Account Control (UAC) ###############
# Function that asks for permission before any chamges are done to the device
# Enabled = 1
# Disabled = 0 
function Test-UAC {
    try {
        # Get path and varibale from settings 
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uac = Get-ItemPropertyValue `
            -Path $path `
            -Name EnableLUA `
            -ErrorAction Stop
        
        if (-not (Test-Path $path)) {
            Add-Result `
                -Category "Security Hardening" `
                -Check "User Account Control" `
                -Expected "Disabled (0)" `
                -Actual "Not Configured" `
                -Status "Pass"

            return 
        }

        # Display results 
         Add-Result `
            -Category "Security Hardening" `
            -Check "User Account Control" `
            -Expected "Enabled (1)" `
            -Actual "EnableLUA = $uac" `
            -Status $(if ($uac -eq 1) { "Pass" }  else { "Fail" })
    } catch {
        Add-Result `
            -Category "Security Hardening" `
            -Check "User Account Control" `
            -Expected "Enabled (1)" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### Safe DLL Search ###############
# Enabled =1 and Disabled = 0 
function Test-SafeDLLSearch {
    try {
        # Gather path and variable
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $dll = Get-ItemProperty `
            -Path $path `
            -Name SafeDllSearchMode `
            -ErrorAction Stop
        
        $valid = $dll.SafeDllSearchMode    
        
        # check if it exists     
        if ($null -eq $valid) {
            Add-Result `
            -Category "Security Hardening" `
            -Check "Safe DLL Search" `
            -Expected "Enabled (1)" `
            -Actual "Not Configured" `
            -Status "Error"
        } 

        # Display results 
        Add-Result `
            -Category "Security Hardening" `
            -Check "Safe DLL Search" `
            -Expected "Enabled (1)" `
            -Actual "SafeDllSearchMode = $dll" `
            -Status $(if ($dll -eq 1) { "Pass" } else { "Fail" })

    } catch {
        Add-Result `
            -Category "Security Hardening" `
            -Check "Safe DLL Search" `
            -Expected "Enabled (1)" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}


############### Always Install Elevated ###############
# Function that if enabled a standard user can execute installs with SYSTEM privileged
# This leads to privilege escalation aas code can be executed as NT AUTHORITY/SYSTEM - higher level of privilege on system 
# Should be disabled = 0
function Test-AlwaysInstallElevated {
    try {
        # Path in system
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

        # Variable requried 
        $alwaysInstall = Get-ItemPropertyValue `
            -Path $path `
            -Name AlwaysInstallElevated `
            -ErrorAction Stop
        
        # If the variable is missing 
        if ($null -eq $alwaysInstall) {
            Add-Result `
                -Category "Security Hardening" `
                -Check "Always Install Elevated" `
                -Expected "Disabled (0)" `
                -Actual "Always Install Elevated was not configured" `
                -Status "Error"
        } 
        continue 

        # If the variable is not missing 
        Add-Result `
            -Category "Security Hardening" `
            -Check "Always Install Elevated" `
            -Expected "Disabled (0)" `
            -Actual "AlwaysInstallElevated = $alwaysInstall" `
            -Status $(if ($alwaysInstall -eq 0) { "Pass" } else { "Fail" })
        
    } catch {
        Add-Result `
            -Category "Security Hardening" `
            -Check "Always Install Elevated" `
            -Expected "Disabled (0)" `
            -Actual $_.Exception.Message `
            -Status "Error"
    }
}

############### SMBv1 ###############
# Should be disabled so to reduce the risk of exposure to ransomware/malware and MIM attacks 
# Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
function Test-SMBv1 {
    try {

        # Gather the data needed 
        $smb = Get-WindowsOptionalFeature `
            -Online `
            -FeatureName SMB1Protocol `
            -ErrorAction SilentlyContinue

        # Check that the state variable is set to Disabled 
        # If it is not equal to Disabled
        if ($smb.State -ne "Disabled") {
            Add-Result `
                -Category "Security Hardening" `
                -Check "SMBv1" `
                -Expected "Disabled" `
                -Actual "SMBv1 = $smb" `
                -Status "Fail"
        } 
        if ($smb.State -eq "Disabled") {
            # If it is set to Disabled
             Add-Result `
                -Category "Security Hardening" `
                -Check "SMBv1" `
                -Expected "Disabled" `
                -Actual "SMBv1 = $smb" `
                -Status "Pass"
        }
    } catch {
         Add-Result `
                -Category "Security Hardening" `
                -Check "SMBv1" `
                -Expected "Disabled" `
                -Actual  $_.Exception.Message `
                -Status "Fail"
    }
}

############### Windows Verified Trust ###############
# function Test-WinVerTrust {
#     try {

#      #  $wintrust = 
#     } catch {

#     }
# }

############### Microsfot Store Disabled ###############
function Test-MicrosoftStore {
    # Path that found policy on my own machine 
    $path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"

    # Check path exists
    if (Test-Path $path) {
        # Get data
        $store =Get-ItemProperty $path

        # Check that the store option 
        $pass = $store.RemoveWindowsStore -eq 1
        
        Add-Result `
            -Category "Application Control" `
            -Check "Microsoft Store DIsabled" `
            -Expected "Disabled (1)" `
            -Actual "RemoveWindowsStore = $($store.RemoveWindowsStore)" `
            -Status $(if($pass) { "Pass" } else { "Fail"} )
    }

    Add-Result `
        -Category "Application Control" `
        -Check "Microsoft Store Disabled" `
        -Expected "Disabled" `
        -Actual "Policy not configured" `
        -Status "Fail"

}


############### Web Filtering ###############
###############  ###############

    # win verified trust enabled
    # open ports PS whats open / whjat shoukd be open / wht shouldn't 
    # microsfot store disabled
    # web filtering -  explit db website check

# Run the checks
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Test-PasswordPolicy
Test-FileShares
Test-Antivirus
Test-ThirdPartyApp
Test-WindowsSecurityUpdates
Test-Accounts
Test-Firewall
Test-UnquotedPaths
Test-WeakServices
Test-WeakPasswords
Test-USBPolicy
Test-BitLocker
Test-WDAC
Test-IPprotocol
Test-LocalAdmin
Test-LAPS
Test-NameResolution
Test-NLA
Test-RDP
Test-LSA
Test-UAC
Test-SafeDLLSearch
Test-AlwaysInstallElevated
Test-SMBv1
Test-MicrosoftStore 


$script:AuditResults | Format-Table -AutoSize -Wrap 
$script:AuditResults | Export-Csv (Join-Path $PSScriptRoot 'BuildReviewResults.csv') -NoTypeInformation