    # script perfroms secruity checks for a build review, including:
    # password policies - done
    # file shares - done
    # weak service permissions - TODO
    # misconfigured anti-virus - done
    # weak passwords in use - TODO
    # outdated 3rd party application - kinda done, gather data for manual review 
    # missing sec updates - done
    # default accoutns in use - INPROGRESS 
    # weak sec policies - TODO
    # weak firewal rules - done


    # temporarily using Write-Host before changing it to a standard formatting table 



# #   helper function to standardise result recording will be implemented later
#     function Add-Result {
#         param (
#             [string]$Category,
#             [string]$Check,
#             [string]$Expected,
#             [string]$Actual,
#             # options for the status 
#             [ValidateSet('Pass','Fail','Not Configured','Error')]
#             [string]$Status
#         )

#         # appent obj to the global result array
#         # the $script command is used for variables that persist across multiple functions 
#             $script:AuditResults += [pscustomobject]@{
#             Category = $Category
#             Check    = $Check
#             Expected = $Expected
#             Actual   = $Actual
#             Status   = $Status
#         }
#     }
#     # function to parse the secedit files for integers key-value pairs using regex
#     # regex is like:
#     # ^\s* start of line, ignore leading spaces
#     # $key exact setting key name 
#     # \s*=\s* ignore spaces around the equal sign
#     # (-?\d+) capture positive or negative integers 
#     function Get-SecEditValue {
#         param (
#             [string[]]$content,
#             [string]$Key
#         )

#         # pattern for start of line and capture the value, see above 
#         $pattern = "^\s*$Key\s*=\s*(-?\d+)"

#         # use Select-String to find the line and extract the value
#         $match = $content | Select-String -Pattern $pattern

#         # if a match is found, return the value as an integer, otherwise return null
#         if ($match) {
#             return [int]$match.Matches.Groups[1].Value
#         } else {
#             return $null
#         }
#     

    # script perfroms secruity checks for a build review, including:
    # password policies - done
    # file shares - done
    # weak service permissions - TODO
    # misconfigured anti-virus - done
    # weak passwords in use - TODO
    # outdated 3rd party application - kinda done, gather data for manual review 
    # missing sec updates - done
    # default accoutns in use - INPROGRESS 
    # weak sec policies - TODO
    # weak firewal rules - done

# Initilise array
$script:AuditResults = @() 

 # function to parse the secedit files for integers key-value pairs using regex
#     # regex is like:
#     # ^\s* start of line, ignore leading spaces
#     # $key exact setting key name 
#     # \s*=\s* ignore spaces around the equal sign
#     # (-?\d+) capture positive or negative integers 
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
function Test-Antivirus {
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

try {
    # Get bits
    $info = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    # [UInt32]$state = $info.productState

    # Check for installed AVs
    if ($null -ne $info) {
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
        $data | Export-Csv data.csv -NoTypeInformation

        # Export results
        Add-Result `
            -Category "Third Party Applications" `
            -Check "Application Inventory" `
            -Expected "Inventory exported for review" `
            -Actual "$($data.Count) applications exported to data.csv" `
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
function Test-Accounts {
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
                -Status $(if ($fire.Enabled -and $fire.DefaultInboundAction -eq 'Block' -and $fire.Enabled) 
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

 password policies ############## 
function Test-PasswordPolicy {
    
    # must be ran buy admin
    if (-not $isAdmin) {
        Write-Host "Script has to be executed as an admin"
        return
    }

    # assume policies passes
    $result = $true
    $wrongSettings = @()
    $policyValues = @()
    
    # recommended values 
    $recommendedSettings = @{
        "ClearTextPassword" = 0
        "MinimumPassword" = 14
        "PasswordComplexity" = 1
        "LockoutBadCount" = 5
        "ResetLockoutCount" = 15
        "LockoutDuration" = 15
    }

    # check device lock policies
    # path found on google 
    $deviceLockPolicyPath = './Device/Vendor/MSFT/Policy/Config/DeviceLock/AccountLockoutPolicy'
    if (Test-Path -PAth $deviceLockPolicyPath) {
        # get all values in the path
        $deviceLockvalues = Get-ItemProperty -Path $deviceLockPolicyPath

        # device passwor 
        if ($deviceLockvalues.DevicePasswordEnabled -eq 0) {
            # get the min pass len if there is any 
            if ($deviceLockvalues.MinDevicePasswordLength) {
                $policyValues['MinimumPassword'] = $deviceLockvalues.MinDevicePasswordLength
            }
             # check complexity
            if ($deviceLockvalues.PasswordComplexity -eq 0) {
                # add to  policy values 
                $policyValues['PasswordComplexity'] = 1
            }       
        } else {
            # if code can't read the device lock settings 
            Write-Host "Error, couldn't read device lock setting"
            continue
        }
    } # if policy is absent 
    else {
        Write-Host "Couldn't read policy as it is absent"
    }

    # compare collected policies values with recommendations 
    if ($policyValues.ClearTextPassword -ne $recommendedSettings.ClearTextPassword) {
        $result = $false
        $wrongSettings += "Added clear text password policy"
    }
    if ($policyValues.MinimumPassword -lt $recommendedSettings.MinimumPassword) {
        $result = $false
        $wrongSettings += "Added clear min password lenth policy" 
    }
    if ($policyValues.PasswordComplexity -lt $recommendedSettings.PasswordComplexity) {
        $result = $false
        $wrongSettings += "Added clear password complexity policy"
    }
    if ($policyValues.LockoutBadCount -gt $recommendedSettings.LockoutBadCount) {
        $result = $false
        $wrongSettings += "Added lockout bad count policy"
    }
    if ($policyValues.ResetLockoutCount -lt $recommendedSettings.ResetLockoutCount) {
        $result = $false
        $wrongSettings += "Added Reset Lockout policy"
    }
    if ($policyValues.LockoutDuration -lt $recommendedSettings.LockoutDuration) {
        $result = $false
        $wrongSettings += "Added lockout duration policy"
    }

}

Test-PasswordPolicy | Format-Table -AutoSize

   # # password policies
    # $passwordPolicyChecks = @(
    #     @{
    #         Key         = "MinimumPasswordLength"
    #         Description = "Minimum Password Length"
    #         Expected    = ">= 14 characters"
    #         Test        = { param($v) $v -ge 14 }
    #     },
    #     @{
    #         Key         = "PasswordComplexity"
    #         Description = "Password Must Meet Complexity Requirements"
    #         Expected    = "1 (Enabled)"
    #         Test        = { param($v) $v -eq 1 }
    #     },
    #     @{
    #         Key         = "MaximumPasswordAge"
    #         Description = "Maximum Password Age"
    #         Expected    = "<= 60 days (and > 0)"
    #         Test        = { param($v) $v -gt 0 -and $v -le 60 }
    #     },
    #     @{
    #         Key         = "LockoutBadCount"
    #         Description = "Account Lockout Threshold"
    #         Expected    = "1 to 5 invalid attempts"
    #         Test        = { param($v) $v -gt 0 -and $v -le 5 }
    #     }
    # )

    # $tempFile = Join-Path $env:TEMP 'PasswordPolicy.txt'

    # try {
    #     # collect data 
    #     #secedit is a windiws tool to analysie security wsettings 
    #     secedit /export /cfg $tempFile /areas SECURITYPOLICY | Out-Null
    #     if ($LASTEXITCODE -ne 0) {
    #         throw "Failed to export security policy. Exit code: $LASTEXITCODE"
    #     }
    #     #read the file content
    #     $content = Get-Content $tempFile -ErrorAction Stop

    #     foreach ($check in $passwordPolicyChecks){
    #         # try catch to avoid one failed check from stopping the whole script
    #         try {
    #             $value = Get-SecEditValue -content $content -Key $check.Key
    #             # is setting present in the export
    #             if ($null -eq $value) {
    #                 Add-Result `
    #                     -Category "Inadequate Password Policies" `
    #                     -Check $check.Description `
    #                     -Expected $check.Expected `
    #                     -Actual "Not Configured" `
    #                     -Status 'Not Configured'
    #             } else {
    #                 $pass = & $check.Test $value
    #                 Add-Result `
    #                     -Category "Inadequate Password Policies" `
    #                     -Check $check.Description `
    #                     -Expected $check.Expected `
    #                     -Actual $value `
    #                     -Status $(if ($pass) { 'Pass' } else { 'Fail' })
    #             }
    #         } # one check failed  
    #         catch {
    #             Add-Result `
    #                 -Category "Inadequate Password Policies" `
    #                 -Check $check.Description `
    #                 -Expected $check.Expected `
    #                 -Actual $_.Exception.Message `
    #                 -Status 'Error'
    #             }
    #         }
    #     } # nothing could be read 
    #     catch {
    #         Add-Result `
    #             -Category "Inadequate Password Policies" `
    #             -Check "Password Policy Check" `
    #             -Expected "N/A" `
    #             -Actual $_.Exception.Message `
    #             -Status 'Error'
    #     } finally {
    #         # clean up the temporary file
    #         if (Test-Path $tempFile) {
    #             Remove-Item $tempFile -Force
    #         }
    #     }

############## file shares ##############   
function Test-fileShares {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch "^(ADMIN\$|IPC\$|C\$|print\$)$"}

        # if there is any shares 
        if ($shares) {
            # loop through and print for manual review 
                foreach($share in $shares){
            Write-Host "Name: $($share.Name)"
            Write-Host "Path: $($share.Path)"
            Write-Host "Description: $($share.Description)"
            }
        } else {
            Write-Host "No non-standard shares were found on the device"
        }
}

Test-fileShares | Format-Table -AutoSize

############## antivuris ##############
function Test-Antivirus {
    # values of states of antivuris
    # real time protection
    [Flags()] enum ProductState 
    {
        Off         = 0x0000
        On          = 0x1000
        Snoozed     = 0x2000
        Expired     = 0x3000
    }

    # is the antivuris up to date
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

    # define bit masks
    [Flags()] enum ProductFlags
    {
        SignatureStatus = 0x00F0
        ProductOwner    = 0x0F00
        ProductState    = 0xF000
    }

    # get bits
    $info = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    # [UInt32]$state = $info.productState

    # check fo rinstalled antivurises 
    if ($null -ne $info) {
        foreach ($i in $info) {
            # check real time protection
            $implementedAV = [ProductState](
                $i.productState -band [ProductFlags]::ProductState
            )
            
            # signature up to date
            $signatureStatus = [SignatureStatus] (
                $i.productState -band [ProductFlags]::SignatureStatus
            )

            # check that antivirus is on and up to date
            if (($implementedAV -eq [ProductState]::On) -and ($signatureStatus -eq [SignatureStatus]::UpToDate)){
                Write-Host "$($i.displayName) is installed, real time protection is $implementedAV, 
                and is $signatureStatus"
                return 
            } # if it fails at finding antovrus 
            else {
                Write-Host "Error in $($i.displayName) is installed but $implementedAV
                and $signatureStatus"
            }
        }
    }
}

Test-Antivirus | Format-Table -AutoSize

############## outdated 3rd party apps ##############
function Test-ThirdPartyApp {
    # first i got to finf the installed apps and their unistall entries in the registry
    # so to exctract app name, install date, etc
    $paths =@(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    # gather datat 
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) {
            foreach ($i in Get-ChildItem -LiteralPath $path -ErrorAction Stop) {
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

    # export to csv for easier manual review
    $app | Export-Csv app.csv -NoTypeInformation
}

Test-ThirdPartyApp | Format-Table -AutoSize

############### check for missing windows updates ###############
function Test-WindowsSecurityUpdates {
    # using built-in PS function that checks for Windows updates using the 
    # built-in Windows update agent
    $session = New-Object -ComObject Microsoft.Update.Session
    $search = $session.CreateUpdateSearcher()

    # find software updates tht are not installed
    $searchresult = $search.Search(
        "IsInstalled=0 and IsHidden=0 and Type='Software'"
    )

    return $searchresult.Updates
}

Test-WindowsSecurityUpdates | Format-Table -AutoSize


############### check for default accounts ###############
# function to identify accounts that should not exist anymore/be disabled
# such as admin, guest, test accounts etc 
function Test-Accounts {
    # standard user ids
    $IDs =@{
        '500' = 'Administrator'
        '501' = 'Guest'
        '503' = 'DefaultAccount'
        '504' = 'UtilityAccount'
    }

    foreach ($user in Get-LocalUser -ErrorAction Stop) {
        # get value if the account SID as txt
        # split txt at each - into parts 
        # select the last part of the result
        $id = ($user.SID.Value -split '-')[-1]

        if ($IDs.ContainsKey($id)) {
            [pscustomobject]@{
                AccountType = $IDs[$id]
                Name = $user.Name
                Enabled = $user.Enabled
                LastLogin = if ($null -ne $user.LastLogon){
                    $user.LastLogon
                } else {
                    $null  
                }
            }
        }
    }
}

 Test-Accounts | Format-Table -AutoSize


############### firewall ###############
function Test-Firewall {

    $firewall = Get-NetFirewallProfile -ErrorAction Stop

    foreach ($fire in $firewall) {
        Write-Host "Profile: $($fire.Name)"
        Write-Host "Enabled: $($fire.Enabled)"
        Write-Host "Actual: $($fire.DefaultInboundAction)"
        Write-Host "Status: $(if ($fire.DefaultInboundAction -eq 'Block') {Pass} else {Fail})"
    }
}

Test-Firewall | Format-Table -AutoSize













############### do not read below ######################

    # exposed file shares
        if ($shares) {
            foreach ($share in $shares) {
                Add-Result `
                -Category "Exposed File Shares" `
                -Description "Custom File Share Discovered ($($share.Name))" `
                -Expected "No non-standard file shares active" `
                -Actual "Share Name: '$($share.Name)' -> Path: '$($share.Path)'" `
                -Passed $false
            }
        } else {
            Add-Result `
            -Category "Exposed File Shares" `
            -Description "Custom SMB File Shares" `
            -Expected "No non-standard file shares active" `
            -Actual "None found" `
            -Passed $true
        }

    # weak service permissions
    $unquotedServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { 
            $_.PathName -and $_.PathName -notlike '"*' -and
            $_.PathName -like '* *' -and$_.PathName -notlike 'C:\Windows\*'
        }

    if ($unquotedServices) {
        foreach ($service in $unquotedServices) {
            Add
        }
    }


























