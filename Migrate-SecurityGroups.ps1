param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$true)]
    [string]$SourceDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$SourceDC,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetDC,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetOU,
    
    [Parameter()]
    [switch]$TestMode = $false
)

# Import required modules
Import-Module ActiveDirectory

function Write-Log {
    param($Message, $Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Type : $Message"
}

function Get-GroupNameFromIdentity {
    param([string]$Identity)
    if ($Identity -match '^(.+)\\(.+)$') {
        return $matches[2]
    }
    return $Identity
}

function Get-DomainCredentials {
    param(
        [string]$DomainName,
        [string]$Purpose
    )
    
    Write-Host "`nEnter credentials for $Purpose domain: $DomainName" -ForegroundColor Cyan
    $credential = Get-Credential -Message "Enter credentials for $DomainName" -UserName "$DomainName\"
    
    if ($null -eq $credential) {
        throw "No credentials provided for $DomainName"
    }
    
    return $credential
}

function Process-PermissionString {
    param(
        [string]$PermissionString,
        [string]$PermissionType,
        [System.Collections.Generic.HashSet[string]]$UniqueGroups,
        [System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]]$GroupPurposes,
        [string]$SourceDC,
        [System.Management.Automation.PSCredential]$SourceCredential,
        [string]$TargetDC,
        [System.Management.Automation.PSCredential]$TargetCredential
    )
    
    if ([string]::IsNullOrWhiteSpace($PermissionString)) {
        return
    }

    Write-Log "Processing $PermissionType permissions: $PermissionString" "DEBUG"
    
    # Split by comma and trim each entry
    $securityObjects = $PermissionString -split ',' | ForEach-Object { $_.Trim() }
    Write-Log "Split into objects: $($securityObjects -join ' | ')" "DEBUG"
    
    foreach ($secObj in $securityObjects) {
        Write-Log "Processing security object: $secObj" "DEBUG"
        
        # Skip empty entries
        if ([string]::IsNullOrWhiteSpace($secObj)) {
            continue
        }
        
        # Skip built-in accounts, SIDs, and system groups
        if ($secObj -like "NT AUTHORITY\*" -or 
            $secObj -like "BUILTIN\*" -or 
            $secObj -eq "Administrators" -or 
            $secObj -eq "Users" -or 
            $secObj -eq "Everyone" -or
            $secObj -match "S-\d-\d+-(\d+-){1,14}\d+") {
            Write-Log "Skipping built-in/system object: $secObj" "DEBUG"
            continue
        }

        $objName = Get-GroupNameFromIdentity $secObj

        try {
            # First try to get as group
            $sourceObject = Get-ADGroup -Identity $objName -Server $SourceDC -Credential $SourceCredential -ErrorAction Stop
            Write-Log "Found as group in source: $objName" "DEBUG"
            
            # If it's a group, add to our collection for processing
            if ($UniqueGroups.Add($objName)) {
                Write-Log "Added new unique group: $objName" "DEBUG"
                $GroupPurposes[$objName] = [System.Collections.Generic.HashSet[string]]::new()
            }
            $GroupPurposes[$objName].Add($PermissionType) | Out-Null
        }
        catch {
            try {
                # If not a group, try as user
                $sourceUser = Get-ADUser -Identity $objName -Server $SourceDC -Credential $SourceCredential -ErrorAction Stop
                Write-Log "Found as user in source: $objName" "DEBUG"
                
                # Check if user exists in target
                try {
                    $targetUser = Get-ADUser -Identity $objName -Server $TargetDC -Credential $TargetCredential -ErrorAction Stop
                    Write-Log "User $objName exists in target domain" "DEBUG"
                }
                catch {
                    Write-Log "User $objName not found in target domain - skipping" "DEBUG"
                }
            }
            catch {
                Write-Log "Object $objName not found as user or group in source domain" "WARN"
            }
        }
    }
}

function Process-SecurityGroups {
    try {
        # Collect credentials
        Write-Host "`nCredential Collection" -ForegroundColor Green
        Write-Host "===================="
        $sourceCredential = Get-DomainCredentials -DomainName $SourceDomain -Purpose "source (read)"
        $targetCredential = Get-DomainCredentials -DomainName $TargetDomain -Purpose "target (read/write)"

        # Test Mode Safety Check
        if ($TestMode) {
            Write-Host "`n=== TEST MODE ENABLED ===" -ForegroundColor Yellow
            Write-Host "No changes will be written to Active Directory" -ForegroundColor Yellow
            Write-Host "This is a simulation only`n" -ForegroundColor Yellow
            
            # Override potentially dangerous cmdlets
            function Script:New-ADGroup { 
                Write-Log "TEST MODE: Would create new AD group with parameters: $($args | ConvertTo-Json)" "TEST"
            }
            function Script:Add-ADGroupMember { 
                Write-Log "TEST MODE: Would add member to AD group with parameters: $($args | ConvertTo-Json)" "TEST"
            }
            function Script:Set-ADGroup { 
                Write-Log "TEST MODE: Would modify AD group with parameters: $($args | ConvertTo-Json)" "TEST"
            }
        }

        # Verify CSV exists
        if (!(Test-Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }

        # Import CSV with tab delimiter
        $permissions = Import-Csv -Path $CsvPath -Delimiter "`t"
        Write-Log "Imported CSV file successfully"
        Write-Log "Headers found: $($permissions[0].PSObject.Properties.Name -join ', ')" "DEBUG"
        Write-Log "Total rows: $($permissions.Count)" "DEBUG"

        # Verify target OU exists
        try {
            $ou = Get-ADOrganizationalUnit -Identity $TargetOU -Server $TargetDC -Credential $targetCredential
            Write-Log "Successfully verified target OU: $TargetOU"
        }
        catch {
            throw "Target OU not found or inaccessible: $TargetOU"
        }

        # Use HashSet for optimal duplicate handling
        $uniqueGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $groupPurposes = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]]::new([StringComparer]::OrdinalIgnoreCase)
        $missingUsers = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]]::new([StringComparer]::OrdinalIgnoreCase)

        # Process permissions
        $processedCount = 0
        $totalEntries = $permissions.Count

        foreach ($entry in $permissions) {
            $processedCount++
            Write-Progress -Activity "Processing Permissions" -Status "$processedCount of $totalEntries" -PercentComplete (($processedCount / $totalEntries) * 100)

            Process-PermissionString -PermissionString $entry.Read -PermissionType "Read" -UniqueGroups $uniqueGroups -GroupPurposes $groupPurposes `
                -SourceDC $SourceDC -SourceCredential $sourceCredential -TargetDC $TargetDC -TargetCredential $targetCredential
            Process-PermissionString -PermissionString $entry.Write -PermissionType "Write" -UniqueGroups $uniqueGroups -GroupPurposes $groupPurposes `
                -SourceDC $SourceDC -SourceCredential $sourceCredential -TargetDC $TargetDC -TargetCredential $targetCredential
            Process-PermissionString -PermissionString $entry.Deny -PermissionType "Deny" -UniqueGroups $uniqueGroups -GroupPurposes $groupPurposes `
                -SourceDC $SourceDC -SourceCredential $sourceCredential -TargetDC $TargetDC -TargetCredential $targetCredential
        }
        Write-Progress -Activity "Processing Permissions" -Completed

        Write-Log "Found $($uniqueGroups.Count) unique security groups to process"
        
        # Generate summary report before processing
        $summaryReport = @()
        foreach ($groupName in $uniqueGroups) {
            $purposes = $groupPurposes[$groupName] -join ", "
            $summaryReport += [PSCustomObject]@{
                GroupName = $groupName
                Purposes = $purposes
            }
        }

        # Display and export summary
        Write-Host "`nGroup Summary Report:" -ForegroundColor Green
        $summaryReport | Format-Table -AutoSize
        $summaryPath = Join-Path $PWD "GroupSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $summaryReport | Export-Csv -Path $summaryPath -NoTypeInformation
        Write-Log "Summary report exported to: $summaryPath"

        # Process each group
        foreach ($groupName in $uniqueGroups) {
            $purposes = $groupPurposes[$groupName] -join ", "
            Write-Log "Processing group: $groupName (Purposes: $purposes)"
            
            try {
                # Get source group and its members
                $sourceGroup = Get-ADGroup -Identity $groupName -Server $SourceDC -Credential $sourceCredential
                $sourceMembers = Get-ADGroupMember -Identity $sourceGroup -Server $SourceDC -Credential $sourceCredential
                
                # Check if group exists in target
                $targetGroup = $null
                try {
                    $targetGroup = Get-ADGroup -Identity $groupName -Server $TargetDC -Credential $targetCredential
                    Write-Log "Group already exists in target domain: $groupName" "WARN"
                }
                catch {
                    if (!$TestMode) {
                        $description = "Migrated group - Original Purposes: $purposes"
                        $targetGroup = New-ADGroup -Name $groupName `
                            -GroupScope Global `
                            -GroupCategory Security `
                            -Description $description `
                            -Path $TargetOU `
                            -Server $TargetDC `
                            -Credential $targetCredential
                        Write-Log "Created group in target domain: $groupName"
                    }
                    else {
                        Write-Log "Test Mode: Would create group: $groupName (Purposes: $purposes)" "TEST"
                    }
                }

                # Process members
                if (!$TestMode -and $targetGroup) {
                    $processedUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    
                    Write-Log "Getting members of source group $groupName" "DEBUG"
                    $sourceMembers = Get-ADGroupMember -Identity $groupName -Server $SourceDC -Credential $sourceCredential
                    Write-Log "Found $($sourceMembers.Count) members in source group" "DEBUG"
                    
                    foreach ($member in $sourceMembers) {
                        Write-Log "Processing member: $($member.SamAccountName)" "DEBUG"
                        if ($processedUsers.Add($member.SamAccountName)) {
                            try {
                                Write-Log "Looking for user $($member.SamAccountName) in target domain" "DEBUG"
                                $targetUser = Get-ADUser -Identity $member.SamAccountName `
                                    -Server $TargetDC `
                                    -Credential $targetCredential
                                
                                Write-Log "Found user in target domain, adding to group" "DEBUG"
                                Add-ADGroupMember -Identity $groupName `
                                    -Members $targetUser `
                                    -Server $TargetDC `
                                    -Credential $targetCredential
                                
                                Write-Log "Successfully added user $($member.SamAccountName) to group $groupName"
                            }
                            catch {
                                Write-Log "Error details: $_" "DEBUG"
                                if (!$missingUsers.ContainsKey($groupName)) {
                                    $missingUsers[$groupName] = [System.Collections.Generic.HashSet[string]]::new()
                                }
                                $missingUsers[$groupName].Add($member.SamAccountName) | Out-Null
                                Write-Log "User $($member.SamAccountName) not found in target domain - skipping" "WARN"
                            }
                        }
                    }
                }
                elseif ($TestMode) {
                    foreach ($member in $sourceMembers) {
                        try {
                            $targetUser = Get-ADUser -Identity $member.SamAccountName `
                                -Server $TargetDC `
                                -Credential $targetCredential
                            
                            Write-Log "Test Mode: Would add user $($member.SamAccountName) to group $groupName" "TEST"
                        }
                        catch {
                            if (!$missingUsers.ContainsKey($groupName)) {
                                $missingUsers[$groupName] = [System.Collections.Generic.HashSet[string]]::new()
                            }
                            $missingUsers[$groupName].Add($member.SamAccountName) | Out-Null
                            Write-Log "Test Mode: User $($member.SamAccountName) not found in target domain - would be skipped" "TEST"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error processing group $groupName : $_" "ERROR"
            }
        }

        # Generate missing users report
        if ($missingUsers.Count -gt 0) {
            Write-Host "`nMissing Users Report:" -ForegroundColor Yellow
            Write-Host "=====================`n"
            
            $missingUsersReport = @()
            foreach ($group in $missingUsers.Keys) {
                foreach ($user in $missingUsers[$group]) {
                    $missingUsersReport += [PSCustomObject]@{
                        GroupName = $group
                        MissingUser = $user
                        GroupPurposes = ($groupPurposes[$group] -join ", ")
                    }
                }
            }
            
            $missingUsersReport | Format-Table -AutoSize
            
            # Export missing users report
            $missingUsersPath = Join-Path $PWD "MissingUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $missingUsersReport | Export-Csv -Path $missingUsersPath -NoTypeInformation
            Write-Log "Missing users report exported to: $missingUsersPath"
            
            # Summary statistics
            $totalMissingUsers = ($missingUsersReport | Select-Object -Unique MissingUser).Count
            $totalAffectedGroups = $missingUsers.Count
            
            Write-Host "`nSummary:" -ForegroundColor Yellow
            Write-Host "- Total unique missing users: $totalMissingUsers"
            Write-Host "- Total affected groups: $totalAffectedGroups"
            Write-Host "- Full details available in: $missingUsersPath`n"
        }
        else {
            Write-Host "`nAll users found in target directory" -ForegroundColor Green
        }

                if ($TestMode) {
            Write-Host "`n=== TEST MODE COMPLETED ===" -ForegroundColor Yellow
            Write-Host "No changes were made to Active Directory" -ForegroundColor Yellow
            Write-Host "Review the logs above to see what changes would be made in production mode`n" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Log $_.Exception.Message "ERROR"
        throw
    }
}

# Execute main function
Process-SecurityGroups
