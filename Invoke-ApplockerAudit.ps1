<#
.SYNOPSIS
A script to help test Applocker configs

.DESCRIPTION
Read the Applocker config and test the ACLS of the path to see if non-admins can write
I wrote this just for fun. It's already late, and I don't want to spend more time to make the code more readable ;) 

#>
#region functions
Function Invoke-MyAclTest {
    param(
        [string]$Path
    )
    try {
        $ACL = Get-acl "$($Path)" -ErrorAction Stop
    } catch {}
    $ACLAccess = $acl.Access | Where-object {$_.FileSystemRights -match ".*(AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnerhip|Write|WriteData).*" -and $_.IdentityReference.value -notmatch 'Administrator.*|NT SERVICE.*|.*SYSTEM|APPLICATION PACKAGE AUTHORITY|CREATOR OWNER.*' -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow}
    return $ACLAccess | select FileSystemRights,IdentityReference
}

Function Test-ApplockerPath {
    param(
        [string]$Path
    )

    $OutCol = [System.Collections.ArrayList]::new()
    if ($Path -match "(%[^\\]*%)") {
        foreach ($wildcardPath in (dir $Path)) {
            $NewPathObject = [PSCustomObject]::new()
            $NewPathObject | Add-Member -MemberType NoteProperty -Name Path -Value $wildcardPath -Force
            $NewPathObject | Add-Member -MemberType NoteProperty -Name ACL -Value (Invoke-MyAclTest -Path $wildcardPath) -Force
            [void]$outCol.Add($NewPathObject)
        }    
    } else {
        $NewPathObject = [PSCustomObject]::new()
        $NewPathObject | Add-Member -MemberType NoteProperty -Name Path -Value $Path -Force
        $NewPathObject | Add-Member -MemberType NoteProperty -Name ACL -Value (Invoke-MyAclTest -Path $Path) -Force
        [void]$outCol.Add($NewPathObject)
    }
    return $OutCol
}
#endregion functions

$SrpKeys = dir HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2

Class OutObj {
    [string]$RuleType
    [string]$ExecutionType
    [int]$EnforcementMode
    [string]$Name
    [string]$UserOrGroupSid
    [string]$Action
    [System.Collections.ArrayList]$Conditions
    [System.Collections.ArrayList]$Exceptions

}


$OutCol = New-Object System.Collections.ArrayList



Foreach ($t in $SrpKeys) {
    Foreach ($k in (dir "HKLM:\$($t.Name.Replace('HKEY_LOCAL_MACHINE\',''))")) {
        $outobj = [outobj]::new()
        $Conditions = [System.Collections.ArrayList]::new()
        [xml]$Rule = $k.GetValue('Value')

        $outobj.EnforcementMode = $t.GetValue('EnforcementMode')
        $outobj.ExecutionType = $t.Name.Split("\")[-1]
        
        if ($rule.FilePathRule -ne $null) {
            $outobj.RuleType = 'FilePathRule'
            $outobj.Name = $rule.FilePathRule.Name
            $outobj.Action = $rule.FilePathRule.Action
            $outobj.UserOrGroupSid = $rule.FilePathRule.UserOrGroupSid
            $outobj.Exceptions = $rule.FilePathRule.Exceptions.FilePathCondition.path
            $Paths = $rule.FilePathRule.Conditions.FilePathCondition.Path
            $EnhancedFilePathCondition = $null

            Foreach ($p in $Paths) {
                # Paths can be full names (C:\test\bla, \\myserver\myshare\bla), and/or contain variables (%OSDRIVE%\SQL) and/or contain wildcards (C:\Users\*\Desktop).
                # We have to check for all cases

                if ($p -like '*%*%*') {
                    if ($p -like '*%OSDRIVE%*') {
                        $ResolvedPath = $p.Replace('%OSDRIVE%',$env:SystemDrive)
                    } else {
                        # Get everything between 2 percent signs that is not a backslash
                        $re = [regex]::new("(%[^\\]*%)")
                        $Matches = $re.Matches($p)
                        $ResolvedPath = $p
                        Foreach ($m in $Matches) {
                            $ResolvedPath = $ResolvedPath.Replace($m.Value,(Invoke-Expression ('$env:' + $m.Value.Replace('%',''))))
                        }
                    }
                } else {
                    $ResolvedPath = $p
                }

                # If the path ends with \* (e.g. C:\Windows\*), we remove the last 2 characters
                if ($ResolvedPath.EndsWith('\*')) {
                    $ResolvedPath = $ResolvedPath.Remove($ResolvedPath.Length-2,2)
                }
                
                if ($ResolvedPath -eq '*') {
                    # If the path only consists of a *, we everything is allowed, and we don't check ACLs
                    $EnhancedFilePathCondition = $rule.FilePathRule.Conditions.FilePathCondition
                }
                if ($EnhancedFilePathCondition -eq $null) {
                    # Process paths with wildcards in them (like *\Appdata or C:\Users\*\Appdata)
                    $EnhancedFilePathCondition = Test-ApplockerPath -Path $ResolvedPath
                }
                [void]$Conditions.Add($EnhancedFilePathCondition)
            }
        } elseif ($rule.FileHashRule -ne $null) {
            $outobj.RuleType = 'FileHashRule'
            $outobj.Name = $rule.FileHashRule.Name
            $outobj.Action = $rule.FileHashRule.Action
            $outobj.UserOrGroupSid = $rule.FileHashRule.UserOrGroupSid
            $outobj.Exceptions = $rule.FileHashRule.Exceptions.FileHashCondition
            [void]$Conditions.Add($rule.FileHashRule.Conditions.FileHashCondition)
        } elseif ($rule.FilePublisherRule -ne $null) {
            $outobj.RuleType = 'FilePublisherRule'
            $outobj.Name = $rule.FilePublisherRule.Name
            $outobj.Action = $rule.FilePublisherRule.Action
            $outobj.UserOrGroupSid = $rule.FilePublisherRule.UserOrGroupSid
            $outobj.Exceptions = $rule.FilePublisherRule.Exceptions.FilePublisherCondition.path
            [void]$Conditions.Add($rule.FilePublisherRule.Conditions.FilePublisherCondition)
        } else {
            Write-Host "No implemented" -ForegroundColor Yellow
            $Rule
        }

        $outobj.Conditions = $Conditions
        [void]$OutCol.Add($outobj)
        
    }
}

# Get all Applocker FilePath rules that allow exeuting files, and list the ACLs for the included folders
$Allow = ($OutCol | ?{$_.RuleType -eq 'FilePathRule' -and $_.Action -eq 'Allow'})
Foreach ($item in $Allow) {
    $item.Conditions | select path,acl
}

#$OutCol | ConvertTo-Json -Depth 100 | Out-File C:\temp\applocker.json -Encoding utf8 -Force
$OutCol | Export-Clixml -Path C:\temp\applocker.clixml -Force -Encoding UTF8
