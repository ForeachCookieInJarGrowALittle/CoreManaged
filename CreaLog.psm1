function Get-RequestTimeStamp {
$offset=((get-date).GetDateTimeFormats()[94] -split "\+"|select -last 1) -split "\:"|select -First 1
(get-date).AddHours(-$offset).GetDateTimeFormats()[94] -split "\+"|select -first 1
}

function New-SWRandomPassword {
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}

function Invoke-mCRRequest {
[Cmdletbinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory=$true)]
    [String]$Request
)
    if ($PSCmdlet.ShouldProcess("$request","Invoke")) {
        convertfrom-json (Invoke-WebRequest -UseBasicParsing $APIEndpoint -ContentType "application/json" -Method POST -Body $Request|select -expand Content)
    }#endif
}

function Get-mCRUser {
[Cmdletbinding(SupportsShouldProcess = $true,DefaultParameterSetName='all')]
Param(
    [Parameter(Mandatory=$true,Valuefrompipeline = $true,Position=0,ParameterSetName = "single")]
    [Microsoft.ActiveDirectory.Management.ADAccount]
    $ADUser
    ,
    [Parameter(Mandatory=$true,ParameterSetName = "all")]
    [switch]$All
) 
    if ($all) {
    $Request=@"
{
"RequestTimestamp":"$(Get-RequestTimeStamp)",
"Function":"GetAllWebuserIDs"
}
"@
    } else {
    $request=@"
{
"RequestTimestamp":"$(Get-RequestTimeStamp)",
"Function":"GetWebuserDetails",
"WebuserID":"$($Aduser.SamAccountName)",
}
"@
    Invoke-mCRRequest -Request $request
    }
}

function New-mCRUser {
[Cmdletbinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory=$true,Valuefrompipeline = $true,Position=0)]
    [Microsoft.ActiveDirectory.Management.ADAccount]
    $ADUser
    ,
    [Parameter(Mandatory=$true)]
    [ValidateSet("OP","PM")]
    $WebuserRoles
    ,
    [Parameter(Mandatory=$false)]
    $WebuserPassword
    ,
    [Parameter(Mandatory=$false)]
    $CompanyID
    ,
    [Parameter(Mandatory=$false)]
    [ValidateSet("DE", "EN", "FR")]
    $WebuserLanguage="DE"
) 
    $request=@"
{
"RequestTimestamp":"$(Get-RequestTimeStamp)",
"Function":"CreateWebuser",
"CompanyID":"$CompanyID",
"WebuserID":"$($Aduser.SamAccountName)",
"WebuserPassword":"$WebuserPassword",
"WebuserFirstname":"$($Aduser.GivenName)",
"WebuserLastname":"$($Aduser.SurName)",
"WebuserEmail":"$($Aduser.Mail)",
"WebuserLanguage":"$WebuserLanguage",
"WebuserRoles":[`"$([string]::Join('","',$WebuserRoles))`"]
}
"@
    
    #if ($pscmdlet.ShouldProcess("$($Aduser.SamAccountName)","Create Webuser for")) {
        $result=Invoke-mCRRequest -Request $request    
    #} else {
    #    Invoke-mCRRequest -Request $request -WhatIf
    #}

    if ($null -ne $result) {
        write-verbose $result
        switch ($result.state) {
            0 {Write-Verbose -Verbose "User has been created successfully"}
            -501 {Write-Verbose -Verbose "User already exists"}
        }
    } else {
        Write-Verbose "no Result received" -verbose
    }
}

function Set-mCRUser {
[Cmdletbinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory=$true,Valuefrompipeline = $true,Position=0)]
    [Microsoft.ActiveDirectory.Management.ADAccount]
    $ADUser
    ,
    [Parameter(Mandatory=$false)]
    [ValidateSet("OP","PM")]
    $WebuserRoles
    ,
    [Parameter(Mandatory=$false)]
    $WebuserPassword
    ,
    [Parameter(Mandatory=$false)]
    $CompanyID
    ,
    [Parameter(Mandatory=$false)]
    [ValidateSet("DE", "EN", "FR")]
    $WebuserLanguage="DE"
) 
    $CurrentUserProperties = Get-mCRUser $ADUser
    $CurrentUserProperties
    
    if (-not $PSBoundParameters.ContainsKey("WebuserLanguage")) {
        $WebuserLanguage = $CurrentUserProperties.WebuserLanguage
    }
    if (-not $PSBoundParameters.ContainsKey("WebuserRoles")) {
        [string[]]$WebuserRoles=$CurrentUserProperties.WebuserRoles
    }
    if (-not $PSBoundParameters.ContainsKey("CompanyID")) {
        $CompanyID = $CurrentUserProperties.CompanyID
    }
    
    $request=@"
{
"RequestTimestamp":"$(Get-RequestTimeStamp)",
"Function":"ModifyWebuser",
"CompanyID":"$CompanyID",
"WebuserID":"$($Aduser.SamAccountName)",
"WebuserFirstname":"$($Aduser.GivenName)",
"WebuserLastname":"$($Aduser.SurName)",
"WebuserEmail":"$($Aduser.Mail)",
"WebuserLanguage":"$WebuserLanguage",
"WebuserRoles":[`"$([string]::Join('","',$WebuserRoles))`"]
}
"@
    
    #if ($pscmdlet.ShouldProcess("$($Aduser.SamAccountName)","Create Webuser for")) {
        $result=Invoke-mCRRequest -Request $request    
    #} else {
    #    Invoke-mCRRequest -Request $request -WhatIf
    #}

    if ($null -ne $result) {
        write-verbose $result
        switch ($result.state) {
            0 {Write-Verbose -Verbose "User has been created successfully"}
            -501 {Write-Verbose -Verbose "User already exists"}
        }
    } else {
        Write-Verbose "no Result received" -verbose
    }
}