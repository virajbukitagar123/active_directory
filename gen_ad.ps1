param( [Parameter(Mandatory=$true)] $JSONFile)

function CreateADGroup {
    param ([Parameter(Mandatory=$true)] $groupObject)

    $name = $groupObject.name
    New-ADGroup -name $name -GroupScope Global
    
}

function RemoveADGroup {
    param ([Parameter(Mandatory=$true)] $groupObject)

    $name = $groupObject.name
    Remove-ADGroup -Confirm:$false -Identity $name

}

function CreateADUser {
    param ([Parameter(Mandatory=$true)] $userObject)

    # Pull out the name from the JSON $userObject
    $name = $userObject.name
    $password = $userObject.password

    $firstname, $lastname = $name.Split(" ")
    $username = ($firstname[0] + $lastname).ToLower()
    $samAccountName = $username
    $principalname = $username

    # Actually create the AD User Object
    New-ADUser -Name "$name" -GivenName $firstname -Surname $lastname -SamAccountName $samAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount

    # Add the user to its corresponding group
    foreach ($group_name in $userObject.groups) {

        try {

            Get-ADGroup -Identity "$group_name"
            Add-ADGroupMember -Identity $group_name -Members $username

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "User $name NOT added to group $group_name because it does not exist"
        }
    }
}

function WeakenPasswordPolicy() {
    secedit /export /cfg C:\windows\tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db C:\windows\security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    rm -force C:\Windows\Tasks\secpol.cfg -confirm:$false
    
}

WeakenPasswordPolicy

$json = ( Get-Content $JSONFile | ConvertFrom-Json )

$Global:Domain = $json.domain

foreach ( $group in $json.groups ) {
    CreateADGroup $group
}

foreach ( $user in $json.users ) {
    CreateADUser $user
}