<#
.SYNOPSIS
Prepares Active Directory for drs, on a Windows domain controller. Safe to re-run.

.DESCRIPTION
Creates, or leaves alone when they exist:
  - the service account (default svc-drs), AES only, with the SPN HTTP/<DrsHost>;
  - CN=RegisteredDevices and the device registration service connection point
    that sends domain-joined PCs to <DrsHost>;
  - the group of users allowed to set up Hello;
  - exactly three rights for the account: write msDS-KeyCredentialLink on the
    users below -UsersOU, and create, manage and delete msDS-Device objects in
    RegisteredDevices. Never Key Admins.
and writes the account's keytab for drs.

.EXAMPLE
.\setup-ad.ps1 -DrsHost adfs.example.test -UsersOU "OU=People,DC=example,DC=test"
#>
param(
    [Parameter(Mandatory)] [string] $DrsHost,
    [Parameter(Mandatory)] [string] $UsersOU,
    [string] $Account = 'svc-drs',
    [string] $EnrolGroup = 'WHfB-Enrol',
    [string] $Keytab = '.\http.keytab',
    # Issue a new keytab for an existing account (the old one stops working).
    [switch] $NewKeytab,
    # The account's password; asked for when not given.
    [SecureString] $Password
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$config = (Get-ADRootDSE).configurationNamingContext
function Exists($dn) { try { Get-ADObject -Identity $dn | Out-Null; $true } catch { $false } }
function Step($text) { Write-Host "  $text" }

Write-Host "drs: preparing $($domain.DNSRoot) for $DrsHost"

# The service account. Its password is only ever typed here and stored in the keytab.
$password = $Password
$created = $false
if (-not (Get-ADUser -Filter "SamAccountName -eq '$Account'")) {
    $created = $true
    if (-not $password) { $password = Read-Host "Password for the new account $Account" -AsSecureString }
    New-ADUser -Name $Account -SamAccountName $Account -UserPrincipalName "$Account@$($domain.DNSRoot)" `
        -AccountPassword $password -PasswordNeverExpires $true -Enabled $true
    Step "created $Account"
} else { Step "$Account exists" }
Set-ADUser $Account -KerberosEncryptionType AES128, AES256
if ((Get-ADUser $Account -Properties servicePrincipalName).servicePrincipalName -notcontains "HTTP/$DrsHost") {
    Set-ADUser $Account -ServicePrincipalNames @{Add = "HTTP/$DrsHost"}
    Step "SPN HTTP/$DrsHost added"
} else { Step "SPN HTTP/$DrsHost exists" }

# Where devices go, and the pointer that sends PCs to drs.
$devices = "CN=RegisteredDevices,$base"
if (-not (Exists $devices)) { New-ADObject -Name RegisteredDevices -Type msDS-DeviceContainer -Path $base; Step "created $devices" }
$drc = "CN=Device Registration Configuration,CN=Services,$config"
if (-not (Exists $drc)) { New-ADObject -Name 'Device Registration Configuration' -Type container -Path "CN=Services,$config" }
$scp = "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,$drc"
if (-not (Exists $scp)) {
    New-ADObject -Name 62a0ff2e-97b9-4513-943f-0d221bd30080 -Type serviceConnectionPoint -Path $drc `
        -OtherAttributes @{keywords = "enterpriseDrsName:$DrsHost"}
} else { Set-ADObject $scp -Replace @{keywords = "enterpriseDrsName:$DrsHost"} }
Step "PCs are sent to $DrsHost"

if (-not (Get-ADGroup -Filter "Name -eq '$EnrolGroup'")) {
    New-ADGroup -Name $EnrolGroup -GroupScope Global -Path $UsersOU
    Step "created group $EnrolGroup (add the users allowed to set up Hello)"
} else { Step "group $EnrolGroup exists" }

# The three rights.
$schema = (Get-ADRootDSE).schemaNamingContext
function SchemaGuid($name) {
    [guid](Get-ADObject -SearchBase $schema -Filter "lDAPDisplayName -eq '$name'" -Properties schemaIDGUID).schemaIDGUID
}
$keyLink = SchemaGuid 'msDS-KeyCredentialLink'
$userClass = SchemaGuid 'user'
$deviceClass = SchemaGuid 'msDS-Device'
$sid = (Get-ADUser $Account).SID
$R = [System.DirectoryServices.ActiveDirectoryRights]
$I = [System.DirectoryServices.ActiveDirectorySecurityInheritance]
function Grant($dn, $rule) {
    $acl = Get-Acl "AD:\$dn"
    $have = $acl.Access | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) -eq $sid -and
        $_.ActiveDirectoryRights -eq $rule.ActiveDirectoryRights -and $_.ObjectType -eq $rule.ObjectType -and
        $_.InheritedObjectType -eq $rule.InheritedObjectType }
    if (-not $have) { $acl.AddAccessRule($rule); Set-Acl "AD:\$dn" $acl }
}
Grant $UsersOU (New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, $R::WriteProperty, 'Allow', $keyLink, $I::Descendents, $userClass))
Grant $devices (New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, ($R::CreateChild -bor $R::DeleteChild), 'Allow', $deviceClass, $I::None))
Grant $devices (New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid, ($R::ReadProperty -bor $R::WriteProperty -bor $R::Delete), 'Allow', $I::Descendents, $deviceClass))
Step "rights granted (Hello keys below $UsersOU, devices in RegisteredDevices)"

# The keytab. ktpass resets the password and the key version, so a re-run
# leaves the one drs already holds alone unless asked. It also sets the UPN to
# HTTP/<host>@<REALM>: AD salts the account's AES keys with its UPN, and only
# then do they match the keys ktpass derives (drs binds by DN, not UPN).
if ($created -or $NewKeytab) {
    if (-not $password) { $password = Read-Host "Password for $Account (it is reset to this)" -AsSecureString }
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    # ktpass reports progress on stderr, which Windows PowerShell turns into errors.
    $log = & { $ErrorActionPreference = 'Continue'
        ktpass /princ "HTTP/$DrsHost@$($domain.DNSRoot.ToUpper())" /mapuser "$($domain.NetBIOSName)\$Account" `
            /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass $plain /out $Keytab 2>&1 }
    if ($LASTEXITCODE -ne 0) { $log | Write-Host; throw "ktpass failed ($LASTEXITCODE)" }
    Step "keytab written to ${Keytab}: copy it to the drs host as /etc/drs/<instance>/http.keytab"
} else {
    Step "keytab not rewritten (the one drs holds stays valid; -NewKeytab issues a new one)"
}

Write-Host "Done. drs binds as $((Get-ADUser $Account).DistinguishedName) with $Account's password (ldap-password)."
