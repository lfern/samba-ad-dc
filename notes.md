```powershell
# checking available interface using Powershell command
Get-NetAdapter -Name "*"
# setup DNS resolver using Powershell
Set-DNSClientServerAddress "output name previous command" –ServerAddresses ("IP domain controller","8.8.8.8")
# verify DNS resolver
Get-DnsClientServerAddress
# ping the AD domain dc1.example.lan
ping dc1.example.lan
# ping the AD domain example.lan
ping example.lan
# add Windows 10 to Active Directory
Add-Computer -DomainName "example.lan" -Restart
```

```powershell
# add computer to domain, no ask for credentals
$domain = “ccddbank.com”
$UserName = “ccddbank\administrator”
$Password = “Password123” | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName,$Password
Add-Computer -DomainName $domain -DomainCredential $Credential -Restart -Verbose
```

https://serverfault.com/questions/699757/gpo-with-samba-as-dc

```powershell
# install RSAT
Get-WindowsCapability -Name RSAT* -Online
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State
```

?????
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

RSAT gpo
https://serverfault.com/questions/699757/gpo-with-samba-as-dc

Gotchas:https://adamtheautomator.com/new-aduser/
```powershell
New-ADUser `
    -Name "Kevin Sapp" `
    -GivenName "Kevin" `
    -Surname "Sapp" `
    -SamAccountName "kesapp-test" `
    -AccountPassword (Read-Host -AsSecureString "Input User Password") `
    -ChangePasswordAtLogon $True `
    -Company "Code Duet" `
    -Title "CEO" `
    -State "California" `
    -City "San Francisco" `
    -Description "Test Account Creation" `
    -EmployeeNumber "45" `
    -Department "Engineering" `
    -DisplayName "Kevin Sapp (Test)" `
    -Country "us" `
    -PostalCode "940001" `
    -Enabled $True

Get-ADUser -Identity kesapp-test -Properties State,Department,Country,City
```

```powershell
$template_account = Get-ADUser -Identity kesapp-test -Properties State,Department,Country,City
$template_account.UserPrincipalName = $null

New-ADUser `
    -Instance $template_account `
    -Name 'James Brown' `
    -SamAccountName 'jbrown' `
    -AccountPassword (Read-Host -AsSecureString "Input User Password") `
    -Enabled $True
```

Create users from csv
```csv
FirstName, LastName, Department, State, EmployeeID, Office, UserPrincipalName, SamAccountName, Password
Micheal, Jordan, NBA, Chicago, 23, Chicago Bulls, mjordan@mylab.local, mjordan, p@ssw0rd1
Lebron, James, NBA, Los Angeles,24, LA Lakers,ljames@mylab.local, ljames, p@ssw0rd2
Dwayne, Wade, NBA, Miami, 13, Miami Heat, dwade@mylab.local, dwade, p@ssw0rd3
```

```powershell
$import_users = Import-Csv -Path sample.csv
$import_users | ForEach-Object {
    New-ADUser `
        -Name $($_.FirstName + " " + $_.LastName) `
        -GivenName $_.FirstName `
        -Surname $_.LastName `
        -Department $_.Department `
        -State $_.State `
        -EmployeeID $_.EmployeeID `
        -DisplayName $($_.FirstName + " " + $_.LastName) `
        -Office $_.Office `
        -UserPrincipalName $_.UserPrincipalName `
        -SamAccountName $_.SamAccountName `
        -AccountPassword $(ConvertTo-SecureString $_.Password -AsPlainText -Force) `
        -Enabled $True
}
```

https://adamtheautomator.com/active-directory-scripts/
https://github.com/adbertram/Random-PowerShell-Work