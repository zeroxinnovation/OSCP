# OSCPP
Following repository contains commands and instructions useful for OSCP preparation

## DOMAIN PENTEST ENVIRONMENT
### DOMAIN MACHINES 
> link
(https://github.com/Hellsender01/Youtube/blob/main/Active%20Directory/Passwords.md)
```
rgreen/DirtyPassword23
rgeller/Password123!@#
```

### KALI LINUX

```
/var/www/html/ad_tools
pass.txt     
SharpHound.exe  
svc_hash
mimikatz.exe  
mimidrv.sys
mimilib.dll   
PsExec64.exe  
shell-x64.exe
```

### MACHINE COMPROMISE SIMULATE

```
RDP

IMPACKET (PASSWORD)

IMPACKET (HASH)
```



## DOMAIN ENUMERATION TECHNIQUES

### NET BINARY

```
net user
net localgroup 
net users test1

net user /domain
net group /domain
net user cbing /domain
net groups /domain "Domain Admins"
```


### POWERSHELL

>Following are some popular powersellscripts used for AD enumeraion

1. DISTINGUISHED NAME

```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
```

2. LDAP PROVIDER PATH

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$SearchString
```

3. DIRECTORY SEARCHER CLASS PREPERATION

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString) 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry 
$Searcher.SearchRoot = $objDomain
```

4. DOMAIN USERS

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString) 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry 
$Searcher.SearchRoot = $objDomain 
$Searcher.filter="samAccountType=805306368"
$Searcher.FindAll()
```

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368" 
$Result= $Searcher.FindAll() 
Foreach ($obj in $Result) 
{ 
Foreach($prop in $obj.Properties) 
{ 
$prop 
} 
Write-Host "------------------------"
}
```

4. DOMAIN GROUPS

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result= $Searcher.FindAll()
Foreach ($obj in $Result)
{
$obj.Properties.name
}
```

5. NESTED GROUPS - USERS/GROUPS INSIDE GROUPS

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Administrators)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```
```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=test_group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$0istinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Nested_group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

```
$domain0bj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domain0bj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=another_Nested-group)"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

6. SERVICE ACCOUNTS ENUMERATION VIA SERVICE PRINCIPAL NAMES 

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
}
Foreach($prop in $obj.Properties)
{
$prop
}
```

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher= New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*backup*"
$Result= $Searcher.FindAll()
Foreach($obj in $Result)
{
}
Foreach($prop in $obj.Properties)
{
$prop
}
```
