
# Ex 1
## Ex 1.1

To connect to attack: ssh -i keyfile.pem kali@ec2-18-170-73-26.eu-west-2.compute.amazonaws.com
Private server: 172.16.13.42
To port forward the server: ssh -i keyfile.pem -L 8080:172.16.13.42:8080 -L 8081:172.16.13.42:80 kali@ec2-18-170-73-26.eu-west-2.compute.amazonaws.com
Access on local machine with http://localhost.com/8080 and http://localhost.com/8081

Backup file located at http://172.16.13.42:8080/backup.zip (http://localhost:8080/backup.zip on our machine)
stored in ~/backup.zip
wordlist downloaded to ~/rockyou.txt

We are trying to crack the password with: fcrackzip -D -p rockyou.txt -u backup.zip

but we might want to skip to next sections...

### Findings:
dirb http://172.16.13.42:8080 -X .php,.zip
#### http://172.16.13.42:8080
---- Scanning URL: http://172.16.13.42:8080/ ----
http://172.16.13.42:8080/docs 
http://172.16.13.42:8080/examples 
http://172.16.13.42:8080/favicon.ico 
http://172.16.13.42:8080/host-manager
http://172.16.13.42:8080/manager
http://172.16.13.42:8080/backup.zip                                                      

#### http://172.16.13.42:80
+ http://172.16.13.42:80/index.html
+ http://172.16.13.42:80/server-status


