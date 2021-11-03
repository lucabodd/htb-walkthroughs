# Antique
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.99 seconds
```
Here we can see that we have port 53 opened running over TCP, which is odd.
So, now we can try to enumerate this port.
First we can try ```nslookup```:
```
[root@kali Bank ]$ nslookup    
> SERVER 10.10.10.29
Default server: 10.10.10.29
Address: 10.10.10.29#53
> 127.0.0.1
1.0.0.127.in-addr.arpa  name = localhost.
> 10.10.10.29
** server can't find 29.10.10.10.in-addr.arpa: NXDOMAIN
> bank.htb
Server:         10.10.10.29
Address:        10.10.10.29#53

Name:   bank.htb
Address: 10.10.10.29
```
As we can see the there is a record for bank.htb.
Now we can try to use ```dnsrecon```, dsnrecon is a simple python script that enables to gather DNS-oriented information on
a given target. Let try to use this tool against this target:
```
[root@kali Bank ]$ dnsrecon -r 127.0.0.1/24 -n 10.10.10.29               
[*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
[+]      PTR localhost 127.0.0.1
[+] 1 Records Found
[root@kali Bank ]$ dnsrecon -r 10.10.10.29/24 -n 10.10.10.29
[*] Performing Reverse Lookup from 10.10.10.0 to 10.10.10.255
[+] 0 Records Found
```
As we can see there is only one PTR record set for localhost.
Now, let's try to perform a DNS zone transfer using ```dig```, for the zone bank.htb:
```
[root@kali Bank ]$ dig axfr bank.htb @$TARGET
; <<>> DiG 9.16.15-Debian <<>> axfr bank.htb @10.10.10.29
;; global options: +cmd
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
;; Query time: 31 msec
;; SERVER: 10.10.10.29#53(10.10.10.29)
;; WHEN: Wed Nov 03 12:23:45 CET 2021
;; XFR size: 6 records (messages 1, bytes 171)
```
## User

## Root
