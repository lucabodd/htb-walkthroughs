# Machine Name
```
Difficulty:
Operating System:
Hints:
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following
```
Nmap scan report for help.htb (10.10.10.121)
Host is up (0.042s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
As we can see the operating system is ubuntu and we can check the exact release on lunchpad if we want.  
As we can quickly see, this should be ubuntu xenial.  
Now let's start digging into port 80.  
## Foothold (optional)

## User
### Method 1 - Technique 1 (optional)
### Method 2 - Technique 2 (optional)

## Root
