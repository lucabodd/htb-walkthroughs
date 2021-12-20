# Machine Name
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap full scan (TCP) on the target shows the following
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          37615/udp   status
|   100024  1          50004/tcp   status
|   100024  1          51408/udp6  status
|_  100024  1          53157/tcp6  status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
50004/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Now, let's dig into port 80.  
Here we can only see a smile picture and a comment: *IRC is almost working!*  
Now, we thanks for the hint and we dig into UnrealIRCd service.  
Before doing so, let's reat the IRC RFC and see how we can connect to the server and provide all the needed information.  
In the [RFC-1459](https://datatracker.ietf.org/doc/html/rfc1459) we can navigate to [Connection Registration](https://datatracker.ietf.org/doc/html/rfc1459#section-4.1) and as we can discover how to connect sending the NICK, PASS, USER commands as follows:  
```
[root@kali Irked ]$ nc 10.10.10.117 6697
:irked.htb NOTICE AUTH :*** Looking up your hostname...
NICK b0d
USER:irked.htb NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
PASS b0d
USER b0d 0 * :b0d
:irked.htb 001 b0d :Welcome to the ROXnet IRC Network b0d!b0d@10.10.14.18
:irked.htb 002 b0d :Your host is irked.htb, running version Unreal3.2.8.1
:irked.htb 003 b0d :This server was created Mon May 14 2018 at 13:12:50 EDT
:irked.htb 004 b0d irked.htb Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
```
As we can see here, the server discloses service version information: ```Unreal3.2.8.1```.
So by just googling around for a changelog, we can see that exploits pop up.  
So without further doing let's searchsploit for unreal ircd:  
```
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRC 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                                                                                                               | linux/remote/16922.rb
UnrealIRC 3.2.8.1 - Local Configuration Stack Overflow                                                                                                                                                    | windows/dos/18011.txt
UnrealIRC 3.2.8.1 - Remote Downloader/Execute                                                                                                                                                             | linux/remote/13853.pl
UnrealIRC 3.x - Remote Denial of Service                                                                                                                                                                  | windows/dos/27407.pl
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## User

## Root
